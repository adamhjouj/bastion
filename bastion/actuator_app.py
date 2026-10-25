"""Authenticated, policy-gated Docker actuator sidecar. Never run in the model container."""
import asyncio
import contextlib
import hashlib
import json
import os

from fastapi import FastAPI, HTTPException, Request
from jsonschema import validate

from bastion import actuator
from bastion import remediation_tools
from bastion import store
from bastion.log_collector import DockerLogCollector
from bastion.security import DESTRUCTIVE, authorize

TOKEN = os.getenv("ACTUATOR_TOKEN", "")
TOOLS = {t["name"]: t for t in actuator.CONTROL_TOOLS + [remediation_tools.PATCH_VULN_TOOL]}
_semaphore = asyncio.Semaphore(2)


def status():
    result = []
    for target in sorted(actuator.ALLOWED_TARGETS):
        try:
            cid = actuator._resolve(target)
            rc, out, _ = actuator._docker("inspect", "--format", "{{.State.Status}}", cid)
            state = out.strip() if rc == 0 else "unknown"
        except actuator.Rejected as exc:
            state = f"unavailable: {exc}"
        result.append({"service": target, "state": state})
    return json.dumps(result)


@contextlib.asynccontextmanager
async def lifespan(app):
    if len(TOKEN) < 32:
        raise ValueError("ACTUATOR_TOKEN must have at least 32 characters")
    store.initialize()
    collector = DockerLogCollector(actuator.PROJECT, actuator.DOCKER,
                                   retention=int(os.getenv("LOG_RETENTION_LINES", "1000")))
    await collector.start()
    try:
        try:
            await asyncio.to_thread(actuator.capture_baseline)
            store.set_health("actuator", {"ready": True, "baseline": True})
        except Exception:
            # Process termination already refuses absent/stale baselines. Log ingestion
            # and other read-only diagnostics must remain available during target failure.
            store.set_health("actuator", {"ready": True, "baseline": False})
        async def heartbeat():
            while True:
                await asyncio.sleep(10)
                await asyncio.to_thread(store.touch_health, "actuator")
                # Re-establish the baseline if the target was re-created after startup
                # and has come back up fresh and clean (kill_process stays usable without
                # trusting a possibly-compromised container). Idempotent + never raises.
                await asyncio.to_thread(actuator.ensure_baseline)
        pulse = asyncio.create_task(heartbeat())
        try:
            yield
        finally:
            pulse.cancel()
            await asyncio.gather(pulse, return_exceptions=True)
    finally:
        await collector.close()
        store.set_health("actuator", {"ready": False})


app = FastAPI(lifespan=lifespan, docs_url=None, openapi_url=None, redoc_url=None)


@app.middleware("http")
async def boundary(request, call_next):
    try:
        authorize(request, TOKEN)
    except HTTPException as exc:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": exc.detail}, exc.status_code, headers=exc.headers)
    return await call_next(request)


@app.get("/health")
async def health():
    return {"ready": True}


@app.post("/lab/restore")
async def lab_restore():
    """Operator lab reset: return the target to its exploitable default (unfreeze, reconnect
    egress, level back to medium). Not exposed to the agent's tool catalog; restoring the
    baseline is not a destructive action, so the destructive-tool policy does not gate it."""
    async with _semaphore:
        return await asyncio.to_thread(remediation_tools.restore_lab)


@app.post("/tools/{name}")
async def tool(name: str, request: Request):
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > 16384:
            raise HTTPException(413, "tool request too large")
    if name not in TOOLS and name != "service_status":
        raise HTTPException(404, "unknown tool")
    try:
        params = json.loads(data)
        schema = TOOLS[name]["input_schema"] if name in TOOLS else {"type": "object", "properties": {}}
        validate(params, dict(schema, additionalProperties=False))
    except Exception:
        raise HTTPException(422, "invalid tool parameters")
    if name in DESTRUCTIVE and os.getenv("ALLOW_DESTRUCTIVE", "0") != "1":
        return {"result": "REJECTED: operator policy has not approved destructive tools"}
    if not store.spend("actuator", 20):
        raise HTTPException(429, "actuator budget exhausted")
    request_key = request.headers.get("idempotency-key", "")
    if not 1 <= len(request_key) <= 128:
        raise HTTPException(422, "Idempotency-Key required")
    key = hashlib.sha256(json.dumps([name, params, request_key], sort_keys=True).encode()).hexdigest()

    def perform():
        if name == "service_status":
            return status()
        if name == "patch_vuln":
            return remediation_tools.do_patch_vuln(**params)
        return actuator.run_tool(name, params)

    async with _semaphore:
        # Store the attempt before executing. Unknown interrupted actions require investigation.
        result = await asyncio.to_thread(store.execute_once, "actuator:" + key, perform)
    return {"result": result}
