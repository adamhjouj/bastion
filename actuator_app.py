"""Authenticated, policy-gated Docker actuator sidecar. Never run in the model container."""
import asyncio
import contextlib
import hashlib
import json
import os

from fastapi import FastAPI, HTTPException, Request
from jsonschema import validate

import actuator
import remediation_tools
import store
from security import DESTRUCTIVE, authorize

TOKEN = os.getenv("ACTUATOR_TOKEN", "")
TOOLS = {t["name"]: t for t in actuator.CONTROL_TOOLS + [remediation_tools.PATCH_VULN_TOOL]}
_semaphore = asyncio.Semaphore(2)


def status():
    result = []
    for target in sorted(actuator.ALLOWED_TARGETS):
        cid = actuator._resolve(target)
        rc, out, _ = actuator._docker("inspect", "--format", "{{.State.Status}}", cid)
        result.append({"service": target, "state": out.strip() if rc == 0 else "unknown"})
    return json.dumps(result)


@contextlib.asynccontextmanager
async def lifespan(app):
    if len(TOKEN) < 32:
        raise ValueError("ACTUATOR_TOKEN must have at least 32 characters")
    store.initialize()
    actuator.capture_baseline()
    yield


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
