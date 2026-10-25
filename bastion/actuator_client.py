"""Typed remote actuator tools. The model container has no Docker socket or CLI."""
import os
import uuid

import httpx

from bastion.actuator import CONTROL_TOOLS
from bastion.remediation_tools import PATCH_VULN_TOOL


def call_tool(name, params, action_id=None):
    url = os.getenv("ACTUATOR_URL", "http://actuator:9010")
    token = os.getenv("ACTUATOR_TOKEN", "")
    if len(token) < 32:
        return "REJECTED: actuator credential unavailable"
    try:
        response = httpx.post(url + "/tools/" + name,
                              headers={"Authorization": f"Bearer {token}",
                                       "Idempotency-Key": action_id or uuid.uuid4().hex},
                              json=params, timeout=22)
        response.raise_for_status()
        return str(response.json()["result"])
    except Exception:
        return "ERROR: actuator unavailable or request rejected"


REGISTER = [{"name": tool["name"], "schema": tool,
             "fn": (lambda _name=tool["name"], **params: call_tool(_name, params))}
            for tool in CONTROL_TOOLS + [PATCH_VULN_TOOL]]
