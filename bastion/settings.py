"""Validated operating modes, credentials, and resource limits."""
import os
from dataclasses import dataclass

MODES = {"observe", "agent", "classifier-contain", "inline"}


def real_key(name):
    value = os.getenv(name, "").strip()
    return bool(value and value not in {"sk-...", "...", "changeme"})


@dataclass(frozen=True)
class Settings:
    mode: str = "observe"
    management_token: str = ""
    inline_failure: str = "reject"
    demo_identity: bool = False
    trusted_proxies: str = ""
    request_limit: int = 65536
    response_limit: int = 2097152
    timeout: float = 5.0
    concurrency: int = 8
    budget_per_minute: int = 120
    queue_limit: int = 10000
    allow_destructive: bool = False
    dashboard_no_auth: bool = False  # dev only: open the /__ dashboard/management boundary

    @classmethod
    def from_env(cls):
        return cls(mode=os.getenv("BASTION_MODE", "observe"),
                   management_token=os.getenv("MANAGEMENT_TOKEN", ""),
                   inline_failure=os.getenv("INLINE_FAILURE", "reject"),
                   demo_identity=os.getenv("DEMO_IDENTITY", "0") == "1",
                   trusted_proxies=os.getenv("TRUSTED_PROXY_CIDRS", ""),
                   request_limit=int(os.getenv("MAX_REQUEST_BYTES", "65536")),
                   response_limit=int(os.getenv("MAX_RESPONSE_BYTES", "2097152")),
                   timeout=float(os.getenv("CLASSIFIER_TIMEOUT", "5")),
                   concurrency=int(os.getenv("CLASSIFIER_CONCURRENCY", "8")),
                   budget_per_minute=int(os.getenv("MODEL_CALLS_PER_MINUTE", "120")),
                   queue_limit=int(os.getenv("QUEUE_LIMIT", "10000")),
                   allow_destructive=os.getenv("ALLOW_DESTRUCTIVE", "0") == "1",
                   dashboard_no_auth=os.getenv("DASHBOARD_NO_AUTH", "0") == "1")

    def validate(self, role="proxy"):
        if self.mode not in MODES:
            raise ValueError(f"BASTION_MODE must be one of {sorted(MODES)}")
        if self.inline_failure not in {"allow", "reject"}:
            raise ValueError("INLINE_FAILURE must be allow or reject")
        if min(self.request_limit, self.response_limit, self.timeout, self.concurrency,
               self.budget_per_minute, self.queue_limit) <= 0:
            raise ValueError("limits and deadlines must be positive")
        if len(self.management_token) < 32:
            raise ValueError("MANAGEMENT_TOKEN must contain at least 32 characters")
        if self.mode in {"inline", "classifier-contain"} and not real_key("TYPESAFE_API_KEY"):
            raise ValueError(f"{self.mode} requires a real TYPESAFE_API_KEY")
        if self.mode == "agent" and not (real_key("ANTHROPIC_API_KEY") or real_key("DEEPSEEK_API_KEY")):
            raise ValueError("agent mode requires a real LLM key")
        if role == "blue" and self.mode == "agent" and not os.getenv("ACTUATOR_TOKEN"):
            raise ValueError("agent mode requires ACTUATOR_TOKEN")
        return self
