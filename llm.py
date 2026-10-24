"""Provider shim. The agents are written against the Anthropic Messages API;
this aims that same SDK at Anthropic OR DeepSeek's Anthropic-compatible endpoint,
chosen by whichever key is set, so blue + red stay provider-agnostic.

    DEEPSEEK_API_KEY  -> DeepSeek  (https://api.deepseek.com/anthropic, deepseek-chat)
    else ANTHROPIC_API_KEY -> Anthropic
    neither           -> no agent (blue falls back to Jev autoblock)
"""
import os

import anthropic

DEEPSEEK_BASE = "https://api.deepseek.com/anthropic"
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")


def provider():
    """'deepseek' | 'anthropic' | None — DeepSeek wins if its key is set (explicit opt-in)."""
    if os.environ.get("DEEPSEEK_API_KEY"):
        return "deepseek"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    return None


def make_client():
    """(client, create_kwargs) for the active provider, or (None, {}) if no key is set.
    create_kwargs carries provider-only Messages params — Anthropic's output_config,
    which DeepSeek's endpoint rejects."""
    p = provider()
    if p == "deepseek":
        return anthropic.Anthropic(api_key=os.environ["DEEPSEEK_API_KEY"],
                                   base_url=DEEPSEEK_BASE), {}
    if p == "anthropic":
        return anthropic.Anthropic(), {"output_config": {"effort": "low"}}
    return None, {}


def model_for(env_override, anthropic_default):
    """Resolve the model name for the active provider. On DeepSeek: a deepseek-* override
    if given, else DEEPSEEK_MODEL (a stale claude-* default left in .env is ignored, so the
    example .env works with just a key added). On Anthropic: the override or the default."""
    if provider() == "deepseek":
        if env_override and not env_override.startswith("claude"):
            return env_override
        return DEEPSEEK_MODEL
    return env_override or anthropic_default
