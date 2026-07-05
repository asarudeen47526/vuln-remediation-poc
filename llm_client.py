"""Provider-agnostic LLM adapter.

Exposes a single function generate(system, user) -> str that works with
Anthropic (Claude), OpenAI (GPT), or Google (Gemini) depending on
config.LLM_PROVIDER. Each SDK reads its own API key from the environment:

    anthropic -> ANTHROPIC_API_KEY
    openai    -> OPENAI_API_KEY
    gemini    -> GEMINI_API_KEY  (or GOOGLE_API_KEY)

Model ids move fast; override with LLM_MODEL if a default is out of date.
"""
from config import LLM_PROVIDER, LLM_MODEL

# Reasonable defaults as of early-mid 2026. Verify against each provider's
# current model list; override via the LLM_MODEL env var.
DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5",
    "openai": "gpt-4.1",
    "gemini": "gemini-2.5-flash",
}


def _model() -> str:
    return LLM_MODEL or DEFAULT_MODELS[LLM_PROVIDER]


def generate(system: str, user: str) -> str:
    """Send a system+user prompt to the configured provider, return the text."""
    if LLM_PROVIDER == "anthropic":
        from anthropic import Anthropic
        client = Anthropic()  # reads ANTHROPIC_API_KEY
        msg = client.messages.create(
            model=_model(),
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")

    if LLM_PROVIDER == "openai":
        from openai import OpenAI
        client = OpenAI()  # reads OPENAI_API_KEY
        r = client.chat.completions.create(
            model=_model(),
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return r.choices[0].message.content

    if LLM_PROVIDER == "gemini":
        from google import genai  # package: google-genai (NOT google-generativeai)
        client = genai.Client()  # reads GEMINI_API_KEY / GOOGLE_API_KEY
        r = client.models.generate_content(
            model=_model(),
            contents=f"{system}\n\n{user}",
        )
        return r.text

    raise ValueError(f"Unknown LLM_PROVIDER: {LLM_PROVIDER!r}")
