"""Provider-agnostic LLM adapter.

Exposes a single function generate(system, user) -> str that works with
Anthropic (Claude), OpenAI (GPT), Google (Gemini), or the local Claude Code
CLI session depending on config.LLM_PROVIDER:

    anthropic  -> ANTHROPIC_API_KEY  (Anthropic API)
    openai     -> OPENAI_API_KEY     (OpenAI API)
    gemini     -> GEMINI_API_KEY     (Google Gemini API)
    claude-sdk -> no API key needed; reuses the `claude` CLI session token
                  stored in ~/.claude (requires Claude Code to be installed
                  and logged in via `claude login`)

Model ids move fast; override with LLM_MODEL if a default is out of date.
"""
import glob
import os
import shutil
import subprocess

from config import LLM_PROVIDER, LLM_MODEL


class LLMConfigError(RuntimeError):
    """Raised when the LLM cannot be called because of missing or invalid
    configuration: API key not set, wrong key, not logged in, etc.
    Callers catch this separately from generic runtime errors so a clear,
    actionable message can be surfaced to the user instead of a stack trace.
    """


def _find_claude_exe() -> str:
    """Return the path to the claude CLI executable.

    Resolution order:
      1. CLAUDE_CLI_PATH env var (explicit override)
      2. shutil.which("claude") — works when claude is on PATH
      3. Windows App Store install pattern (Claude desktop app)
    Raises RuntimeError if not found.
    """
    override = os.getenv("CLAUDE_CLI_PATH", "").strip()
    if override:
        return override

    found = shutil.which("claude") or shutil.which("claude.cmd")
    if found:
        return found

    # Windows App Store / desktop app installs claude.exe under AppData\Local\Packages
    appdata = os.environ.get("LOCALAPPDATA", "")
    if appdata:
        pattern = os.path.join(
            appdata, "Packages", "Claude_*",
            "LocalCache", "Roaming", "Claude", "claude-code", "*", "claude.exe",
        )
        matches = sorted(glob.glob(pattern), reverse=True)  # newest version first
        if matches:
            return matches[0]

    raise RuntimeError(
        "claude CLI not found. Either:\n"
        "  1. Add claude.exe to PATH, or\n"
        "  2. Set CLAUDE_CLI_PATH=/full/path/to/claude.exe in .env"
    )

# Reasonable defaults as of early-mid 2026. Verify against each provider's
# current model list; override via the LLM_MODEL env var.
DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5",
    "openai":    "gpt-4.1",
    "gemini":    "gemini-2.5-flash",
    "claude-sdk": "claude-sonnet-5",  # passed to --model; omit to use CLI default
}


def _model() -> str:
    return LLM_MODEL or DEFAULT_MODELS.get(LLM_PROVIDER, "")


def generate(system: str, user: str) -> str:
    """Send a system+user prompt to the configured provider, return the text."""

    # ------------------------------------------------------------------
    # claude-sdk: reuse the Claude Code CLI session — no API key needed
    # Requires: `claude` on PATH and logged in via `claude login`
    # ------------------------------------------------------------------
    if LLM_PROVIDER == "claude-sdk":
        exe = _find_claude_exe()
        cmd = [
            exe, "-p", user,
            "--system-prompt", system,
            "--output-format", "text",
        ]
        model = _model()
        if model:
            cmd += ["--model", model]
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=120)
        if r.returncode != 0:
            stderr = (r.stderr.strip() or r.stdout.strip())
            if any(kw in stderr.lower() for kw in
                   ("not logged in", "unauthorized", "login", "auth", "session")):
                raise LLMConfigError(
                    f"Claude CLI is not authenticated. "
                    f"Run 'claude login' on the control node and try again.\n"
                    f"Detail: {stderr}"
                )
            raise RuntimeError(f"claude CLI exited {r.returncode}: {stderr}")
        return r.stdout.strip()

    if LLM_PROVIDER == "anthropic":
        key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        if not key:
            raise LLMConfigError(
                "ANTHROPIC_API_KEY is not set. "
                "Add it to .env: ANTHROPIC_API_KEY=sk-ant-api03-... then restart."
            )
        try:
            from anthropic import Anthropic
            client = Anthropic(api_key=key)
            msg = client.messages.create(
                model=_model(),
                max_tokens=1024,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        except Exception as exc:
            s = str(exc).lower()
            if any(kw in s for kw in ("authentication", "invalid x-api-key", "401", "unauthorized", "api_key")):
                raise LLMConfigError(
                    f"Anthropic API key is invalid or expired. "
                    f"Verify ANTHROPIC_API_KEY in .env, then restart.\nDetail: {exc}"
                ) from exc
            raise

    if LLM_PROVIDER == "openai":
        key = os.getenv("OPENAI_API_KEY", "").strip()
        if not key:
            raise LLMConfigError(
                "OPENAI_API_KEY is not set. "
                "Add it to .env: OPENAI_API_KEY=sk-proj-... then restart."
            )
        try:
            from openai import OpenAI
            client = OpenAI(api_key=key)
            r = client.chat.completions.create(
                model=_model(),
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
            return r.choices[0].message.content
        except Exception as exc:
            s = str(exc).lower()
            if any(kw in s for kw in ("authentication", "incorrect api key", "401", "unauthorized")):
                raise LLMConfigError(
                    f"OpenAI API key is invalid or expired. "
                    f"Verify OPENAI_API_KEY in .env, then restart.\nDetail: {exc}"
                ) from exc
            raise

    if LLM_PROVIDER == "gemini":
        key = (os.getenv("GEMINI_API_KEY", "") or os.getenv("GOOGLE_API_KEY", "")).strip()
        if not key:
            raise LLMConfigError(
                "GEMINI_API_KEY (or GOOGLE_API_KEY) is not set. "
                "Add it to .env: GEMINI_API_KEY=... then restart."
            )
        try:
            from google import genai  # package: google-genai (NOT google-generativeai)
            client = genai.Client(api_key=key)
            r = client.models.generate_content(
                model=_model(),
                contents=f"{system}\n\n{user}",
            )
            return r.text
        except Exception as exc:
            s = str(exc).lower()
            if any(kw in s for kw in ("api_key", "credentials", "401", "unauthorized", "permission")):
                raise LLMConfigError(
                    f"Gemini API key is invalid or expired. "
                    f"Verify GEMINI_API_KEY in .env, then restart.\nDetail: {exc}"
                ) from exc
            raise

    raise ValueError(f"Unknown LLM_PROVIDER: {LLM_PROVIDER!r}")
