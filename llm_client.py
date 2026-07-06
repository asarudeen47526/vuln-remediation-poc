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
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        if r.returncode != 0:
            raise RuntimeError(
                f"claude CLI exited {r.returncode}: {r.stderr.strip() or r.stdout.strip()}"
            )
        return r.stdout.strip()

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
