"""
LLM Client Utilities

Provides helper functions to create LLM clients from configuration,
especially for subprocess/cron environments where no Claude session exists.

Supports two backends:
  - SimpleLLMClient: Anthropic SDK (API billing users, needs sk-ant-xxx key)
  - CLILLMClient: claude CLI (Claude Max users, uses OAuth authentication)
"""

import os
import shutil
import subprocess
import yaml
import logging
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class SimpleLLMClient:
    """
    Simple LLM client wrapper for Anthropic API.
    Compatible with skill_framework's llm_client interface.
    """

    def __init__(self, api_key: str, base_url: Optional[str] = None, model: str = "claude-sonnet-4-5-20250929"):
        """
        Initialize Anthropic client.

        Args:
            api_key: Anthropic API key
            base_url: Optional API base URL
            model: Model name to use
        """
        try:
            from anthropic import Anthropic
        except ImportError:
            raise ImportError(
                "anthropic package is required. Install with: pip install anthropic>=0.18.0"
            )

        self.api_key = api_key
        self.base_url = base_url
        self.model = model

        # Initialize Anthropic client
        client_kwargs = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url

        self.client = Anthropic(**client_kwargs)
        logger.info(f"Initialized Anthropic client with model: {model}")

    def generate(self, prompt: str, max_tokens: int = 4096, temperature: float = 0.0) -> str:
        """
        Generate response from LLM.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature

        Returns:
            Generated text response
        """
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}],
            )

            # Extract text from response
            if response.content and len(response.content) > 0:
                return response.content[0].text
            else:
                return ""

        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            raise


class CLILLMClient:
    """
    LLM client that calls `claude` CLI for inference.
    For Claude Max users who authenticate via OAuth (no API key needed).

    Same `generate()` interface as SimpleLLMClient.
    """

    def __init__(self, claude_path: str = "claude", model: str = "", timeout: int = 120):
        self.claude_path = claude_path
        self.model = model
        self.timeout = timeout
        self.backend = "claude-cli"
        logger.info(f"Initialized claude CLI client (path: {claude_path})")

    def generate(self, prompt: str, max_tokens: int = 4096, temperature: float = 0.0) -> str:
        """
        Generate response by calling claude CLI.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate
            temperature: Ignored (claude CLI uses default)

        Returns:
            Generated text response
        """
        cmd = [self.claude_path, "-p", prompt, "--output-format", "text"]

        if self.model:
            cmd.extend(["--model", self.model])

        logger.info(f"Calling claude CLI (prompt_len={len(prompt)})")

        try:
            # Remove CLAUDECODE env var to allow running inside a Claude Code session
            env = os.environ.copy()
            env.pop("CLAUDECODE", None)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )

            if result.returncode != 0:
                stderr = result.stderr.strip()
                raise RuntimeError(f"claude CLI failed (exit {result.returncode}): {stderr}")

            response_text = result.stdout.strip()
            if not response_text:
                raise RuntimeError("claude CLI returned empty response")

            logger.info(f"claude CLI response received (len={len(response_text)})")
            return response_text

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"claude CLI timed out after {self.timeout}s")


def _get_api_key() -> Optional[str]:
    """Get API key from environment if it looks like a real API key (sk-ant- prefix)."""
    for env_var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        key = os.environ.get(env_var, "").strip()
        if key and key.startswith("sk-ant-"):
            return key
    return None


def _check_claude_cli() -> Optional[str]:
    """Check if `claude` CLI is available and functional."""
    claude_path = shutil.which("claude")
    if not claude_path:
        return None
    try:
        result = subprocess.run(
            [claude_path, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            logger.info(f"Found claude CLI: {result.stdout.strip()}")
            return claude_path
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def load_config_file() -> Dict[str, Any]:
    """
    Load configuration file from multiple possible locations.

    Returns:
        Configuration dictionary
    """
    # Try multiple config locations
    config_paths = [
        Path(__file__).parent.parent / "config" / "config.yml",  # Relative to this file
        Path.cwd() / "config" / "config.yml",  # Current working directory
        Path.home() / ".claude" / "skills" / "skills-audit" / "config" / "config.yml",  # User home
    ]

    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    config = yaml.safe_load(f)
                    logger.info(f"Loaded config from: {config_path}")
                    return config
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")

    logger.warning("No config file found, using defaults")
    return {}


def expand_env_vars(value: str) -> str:
    """
    Expand environment variables in config values.

    Example:
        "${ANTHROPIC_AUTH_TOKEN}" -> actual env var value

    Args:
        value: Config value that may contain ${VAR_NAME}

    Returns:
        Expanded value
    """
    if not isinstance(value, str):
        return value

    # Match ${VAR_NAME} pattern
    import re

    def replace_env_var(match):
        var_name = match.group(1)
        return os.getenv(var_name, "")

    return re.sub(r"\$\{([^}]+)\}", replace_env_var, value)


def create_llm_client_from_config(config: Optional[Dict[str, Any]] = None):
    """
    Create LLM client from configuration.

    Priority:
      1. API key with sk-ant- prefix → SimpleLLMClient (Anthropic SDK, faster)
      2. `claude` CLI available → CLILLMClient (Claude Max, OAuth)
      3. Neither → None (AI phases will be skipped)

    Args:
        config: Configuration dict (if None, will load from file)

    Returns:
        SimpleLLMClient, CLILLMClient, or None
    """
    if config is None:
        config = load_config_file()

    llm_config = config.get("llm", {})
    model = llm_config.get("model", "claude-sonnet-4-5-20250929")

    # 1. Try API key (SDK mode) — check config first, then env vars
    api_key = expand_env_vars(llm_config.get("api_key", ""))
    if not api_key or not api_key.startswith("sk-ant-"):
        api_key = _get_api_key()

    if api_key:
        base_url = expand_env_vars(llm_config.get("base_url", ""))
        if not base_url:
            base_url = os.getenv("ANTHROPIC_BASE_URL")
        try:
            client = SimpleLLMClient(api_key=api_key, base_url=base_url, model=model)
            logger.info("LLM client: Anthropic SDK (API billing)")
            return client
        except ImportError:
            logger.warning("API key found but `anthropic` package not installed")
        except Exception as e:
            logger.error(f"Failed to create SDK client: {e}")

    # 2. Try claude CLI (Max mode)
    claude_path = _check_claude_cli()
    if claude_path:
        client = CLILLMClient(claude_path=claude_path, model=model)
        logger.info("LLM client: claude CLI (Claude Max)")
        return client

    # 3. Nothing available
    logger.error(
        "No LLM client available. Either set ANTHROPIC_API_KEY (sk-ant-xxx) "
        "or install claude CLI for Claude Max support."
    )
    return None


def ensure_llm_client(context, is_claude_code: bool = False) -> Optional[Any]:
    """
    Ensure LLM client is available, creating one from config if needed.

    Priority:
    1. If context.llm_client exists: use it
    2. If is_claude_code=True: return None (Claude will handle it)
    3. Otherwise: create client from config

    Args:
        context: SkillContext object
        is_claude_code: Whether running in Claude Code environment

    Returns:
        LLM client or None
    """
    # If client already exists, use it
    if context.llm_client:
        logger.debug("Using existing llm_client from context")
        return context.llm_client

    # If in Claude Code environment, return None (Claude handles it)
    if is_claude_code:
        logger.debug("Claude Code environment - Claude will handle LLM calls")
        return None

    # Otherwise, create client from config (for subprocess/cron)
    logger.info("No llm_client in context - creating from config (subprocess mode)")
    client = create_llm_client_from_config()

    if client:
        # Inject into context for subsequent use
        context.llm_client = client
        logger.info("Successfully created and injected LLM client into context")
    else:
        logger.error("Failed to create LLM client from config")

    return client
