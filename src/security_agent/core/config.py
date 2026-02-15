from pathlib import Path
from typing import Optional
import yaml
from rich.console import Console

console = Console()

CONFIG_DIR = Path(__file__).parent.parent.parent.parent / "config"


def load_config(profile: Optional[str] = None) -> dict:
    """Load scan configuration, optionally overlaying a scan profile."""
    default_path = CONFIG_DIR / "default_config.yaml"
    if not default_path.exists():
        console.print("[yellow]Warning: default_config.yaml not found, using built-in defaults[/]")
        return _builtin_defaults()

    with open(default_path, "r") as f:
        config = yaml.safe_load(f)

    if profile:
        profile_path = CONFIG_DIR / "scan_profiles" / f"{profile}.yaml"
        if profile_path.exists():
            with open(profile_path, "r") as f:
                profile_config = yaml.safe_load(f)
            config = _deep_merge(config, profile_config)
        else:
            console.print(f"[yellow]Warning: Profile '{profile}' not found, using defaults[/]")

    return config


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dictionaries, with override taking precedence."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _builtin_defaults() -> dict:
    return {
        "scan": {
            "timeout": 30,
            "max_concurrent": 5,
            "rate_limit": 10,
            "user_agent": "SecurityAgent/1.0 (Authorized Security Scan)",
            "follow_redirects": True,
            "max_redirects": 5,
            "verify_ssl": True,
        },
        "scanners": {},
        "ai": {"enabled": False},
        "reporting": {"formats": ["json"], "output_dir": "./reports"},
        "human_loop": {"enabled": True, "require_phase_approval": True},
    }
