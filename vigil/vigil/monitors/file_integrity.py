"""File Integrity Monitor — watches critical directories for unexpected changes.

Computes SHA-256 hashes of all files in configured directories and alerts when
files are added, removed, or modified. Designed to catch persistence mechanisms
(startup folder drops, browser extension tampering) and unauthorized changes.

Design decisions:
  - Baseline is built on first run and stored in memory (no external database)
  - Only files are hashed, not directories — empty directory creation is ignored
  - Files that can't be read (permissions, locks) are logged and skipped, not crashed on
  - Configurable watch paths with sensible defaults for Windows and Linux
  - Runs alongside the crypto monitor in the same process via the shared CLI
"""

import hashlib
import logging
import os
import platform
import time
from pathlib import Path

from vigil.alerts import send_alert

logger = logging.getLogger("vigil")


# Sensible default paths if the user doesn't configure any.
# These cover the most common persistence and theft targets.
DEFAULT_WATCH_PATHS_WINDOWS = [
    # Startup folders (per-user and all-users)
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    # Browser wallet extensions (Chrome default profile)
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings"),
    # Browser wallet extensions (Edge default profile)
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Local Extension Settings"),
]

DEFAULT_WATCH_PATHS_LINUX = [
    os.path.expanduser("~/.config/autostart"),
    os.path.expanduser("~/.local/share/applications"),
    os.path.expanduser("~/.config/google-chrome/Default/Local Extension Settings"),
    "/etc/cron.d",
]


def _get_default_paths() -> list[str]:
    """Return platform-appropriate default watch paths."""
    if platform.system() == "Windows":
        return DEFAULT_WATCH_PATHS_WINDOWS
    return DEFAULT_WATCH_PATHS_LINUX


def _hash_file(filepath: str) -> str | None:
    """Compute SHA-256 hash of a file. Returns None if the file can't be read."""
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError) as e:
        logger.debug(f"Cannot hash {filepath}: {e}")
        return None


def _scan_directory(dirpath: str) -> dict[str, str]:
    """Walk a directory and return {filepath: sha256_hash} for all readable files."""
    results = {}
    path = Path(dirpath)
    if not path.exists():
        logger.debug(f"Watch path does not exist (skipping): {dirpath}")
        return results
    if not path.is_dir():
        # Single file — hash it directly
        file_hash = _hash_file(str(path))
        if file_hash:
            results[str(path)] = file_hash
        return results

    for root, _dirs, files in os.walk(dirpath):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_hash = _hash_file(filepath)
            if file_hash is not None:
                results[filepath] = file_hash

    return results


def _build_baseline(watch_paths: list[str]) -> dict[str, str]:
    """Build initial baseline of all files in all watch paths."""
    baseline = {}
    for dirpath in watch_paths:
        baseline.update(_scan_directory(dirpath))
    return baseline


def _check_changes(baseline: dict[str, str], current: dict[str, str]) -> tuple[list, list, list]:
    """Compare current scan against baseline.

    Returns:
        Tuple of (new_files, removed_files, modified_files).
    """
    baseline_paths = set(baseline.keys())
    current_paths = set(current.keys())

    new_files = sorted(current_paths - baseline_paths)
    removed_files = sorted(baseline_paths - current_paths)
    modified_files = sorted(
        p for p in baseline_paths & current_paths
        if baseline[p] != current[p]
    )

    return new_files, removed_files, modified_files


def run(config: dict, once: bool = False) -> None:
    """Main entry point for the file integrity monitor.

    Args:
        config: Validated vigil config dict.
        once: If True, build baseline and run one comparison, then exit.
    """
    fim_cfg = config["monitors"]["file_integrity"]
    watch_paths = fim_cfg.get("watch_paths", [])
    check_interval = fim_cfg.get("check_interval_seconds", 300)

    # Use defaults if the user passed the special string "defaults"
    if watch_paths == ["defaults"] or not watch_paths:
        watch_paths = _get_default_paths()
        logger.info(f"Using default watch paths for {platform.system()}")

    # Filter to paths that actually exist
    existing = [p for p in watch_paths if Path(p).exists()]
    missing = [p for p in watch_paths if not Path(p).exists()]

    if missing:
        logger.info(f"Watch paths not found (skipping): {', '.join(missing)}")

    if not existing:
        logger.warning("No valid watch paths found. File integrity monitor has nothing to watch.")
        return

    # Build initial baseline
    logger.info(f"File integrity monitor started — scanning {len(existing)} path(s)")
    baseline = _build_baseline(existing)
    logger.info(f"Baseline established: {len(baseline)} file(s) indexed")

    if once:
        # In --once mode, scan twice with a 1-second gap to demonstrate the check works
        logger.info("Single check mode — rescanning for changes...")
        time.sleep(1)
        current = _build_baseline(existing)
        new_files, removed_files, modified_files = _check_changes(baseline, current)
        _report_changes(new_files, removed_files, modified_files, config)
        if not new_files and not removed_files and not modified_files:
            logger.info("No changes detected.")
        return

    # Continuous monitoring loop
    while True:
        time.sleep(check_interval)

        current = _build_baseline(existing)
        new_files, removed_files, modified_files = _check_changes(baseline, current)
        _report_changes(new_files, removed_files, modified_files, config)

        # Update baseline to current state after alerting
        # This means each change is alerted exactly once
        baseline = current


def _report_changes(
    new_files: list, removed_files: list, modified_files: list, config: dict
) -> None:
    """Send alerts for any detected changes."""
    for filepath in new_files:
        send_alert(
            f"New file detected: {filepath}",
            config,
            source="file_integrity",
        )

    for filepath in removed_files:
        send_alert(
            f"File removed: {filepath}",
            config,
            source="file_integrity",
        )

    for filepath in modified_files:
        send_alert(
            f"File modified: {filepath}",
            config,
            source="file_integrity",
        )
