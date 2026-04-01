"""Command-line interface for vigil.

Usage:
    python -m vigil.cli crypto --once     # Test crypto monitor (single check)
    python -m vigil.cli crypto            # Run crypto monitor continuously
    python -m vigil.cli files --once      # Test file integrity monitor
    python -m vigil.cli files             # Run file integrity monitor continuously
    python -m vigil.cli all               # Run all enabled monitors
    python -m vigil.cli all --once        # Single check on all enabled monitors
"""

import argparse
import logging
import sys
import threading

from vigil import __version__
from vigil.config import ConfigError, load_config


def _setup_logging(verbose: bool = False) -> None:
    """Configure logging format and level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="[%(asctime)s] [vigil.%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=level,
    )


def _run_crypto(config: dict, once: bool) -> None:
    """Import and run the crypto monitor."""
    from vigil.monitors.crypto import run
    run(config, once=once)


def _run_files(config: dict, once: bool) -> None:
    """Import and run the file integrity monitor."""
    from vigil.monitors.file_integrity import run
    run(config, once=once)


def _run_all(config: dict, once: bool) -> None:
    """Run all enabled monitors. In continuous mode, each runs in its own thread."""
    monitors = config.get("monitors", {})
    runners = []

    crypto = monitors.get("crypto", {})
    if isinstance(crypto, dict) and crypto.get("enabled", False):
        runners.append(("crypto", _run_crypto))

    fim = monitors.get("file_integrity", {})
    if isinstance(fim, dict) and fim.get("enabled", False):
        runners.append(("files", _run_files))

    if not runners:
        print("No monitors enabled in config.yaml. Nothing to run.")
        sys.exit(1)

    if once:
        # Sequential single checks
        for name, runner in runners:
            runner(config, once=True)
        return

    # Continuous mode: each monitor in its own thread
    threads = []
    for name, runner in runners:
        t = threading.Thread(target=runner, args=(config, False), name=f"vigil-{name}", daemon=True)
        t.start()
        threads.append(t)

    # Block until interrupted
    try:
        for t in threads:
            while t.is_alive():
                t.join(timeout=1)
    except KeyboardInterrupt:
        print("\n[vigil] Shutting down.")
        sys.exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vigil",
        description="Lightweight home security monitor — crypto wallets, file integrity, network threats.",
    )
    parser.add_argument("--version", action="version", version=f"vigil {__version__}")
    parser.add_argument("--config", default="config.yaml", help="Path to config file (default: config.yaml)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    subparsers = parser.add_subparsers(dest="command")

    # crypto subcommand
    crypto_parser = subparsers.add_parser("crypto", help="Run crypto wallet monitor")
    crypto_parser.add_argument("--once", action="store_true", help="Run one check cycle and exit")

    # files subcommand
    files_parser = subparsers.add_parser("files", help="Run file integrity monitor")
    files_parser.add_argument("--once", action="store_true", help="Scan once and exit")

    # all subcommand
    all_parser = subparsers.add_parser("all", help="Run all enabled monitors")
    all_parser.add_argument("--once", action="store_true", help="Run one check cycle per monitor and exit")

    args = parser.parse_args()
    _setup_logging(verbose=args.verbose)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"[vigil] Config error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.command == "crypto":
        if not config.get("monitors", {}).get("crypto", {}).get("enabled", False):
            print("[vigil] Crypto monitor is not enabled in config.yaml.")
            sys.exit(1)
        _run_crypto(config, once=args.once)

    elif args.command == "files":
        if not config.get("monitors", {}).get("file_integrity", {}).get("enabled", False):
            print("[vigil] File integrity monitor is not enabled in config.yaml.")
            sys.exit(1)
        _run_files(config, once=args.once)

    elif args.command == "all":
        _run_all(config, once=args.once)


if __name__ == "__main__":
    main()
