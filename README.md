# vigil

Lightweight security monitor for home users. Watches your crypto wallets, critical system directories, and (soon) network traffic — then alerts you via Slack, Matrix, or your SIEM.

Two working modules in v0.1:

**Crypto Wallet Watchdog** — monitors public ETH and BTC addresses via free APIs (Etherscan, Blockstream). Alerts on large outbound transfers and transactions to flagged addresses. Prices fetched live from CoinGecko. Rate-limit safe, deduplicates alerts, filters outbound only (deposits don't trigger alerts).

**File Integrity Monitor** — SHA-256 baseline of critical directories (startup folders, browser extension storage, cron). Alerts when files are added, removed, or modified. No external dependencies. Works on Windows and Linux with sensible defaults.

Both modules share one alert pipeline and one config file.

## Quick Start

```bash
git clone https://github.com/jawsec/vigil.git
cd vigil
pip install -r requirements.txt
cp config.yaml.example config.yaml   # edit with your wallet addresses
python -m vigil crypto --once         # test crypto monitor (single check)
python -m vigil files --once          # test file integrity monitor
python -m vigil all                   # run everything continuously
```

## Usage

```
vigil crypto --once     Single crypto check, then exit
vigil crypto            Continuous crypto monitoring (~60s cycles)
vigil files --once      Build baseline + scan once
vigil files             Continuous file integrity monitoring (default: 5min cycles)
vigil all --once        Single check on all enabled monitors
vigil all               Run all enabled monitors in parallel
```

Add `--verbose` for debug logging. Use `--config path/to/config.yaml` for a custom config location.

## Configuration

Copy `config.yaml.example` to `config.yaml` and edit. The example config includes real public addresses (Ethereum Foundation, Satoshi genesis) so you can test immediately.

Key settings:

- `alert.type` — where alerts go: `slack`, `matrix`, `json` (structured stdout for SIEM), or `stdout` (plain text)
- `monitors.crypto.wallets` — your public wallet addresses organized by chain
- `monitors.crypto.thresholds.large_transfer_usd` — dollar threshold for outbound transfer alerts
- `monitors.crypto.flagged_addresses` — known-bad addresses that trigger alerts at any amount
- `monitors.file_integrity.watch_paths` — directories to monitor (or `["defaults"]` for platform defaults)

See [config.yaml.example](config.yaml.example) for full documentation.

## Architecture

```
vigil/
├── cli.py              # Subcommand CLI (crypto, files, all)
├── config.py           # YAML loader with validation
├── alerts.py           # Shared alert pipeline (Slack, Matrix, JSON, stdout)
└── monitors/
    ├── crypto.py       # ETH + BTC wallet monitoring
    ├── file_integrity.py   # SHA-256 directory watching
    └── network.py      # Planned for v0.3
```

Design decisions documented in source. Each monitor exposes a `run(config, once=False)` entry point. The CLI handles threading when running multiple monitors via `vigil all`.

## Pairing with Sigma Rules

This tool is designed to complement [jawsec/sigma-detection-rules](https://github.com/jawsec/sigma-detection-rules). The Sigma rules detect threats in your SIEM logs. Vigil detects threats that don't show up in Sysmon — blockchain transactions, file changes outside of logged events, and (eventually) network IOCs.

Together they cover the full kill-chain: Sigma catches the attack, vigil catches the impact.

## Roadmap

- **v0.1** — Crypto wallet monitor + file integrity monitor (current)
- **v0.2** — Solana support, rapid transaction velocity detection, configurable baseline persistence
- **v0.3** — Network threat feed monitor (abuse.ch, Feodo Tracker)
- **v1.0** — Systemd/Windows service support, tray icon, web dashboard

## Requirements

- Python 3.10+
- `requests` and `pyyaml` (see requirements.txt)
- Free Etherscan API key (optional, improves rate limits)
- No databases, no Docker, no complex setup

## License

MIT — see [LICENSE](LICENSE).

---

Built by [jawsec](https://github.com/jawsec) | Kino Security LLC
