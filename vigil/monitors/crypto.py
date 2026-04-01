"""Crypto Wallet Watchdog — monitors public wallet addresses for suspicious activity.

Supported chains:
  - ETH via Etherscan (free tier, optional API key)
  - BTC via Blockstream (no key needed)

Detection cases:
  - Large outbound transfers exceeding a USD threshold
  - Transactions to addresses on a user-maintained flagged list

Design decisions:
  - Prices fetched once per cycle via CoinGecko (single call, comma-separated IDs)
  - Deduplication uses a set for O(1) lookup + a deque for bounded memory (max 2000 tx hashes)
  - Only outbound transactions trigger alerts (inbound deposits are not security events)
  - 5-second delay between API calls to stay within Etherscan's free-tier rate limit
  - Price lookup failures skip the entire cycle rather than alerting with wrong values
"""

import logging
import time
import requests
from collections import deque

from vigil.alerts import send_alert

logger = logging.getLogger("vigil")

COINGECKO_URL = "https://api.coingecko.com/api/v3/simple/price"
ETHERSCAN_URL = "https://api.etherscan.io/api"
BLOCKSTREAM_URL = "https://blockstream.info/api"

# Bounded dedup: deque enforces max size, set gives O(1) lookup.
# When the deque evicts an old hash, we remove it from the set too.
_seen_order = deque(maxlen=2000)
_seen_set = set()


def _mark_seen(tx_id: str) -> bool:
    """Record a transaction as seen. Returns True if it was already seen."""
    if tx_id in _seen_set:
        return True
    if len(_seen_order) == _seen_order.maxlen:
        # Deque is full — the oldest entry is about to be evicted
        evicted = _seen_order[0]
        _seen_set.discard(evicted)
    _seen_order.append(tx_id)
    _seen_set.add(tx_id)
    return False


def _fetch_prices() -> dict | None:
    """Fetch ETH and BTC prices in a single CoinGecko call.

    Returns dict like {"ethereum": 3500.0, "bitcoin": 97000.0} or None on failure.
    """
    try:
        resp = requests.get(
            COINGECKO_URL,
            params={"ids": "ethereum,bitcoin", "vs_currencies": "usd"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "ethereum": float(data["ethereum"]["usd"]),
            "bitcoin": float(data["bitcoin"]["usd"]),
        }
    except Exception as e:
        logger.warning(f"Price fetch failed — skipping alerts this cycle: {e}")
        return None


def _check_eth(address: str, config: dict, price: float, threshold: float, flagged: set) -> None:
    """Check recent ETH transactions for a single address."""
    try:
        api_key = config.get("monitors", {}).get("crypto", {}).get("etherscan_api_key", "")
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "sort": "desc",
            "page": 1,
            "offset": 10,
        }
        if api_key:
            params["apikey"] = api_key

        resp = requests.get(ETHERSCAN_URL, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "1":
            # Etherscan returns status "0" for errors or empty results
            msg = data.get("message", "unknown error")
            if "No transactions found" not in msg:
                logger.warning(f"Etherscan returned status 0 for {address[:10]}...: {msg}")
            return

        for tx in data.get("result", []):
            tx_hash = tx.get("hash", "")
            if not tx_hash or _mark_seen(tx_hash):
                continue

            # Only alert on outbound transactions from the monitored address
            tx_from = tx.get("from", "").lower()
            if tx_from != address.lower():
                continue

            value_eth = int(tx.get("value", 0)) / 1e18
            value_usd = value_eth * price
            tx_to = tx.get("to", "")

            # Check flagged addresses
            if tx_to.lower() in flagged:
                send_alert(
                    f"ETH transaction to FLAGGED address: {tx_to[:10]}... "
                    f"(${value_usd:,.0f}) from {address[:10]}...",
                    config,
                    source="crypto",
                )
                continue

            # Check large transfer threshold
            if value_usd > threshold:
                send_alert(
                    f"Large ETH outbound: ${value_usd:,.0f} ({value_eth:.4f} ETH) "
                    f"from {address[:10]}... to {tx_to[:10]}...",
                    config,
                    source="crypto",
                )

    except requests.RequestException as e:
        logger.warning(f"ETH check failed for {address[:10]}...: {e}")
    except (KeyError, ValueError, TypeError) as e:
        logger.warning(f"ETH response parsing error for {address[:10]}...: {e}")


def _check_btc(address: str, config: dict, price: float, threshold: float, flagged: set) -> None:
    """Check recent BTC transactions for a single address."""
    try:
        resp = requests.get(f"{BLOCKSTREAM_URL}/address/{address}/txs", timeout=10)
        resp.raise_for_status()
        txs = resp.json()

        for tx in txs[:5]:
            txid = tx.get("txid", "")
            if not txid or _mark_seen(txid):
                continue

            # Determine if this is outbound by checking if our address appears in inputs
            is_outbound = False
            for vin in tx.get("vin", []):
                prevout = vin.get("prevout", {})
                if prevout.get("scriptpubkey_address", "") == address:
                    is_outbound = True
                    break

            if not is_outbound:
                continue

            # Sum outputs that are NOT back to our address (actual amount sent out)
            value_sat = sum(
                vout.get("value", 0)
                for vout in tx.get("vout", [])
                if vout.get("scriptpubkey_address", "") != address
            )
            value_btc = value_sat / 100_000_000
            value_usd = value_btc * price

            # Collect destination addresses for flagged check
            destinations = [
                vout.get("scriptpubkey_address", "")
                for vout in tx.get("vout", [])
                if vout.get("scriptpubkey_address", "") != address
            ]

            flagged_dest = [d for d in destinations if d.lower() in flagged]
            if flagged_dest:
                send_alert(
                    f"BTC transaction to FLAGGED address: {flagged_dest[0][:10]}... "
                    f"(${value_usd:,.0f}) from {address[:10]}...",
                    config,
                    source="crypto",
                )
                continue

            if value_usd > threshold:
                dest_display = destinations[0][:10] if destinations else "unknown"
                send_alert(
                    f"Large BTC outbound: ${value_usd:,.0f} ({value_btc:.6f} BTC) "
                    f"from {address[:10]}... to {dest_display}...",
                    config,
                    source="crypto",
                )

    except requests.RequestException as e:
        logger.warning(f"BTC check failed for {address[:10]}...: {e}")
    except (KeyError, ValueError, TypeError) as e:
        logger.warning(f"BTC response parsing error for {address[:10]}...: {e}")


def run(config: dict, once: bool = False) -> None:
    """Main entry point for the crypto wallet monitor.

    Args:
        config: Validated vigil config dict.
        once: If True, run one check cycle and exit. Useful for testing.
    """
    crypto_cfg = config["monitors"]["crypto"]
    threshold = crypto_cfg["thresholds"]["large_transfer_usd"]
    wallets = crypto_cfg.get("wallets", {})
    flagged = {addr.lower() for addr in crypto_cfg.get("flagged_addresses", [])}

    # Count total wallets for logging
    total = sum(len(addrs) for addrs in wallets.values())
    mode = "single check" if once else "continuous monitoring"
    logger.info(f"Crypto monitor started — {total} wallet(s), threshold ${threshold:,.0f}, {mode}")

    while True:
        prices = _fetch_prices()
        if prices is None:
            if once:
                logger.warning("Price fetch failed on single run — exiting.")
                return
            time.sleep(60)
            continue

        for chain, addresses in wallets.items():
            for addr in addresses:
                if chain == "eth" and "ethereum" in prices:
                    _check_eth(addr, config, prices["ethereum"], threshold, flagged)
                    time.sleep(5)  # Etherscan free-tier: 1 call per 5 seconds
                elif chain == "btc" and "bitcoin" in prices:
                    _check_btc(addr, config, prices["bitcoin"], threshold, flagged)
                    time.sleep(2)  # Blockstream is more lenient
                else:
                    logger.warning(f"Unsupported chain '{chain}' — skipping {addr[:10]}...")

        if once:
            logger.info("Single check complete.")
            return

        # Sleep remainder of the cycle. Total cycle time depends on wallet count
        # but the per-call sleeps above handle rate limiting. This just adds a buffer.
        time.sleep(30)
