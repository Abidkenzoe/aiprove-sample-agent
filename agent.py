#!/usr/bin/env python3
"""AIProve sample agent — the full loop, cleanly, in one file.

Reads https://aiprove.fun/skill.md, authenticates with its own keypair
(EIP-191 challenge -> sign -> session token), lists open bounties and
enters the nearest-deadline one.

    # dry run: auth + list only, no enter
    python3 agent.py --generate --dry-run

    # real run: auth + list + enter nearest-deadline bounty
    python3 agent.py --generate
    AGENT_PRIVATE_KEY=0x... python3 agent.py

Identity = your Ethereum-style address. No signup, no email, no password.
The keypair is either generated fresh (--generate, printed once — save it
yourself, it is never written to disk by this script) or supplied via the
AGENT_PRIVATE_KEY environment variable. Never hardcode a key in this repo.

Auth flow (per /skill.md, verified live 2026-11-13):
    GET  /api/auth/challenge?address=<addr>   -> {"challenge": "...", ...}
    sign challenge with EIP-191 personal_sign  -> signature, sent WITH 0x
    POST /api/auth/verify {address, signature} -> {"token": "<session>", ...}
    Bearer token on every write call.

Hardening (GPT-6.1-Sol review, 2026-11-14 — FIX before shipping):
  * All HTTP goes through one checked curl transport: -q -sS, connect
    timeout 10s, max time 45s, --proto =http,https, returncode checked,
    OSError/TimeoutExpired raised as RuntimeError.
  * Strict JSON: invalid JSON, an empty body, or a non-dict payload
    raises; challenge and token must be nonempty strings.
  * The list response must contain a `bounties` list of dicts; a full run
    with an empty list exits nonzero. A dry run is explicitly logged as
    incomplete evidence (auth + list only, enter never exercised).
  * Deadlines: missing/invalid endsAt sorts last (math.inf); the slug is
    validated as a nonempty string and URL-quoted in the enter path.
  * skill.md must return HTTP 200 through the same transport (not just
    substring checks).
  * The transcript is written in a finally block, even on failure.
  * No token material is logged (no token prefix, no raw auth/enter
    responses — status + allowlisted fields only). --save-session uses
    O_EXCL and refuses an existing path or symlink.

Gotchas found the hard way (2026-11-13, live API):
  * Plain urllib gets HTTP 403 from Cloudflare on this host, and large
    responses die with IncompleteRead. This agent does HTTP via curl
    with a browser User-Agent — that works reliably.
  * The live challenge text is:
        "aiprove.fun wants you to sign in with your agent wallet.\\n\\n
         Address: 0x...\\nNonce: ...\\nIssued-At: ...\\nDomain: aiprove.fun"
    It is a sign-in message only. This script inspects it before signing
    and aborts on any transfer/approve/spend/mint/payment wording, on a
    missing address, or on a missing aiprove.fun mention.
  * The signature MUST be sent with the "0x" prefix. Bare hex gets
    HTTP 401 "malformed signature".
  * Submitting auto-enters a bounty, so enter is optional — but this
    sample does the explicit enter step to demonstrate the full loop.
  * The session token is never logged and never saved to disk by default;
    use --save-session to store it mode 0600 (refuses existing files).

Dependencies: Python 3.10+, curl, eth-account (`pip install -r requirements.txt`).
"""
import argparse
import json
import math
import os
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import quote

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
except ImportError:  # pragma: no cover
    Account = None

DEFAULT_API = "https://aiprove.fun"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "Chrome/120 Safari/537.36")
CURL_TIMEOUT = 50  # subprocess timeout; curl --max-time is 45s inside it
LOG = []


class AgentError(Exception):
    """Controlled failure: a step of the loop could not complete."""


def log(msg: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"[{stamp}] {msg}"
    LOG.append(line)
    print(line, flush=True)


def _curl(args: list[str], url: str) -> subprocess.CompletedProcess:
    """Run curl with the hardened flag set; transport errors raise."""
    cmd = ["curl", "-q", "-sS", "--connect-timeout", "10",
           "--max-time", "45", "--proto", "=http,https"] + args + [url]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=CURL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"curl transport failed for {url}: {e}") from e
    if out.returncode != 0:
        raise RuntimeError(
            f"curl exited {out.returncode} for {url}: "
            f"{out.stderr.strip()[:300]}")
    return out


def _curl_with_status(args: list[str], url: str) -> tuple[int, str]:
    """Checked curl call returning (HTTP status, body text)."""
    out = _curl(["-w", "\n%{http_code}"] + args, url)
    text = out.stdout.strip()
    head, sep, tail = text.rpartition("\n")
    if not sep:
        # Whole output is just the status line (empty body).
        try:
            return int(text), ""
        except ValueError:
            raise RuntimeError(
                f"no HTTP status in response from {url}") from None
    try:
        return int(tail), head
    except ValueError:
        raise RuntimeError(f"no HTTP status in response from {url}") from None


def req(api: str, method: str, path: str, token: str | None = None,
        body: dict | None = None) -> tuple[int, dict]:
    """HTTP via curl: urllib is 403-blocked by Cloudflare on this host.

    Strict: transport failure, an empty body, invalid JSON, or a
    non-dict JSON payload all raise RuntimeError.
    """
    url = api + path
    args = ["-A", UA, "-H", "Accept: application/json",
            "-H", "Content-Type: application/json"]
    if token:
        args += ["-H", f"Authorization: Bearer {token}"]
    if body is not None:
        args += ["-X", method, "--data", json.dumps(body)]
    elif method != "GET":
        args += ["-X", method]
    status, payload_text = _curl_with_status(args, url)
    if not payload_text:
        raise RuntimeError(f"empty JSON body from {url} (HTTP {status})")
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"invalid JSON from {url} (HTTP {status}): {e}") from e
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"non-dict JSON payload from {url} (HTTP {status}): "
            f"{type(payload).__name__}")
    return status, payload


def _safe_error(data: dict) -> str:
    """Allowlisted error detail for logs: the server's `error` string."""
    err = data.get("error")
    if isinstance(err, str) and err:
        return f": {err}"[:300]
    return ""


def load_keypair(args) -> tuple[str, str]:
    """Return (address, private_key_hex). Never prints the private key."""
    if args.generate:
        acct = Account.create()
        log("generated fresh keypair (throwaway — save the key yourself)")
        log(f"address: {acct.address}")
        log("private key: <generated, NOT printed, NOT saved — "
            "re-run with AGENT_PRIVATE_KEY to reuse this identity>")
        return acct.address, acct.key.hex()
    pk = os.environ.get("AGENT_PRIVATE_KEY", "")
    if not pk:
        raise AgentError(
            "no keypair: pass --generate for a fresh throwaway keypair, "
            "or set AGENT_PRIVATE_KEY=0x...")
    acct = Account.from_key(pk)
    log(f"loaded keypair from AGENT_PRIVATE_KEY, address: {acct.address}")
    return acct.address, acct.key.hex()


def check_challenge(challenge: str, address: str) -> None:
    """Inspect the challenge before signing. Abort on anything tx-like."""
    bad = ["transfer", "approve", "spend", "mint", "payment",
           "send eth", "permit", "amount"]
    lowered = challenge.lower()
    if any(w in lowered for w in bad):
        raise AgentError("ABORT: challenge contains transaction-like wording")
    if address.lower() not in lowered:
        raise AgentError("ABORT: challenge does not contain our address")
    if "aiprove" not in lowered:
        raise AgentError("ABORT: challenge does not mention aiprove")
    log("challenge inspected: sign-in message only, our address present")


def authenticate(api: str, address: str, pk: str) -> str:
    log("step 1: GET /api/auth/challenge")
    status, data = req(api, "GET", f"/api/auth/challenge?address={address}")
    log(f"challenge status: {status}")
    if status != 200:
        raise AgentError(
            f"challenge failed: HTTP {status}{_safe_error(data)}")
    challenge = data.get("challenge")
    if not isinstance(challenge, str) or not challenge:
        raise AgentError(
            "challenge response has no nonempty challenge string")
    check_challenge(challenge, address)
    acct = Account.from_key(pk)
    if acct.address.lower() != address.lower():
        raise AgentError("keypair address mismatch")
    sig = acct.sign_message(encode_defunct(text=challenge))
    sig_hex = "0x" + sig.signature.hex()  # 0x prefix REQUIRED (else 401)
    log(f"signed challenge (signature length {len(sig_hex)} chars)")
    log("step 2: POST /api/auth/verify")
    status, data = req(api, "POST", "/api/auth/verify",
                       body={"address": address, "signature": sig_hex})
    log(f"verify status: {status}")
    if status != 200:
        raise AgentError(f"verify failed: HTTP {status}{_safe_error(data)}")
    token = data.get("token")
    if not isinstance(token, str) or not token:
        raise AgentError("verify response has no nonempty token string")
    log("authenticated (token held in memory only, never logged); "
        f"expiresAt: {data.get('expiresAt')}")
    return token


def deadline_key(b: dict) -> float:
    """Sort key for endsAt: missing/invalid values sort last."""
    try:
        return float(b.get("endsAt"))
    except (TypeError, ValueError):
        return math.inf


def list_open(api: str, token: str | None = None) -> list[dict]:
    log("step 3: GET /api/bounties?status=open (authenticated)")
    status, data = req(api, "GET", "/api/bounties?status=open", token=token)
    log(f"list status: {status}")
    if status != 200:
        raise AgentError(f"list failed: HTTP {status}{_safe_error(data)}")
    bounties = data.get("bounties")
    if not isinstance(bounties, list):
        raise AgentError("list response has no `bounties` list")
    if any(not isinstance(b, dict) for b in bounties):
        raise AgentError("list response contains a non-dict bounty entry")
    log(f"open bounties: {len(bounties)}")
    for b in sorted(bounties, key=deadline_key):
        log(f"  {b.get('endDate')} | {b.get('slug')} | {b.get('title')} | "
            f"{b.get('amt')} {b.get('unit')} | lane={b.get('lane')} | "
            f"subs={b.get('subs')}")
    return bounties


def enter_nearest(api: str, token: str, bounties: list[dict],
                  handle: str | None = None) -> dict:
    if not bounties:
        raise AgentError("no open bounties to enter")
    pick = min(bounties, key=deadline_key)
    slug = pick.get("slug")
    if not isinstance(slug, str) or not slug:
        raise AgentError("nearest bounty has no valid slug")
    log(f"step 4: nearest-deadline bounty is {slug} "
        f"({pick.get('title')}, ends {pick.get('endDate')})")
    body = {"handle": handle} if handle else {}
    status, data = req(api, "POST",
                       f"/api/bounties/{quote(slug, safe='')}/enter",
                       token=token, body=body)
    log(f"enter {slug} status: {status}")
    if status not in (200, 201):
        raise AgentError(f"enter failed: HTTP {status}{_safe_error(data)}")
    return data


def read_skill(api: str) -> None:
    """Step 0 per the bounty brief: read skill.md before doing anything."""
    log("step 0: GET /skill.md")
    status, text = _curl_with_status(["-A", UA], api + "/skill.md")
    if status != 200:
        raise AgentError(f"skill.md fetch failed: HTTP {status}")
    if "/api/auth/challenge" not in text or "/api/bounties" not in text:
        raise AgentError("skill.md did not contain the expected API flow")
    log(f"skill.md read ({len(text)} bytes, HTTP 200): auth -> list -> "
        "enter -> build -> submit")


def save_session(path: str, address: str, token: str) -> None:
    """Save the session token JSON, mode 0600, refusing existing paths.

    O_EXCL refuses to overwrite an existing file or follow a symlink.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise AgentError(
            f"session file already exists, refusing to overwrite: {path} "
            "(remove it first — it may be a symlink)") from None
    except OSError as e:
        raise AgentError(f"cannot create session file {path}: {e}") from e
    with os.fdopen(fd, "w") as f:
        json.dump({"address": address, "token": token}, f, indent=2)
    log(f"session saved to {path} (mode 0600, created with O_EXCL)")


def write_transcript(path: str) -> None:
    with open(path, "w") as f:
        f.write("\n".join(LOG) + "\n")


def run(args) -> None:
    """The loop. Raises AgentError/RuntimeError on any failed step."""
    log(f"AIProve sample agent — api={args.api} dry_run={args.dry_run}")
    read_skill(args.api)
    address, pk = load_keypair(args)
    token = authenticate(args.api, address, pk)
    if args.save_session:
        save_session(args.save_session, address, token)
    bounties = list_open(args.api, token)
    if not bounties:
        if args.dry_run:
            log("dry run: empty bounty list — nothing was entered, and "
                "this run is INCOMPLETE EVIDENCE for the full loop "
                "(auth + list only)")
        else:
            raise AgentError(
                "no open bounties — full run cannot enter anything")
    elif args.dry_run:
        log("dry run: enter step skipped — this run is INCOMPLETE "
            "EVIDENCE for the full loop (auth + list only, "
            "enter never exercised)")
    else:
        enter_nearest(args.api, token, bounties, args.handle)
    log("loop complete: skill.md read, authenticated, listed, "
        + ("entered one bounty" if bounties and not args.dry_run
           else "no enter (dry run / none open)"))


def main() -> int:
    p = argparse.ArgumentParser(description="AIProve sample agent")
    p.add_argument("--generate", action="store_true",
                   help="generate a fresh throwaway keypair for this run")
    p.add_argument("--dry-run", action="store_true",
                   help="auth + list only, do not enter any bounty")
    p.add_argument("--api", default=os.environ.get(
        "AIPROVE_API_BASE", DEFAULT_API), help="API base URL")
    p.add_argument("--handle", default=None,
                   help="optional agent handle sent on enter")
    p.add_argument("--save-session", default=None,
                   help="save session token JSON here (mode 0600)")
    p.add_argument("--transcript", default="transcript.txt",
                   help="write the run log here")
    args = p.parse_args()

    if Account is None:
        print("eth-account is not installed: "
              "pip install -r requirements.txt", file=sys.stderr)
        return 2
    exit_code = 0
    try:
        run(args)
    except (AgentError, RuntimeError) as e:
        log(f"ERROR: {e}")
        exit_code = 1
    except Exception as e:  # unexpected: never exit 0 on a broken loop
        log(f"ERROR (unexpected {type(e).__name__}): {e}")
        exit_code = 1
    finally:
        # Transcript is written even on failure, so a broken run is
        # still inspectable.
        try:
            write_transcript(args.transcript)
        except OSError as e:
            print(f"WARNING: could not write transcript "
                  f"{args.transcript}: {e}", file=sys.stderr)
        else:
            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            print(f"[{stamp}] transcript written to {args.transcript}",
                  flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
