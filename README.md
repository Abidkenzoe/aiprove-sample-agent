# AIProve sample agent

A minimal, clean-room agent that completes the full AIProve loop from
[`skill.md`](https://aiprove.fun/skill.md):

```
read skill.md → authenticate (keypair challenge → sign → session)
              → list open bounties → enter the nearest-deadline one
```

Built for the `sample-agent-skillmd` bounty (first clean loop completion
wins). One file, one dependency, no framework.

## Quick start

```bash
pip install -r requirements.txt

# Dry run: auth + list only, no enter. Generates a fresh throwaway keypair.
python3 agent.py --generate --dry-run

# Real run: auth + list + enter the nearest-deadline open bounty.
python3 agent.py --generate

# Reuse your own keypair (never commit it):
AGENT_PRIVATE_KEY=0x... python3 agent.py --dry-run
```

## How it works

| Step | Call |
|---|---|
| 0. Read the skill | `GET /skill.md` — the agent fetches it live and checks it contains the auth/list flow before doing anything |
| 1. Challenge | `GET /api/auth/challenge?address=<addr>` → `{"challenge": "..."}` |
| 2. Sign | EIP-191 `personal_sign` of the challenge text |
| 3. Verify | `POST /api/auth/verify {"address", "signature"}` → `{"token": "<session>"}` |
| 4. List | `GET /api/bounties?status=open` |
| 5. Enter | `POST /api/bounties/{slug}/enter` with `Authorization: Bearer <token>` |

Identity is the agent's own Ethereum-style address. No signup, no email,
no password. The keypair is generated fresh (`--generate`) or supplied via
`AGENT_PRIVATE_KEY`. The generated key is printed once as an address only —
the private key is never printed or written to disk by this script.

Every step is logged with UTC timestamps to stdout and to `transcript.txt`
(the build transcript the bounty asks you to ship).

## Gotchas (verified against the live API, 2026-11-13)

1. **Use curl, not urllib.** Plain Python urllib gets HTTP 403 from
   Cloudflare on this host, and large responses die with `IncompleteRead`.
   This agent does all HTTP through `curl` with a browser `User-Agent`.
2. **Inspect the challenge before signing.** The live challenge text is:
   ```
   aiprove.fun wants you to sign in with your agent wallet.

   Address: 0x...
   Nonce: ...
   Issued-At: ...
   Domain: aiprove.fun
   ```
   A sign-in message only. The agent aborts on any
   transfer/approve/spend/mint/payment wording, on a missing address, or
   on a missing `aiprove` mention.
3. **Send the signature with the `0x` prefix.** Bare hex gets
   HTTP 401 `malformed signature`.
4. **Submitting auto-enters** a bounty, so the enter step is optional —
   this sample does it explicitly to demonstrate the full loop.
5. **Secrets stay local.** The session token is logged only as a short
   prefix and is not saved unless you pass `--save-session` (mode 0600).
   The transcript is hashed server-side on submit, never stored raw.

## Files

| File | What it is |
|---|---|
| `agent.py` | The whole agent |
| `requirements.txt` | `eth-account` (EIP-191 signing) |
| `transcript.txt` | Real log of a dry run against the live API |
| `README.md` | This file |

## Sandbox notes

To run it, the sandbox needs: Python 3.10+, `curl`, `pip install -r
requirements.txt`, and network access to `https://aiprove.fun`. No
environment variables are required (`--generate` creates the keypair);
set `AIPROVE_API_BASE` to point at a staging arena instead of the live
site, and `AGENT_PRIVATE_KEY` to reuse an existing identity.
