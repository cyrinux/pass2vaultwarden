# pass2vaultwarden

Migrate your [pass](https://www.passwordstore.org/) password store to [Bitwarden](https://bitwarden.com/) / [Vaultwarden](https://github.com/dani-garcia/vaultwarden) — including attachments.

## Features

- Scans all `.gpg` entries in your password store via `pass show` (with `gpg --decrypt` fallback)
- Generates a Bitwarden-compatible CSV for bulk import
- Detects attachment candidates (PEM/cert blocks, binary or oversized entries) and exports them as files
- Optionally imports the CSV directly via the `bw` CLI and uploads attachments concurrently
- Infers URIs from entry paths when no explicit URL is present
- Handles TOTP (`otpauth://`) entries
- Security-conscious: writes sensitive files with `umask 077`, never prints `BW_SESSION` or secrets
- Retries with exponential backoff on transient Bitwarden API errors (rate limits, timeouts…)

## Requirements

- Python 3.8+
- [`pass`](https://www.passwordstore.org/) — for decryption
- `gpg` — fallback decryption
- [`bw` CLI](https://bitwarden.com/help/cli/) — only if using `--import-bw`

## Installation

```bash
git clone https://github.com/cyrinux/pass2vaultwarden.git
cd pass2vaultwarden
chmod +x pass2vaultwarden.py
```

## Usage

### Export to CSV only

```bash
./pass2vaultwarden.py --store ~/.password-store --out bitwarden.csv
```

### Export CSV + import into Bitwarden/Vaultwarden + upload attachments

```bash
./pass2vaultwarden.py \
  --store ~/.password-store \
  --attachments \
  --attachments-dir /dev/shm/bw_att \
  --import-bw \
  --concurrency 4 \
  --out attachments-report.csv
```

> **Note:** After migration, delete any temporary CSV files and attachment directories — they contain plaintext secrets.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--store` | `~/.password-store` | Path to your pass store |
| `--out` | `bitwarden.csv` | Output CSV path (or report path when `--import-bw` is used) |
| `--attachments` | off | Export attachment candidates to files |
| `--attachments-dir` | `/dev/shm/bw_att` | Directory to write attachment files |
| `--max-inline-size` | `1024` | Max bytes before an entry is treated as attachment |
| `--import-bw` | off | Import CSV via `bw` CLI and upload attachments |
| `--interactive` | off | Prompt on ambiguous item matches (requires TTY + `--concurrency 1`) |
| `--concurrency` | `4` | Number of parallel attachment uploads |
| `--max-attempts` | `5` | Max retry attempts per attachment upload |
| `--backoff-base` | `1.0` | Initial backoff delay in seconds (doubles each retry) |
| `--dry-run` | off | Scan and report without writing anything |
| `--add-url` | off | Write inferred URLs back into the pass store |
| `--allow-nonascii` | off | Process entries with non-ASCII paths |
| `--skip-errors` | off | Continue on errors instead of aborting |
| `--verbose` | off | Verbose output |

## How it works

1. **Scan** — walks the store for `*.gpg` files
2. **Decrypt** — runs `pass show <entry>` (falls back to `gpg --decrypt`)
3. **Parse** — extracts password, username, email, URL, TOTP and custom fields using key-value heuristics
4. **Classify** — entries with PEM blocks, empty content, or large binary data become attachment candidates
5. **Export** — writes a Bitwarden CSV (and optionally attachment files)
6. **Import** *(optional)* — calls `bw import bitwardencsv` then uploads each attachment via `bw create attachment`

## Security

- Sensitive output files are created with `0600` permissions (`umask 077`)
- `BW_SESSION` and secrets are never printed to stdout/stderr
- Attachment files are written to `/dev/shm` by default (RAM-backed, not persisted to disk)
- Delete temporary files after migration

## License

MIT

## Contributors

- [cyrinux](https://github.com/cyrinux)
