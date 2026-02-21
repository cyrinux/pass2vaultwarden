#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pass2bw_full.py — Migration password-store -> CSV Bitwarden + import bw + upload pièces jointes.

Fonctionnement:
- Parcourt un dépôt pass (fichiers *.gpg).
- Lit via `pass show` (PASSWORD_STORE_DIR) avec fallback `gpg --decrypt`.
- Génère un CSV conforme à l'en-tête Bitwarden (csv) pour vault individuel.
- Détecte des entrées "pièce jointe" (BEGIN/END, vide, ou trop grosses) et peut exporter leur contenu en fichiers.
- Optionnel: importe via Bitwarden CLI (`bw import`) puis uploade les pièces jointes (`bw create attachment`)
  avec concurrence, retries et backoff.

Sécurité:
- N'imprime jamais BW_SESSION ni les secrets.
- Écrit les fichiers sensibles avec umask 077 (permissions restrictives).
"""

import argparse
import csv
import hashlib
import json
import os
import random
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    import pty
    import select
    import termios
    import tty
except Exception:
    pty = None  # type: ignore

BITWARDEN_HEADER = [
    "folder",
    "favorite",
    "type",
    "name",
    "notes",
    "fields",
    "reprompt",
    "login_uri",
    "login_username",
    "login_password",
    "login_totp",
]

USERNAME_KEYS = {"login", "user", "username", "name"}
EMAIL_KEYS = {"email", "mail"}
URL_KEYS = {"url", "uri", "website", "site", "web"}
OTP_KEYS = {"otp", "totp", "2fa", "mfa"}

DENYLIST_EXT = {
    ".asc",
    ".bak",
    ".cfg",
    ".conf",
    ".config",
    ".crt",
    ".csv",
    ".db",
    ".der",
    ".env",
    ".gz",
    ".ini",
    ".json",
    ".key",
    ".kubeconfig",
    ".lock",
    ".log",
    ".md",
    ".p12",
    ".pem",
    ".pfx",
    ".pub",
    ".rst",
    ".sig",
    ".sql",
    ".sqlite",
    ".tar",
    ".toml",
    ".tsv",
    ".txt",
    ".xml",
    ".xz",
    ".yaml",
    ".yml",
    ".zip",
}

KV_RE = re.compile(r"^\s*([^:]{1,200}?)\s*:\s*(.*)\s*$")
URL_LINE_RE = re.compile(r"^\s*(https?://\S+)\s*$", re.IGNORECASE)
OTPAUTH_RE = re.compile(r"(otpauth://\S+)", re.IGNORECASE)

BEGIN_RE = re.compile(r"^-----BEGIN ", re.IGNORECASE)
END_RE = re.compile(r"^-----END ", re.IGNORECASE)

DOMAIN_RE = re.compile(
    r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$"
)
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def is_ascii(s: str) -> bool:
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def chmod_safely(path: str, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def ensure_dir(path: str, mode: int = 0o700) -> None:
    os.makedirs(path, exist_ok=True)
    chmod_safely(path, mode)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def short_hash(s: str, n: int = 8) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:n]


def sanitize_filename_base(s: str) -> str:
    out = s.strip().lstrip(".")
    out = out.replace(os.sep, "_")
    out = out.replace("/", "_")
    out = re.sub(r"\s+", "_", out)
    out = re.sub(r"[^A-Za-z0-9._-]+", "_", out)
    if not out:
        out = "attachment"
    return out[:180]


def strip_gpg_ext(relpath: str) -> str:
    return relpath[:-4] if relpath.endswith(".gpg") else relpath


def to_pass_entry(rel_no_ext: str) -> str:
    return rel_no_ext.replace(os.sep, "/")


def run_cmd(
    argv: List[str],
    env: Optional[Dict[str, str]] = None,
    input_bytes: Optional[bytes] = None,
    capture: bool = True,
    check: bool = False,
    text: bool = False,
) -> Tuple[int, bytes, bytes]:
    p = subprocess.run(
        argv,
        input=input_bytes,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=env,
        check=False,
    )
    rc = p.returncode
    out = p.stdout if capture and p.stdout is not None else b""
    err = p.stderr if capture and p.stderr is not None else b""
    if check and rc != 0:
        raise subprocess.CalledProcessError(rc, argv, output=out, stderr=err)
    return rc, out, err


def first_nonempty_line(lines: List[str]) -> Tuple[Optional[int], Optional[str]]:
    for i, line in enumerate(lines):
        if line.strip() != "":
            return i, line
    return None, None


def nonempty_lines(lines: List[str]) -> List[str]:
    return [ln for ln in lines if ln.strip() != ""]


def is_begin_end_block(text: str) -> bool:
    lines = text.splitlines()
    ne = nonempty_lines(lines)
    if not ne:
        return False
    return bool(BEGIN_RE.match(ne[0])) and bool(END_RE.match(ne[-1]))


def host_is_ip(host: str) -> bool:
    if not IP_RE.match(host):
        return False
    try:
        parts = [int(x) for x in host.split(".")]
    except ValueError:
        return False
    return all(0 <= p <= 255 for p in parts)


def ip_is_private(ip: str) -> bool:
    if not host_is_ip(ip):
        return False
    a, b, c, d = [int(x) for x in ip.split(".")]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    return False


def infer_uri_from_entry(entry: str) -> str:
    parts = [p for p in entry.split("/") if p]
    if not parts:
        return ""

    scheme_hint = None
    lowered = [p.lower() for p in parts]
    if "https" in lowered:
        scheme_hint = "https"
    elif "http" in lowered:
        scheme_hint = "http"

    leaf = parts[-1].strip()
    if not leaf:
        return ""

    ext = os.path.splitext(leaf)[1].lower()
    if ext in DENYLIST_EXT:
        return ""

    host = leaf.lstrip(".")
    if host_is_ip(host):
        scheme = "http" if (scheme_hint == "http" or ip_is_private(host)) else "https"
        return f"{scheme}://{host}"
    if host.lower() in {"localhost"}:
        scheme = "http" if scheme_hint == "http" else "http"
        return f"{scheme}://{host}"
    if DOMAIN_RE.match(host):
        scheme = "http" if scheme_hint == "http" else "https"
        return f"{scheme}://{host}"

    return ""


def decode_text(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("utf-8", "replace")


def pass_show(entry: str, store: str) -> Tuple[Optional[bytes], Optional[str]]:
    env = os.environ.copy()
    env["PASSWORD_STORE_DIR"] = store
    rc, out, err = run_cmd(["pass", "show", entry], env=env, capture=True)
    if rc == 0:
        return out, None
    msg = (err.decode("utf-8", "replace") or f"pass show a échoué (code {rc})").strip()
    return None, msg


def gpg_decrypt(filepath: str, store: str) -> Tuple[Optional[bytes], Optional[str]]:
    env = os.environ.copy()
    env["PASSWORD_STORE_DIR"] = store
    rc, out, err = run_cmd(
        ["gpg", "--quiet", "--batch", "--decrypt", filepath], env=env, capture=True
    )
    if rc == 0:
        return out, None
    msg = (
        err.decode("utf-8", "replace") or f"gpg --decrypt a échoué (code {rc})"
    ).strip()
    return None, msg


def pass_insert_multiline(
    entry: str, store: str, content_utf8: str
) -> Tuple[bool, str]:
    env = os.environ.copy()
    env["PASSWORD_STORE_DIR"] = store
    rc, out, err = run_cmd(
        ["pass", "insert", "-m", "-f", entry],
        env=env,
        input_bytes=content_utf8.encode("utf-8"),
        capture=True,
    )
    if rc == 0:
        return True, ""
    msg = (
        err.decode("utf-8", "replace")
        or out.decode("utf-8", "replace")
        or f"pass insert a échoué (code {rc})"
    ).strip()
    return False, msg


def fields_to_cell(pairs: List[Tuple[str, str]]) -> str:
    out: List[str] = []
    for k, v in pairs:
        kk = (k or "").strip()
        vv = (v or "").strip()
        if not kk or not vv:
            continue
        if "\n" in vv:
            continue
        out.append(f"{kk}: {vv}")
    return "\n".join(out)


@dataclass
class CsvRow:
    folder: str
    favorite: str
    type: str
    name: str
    notes: str
    fields: str
    reprompt: str
    login_uri: str
    login_username: str
    login_password: str
    login_totp: str

    def as_list(self) -> List[str]:
        return [
            self.folder,
            self.favorite,
            self.type,
            self.name,
            self.notes,
            self.fields,
            self.reprompt,
            self.login_uri,
            self.login_username,
            self.login_password,
            self.login_totp,
        ]


@dataclass
class AttachmentTask:
    file_path: str
    file_name: str
    item_name: str
    pass_entry: str


@dataclass
class UploadResult:
    file_name: str
    file_path: str
    item_name: str
    pass_entry: str
    item_id: str
    attachment_id: str
    status: str
    message: str
    attempts: int
    timestamp: str


def parse_entry_to_rows(
    entry: str,
    rel_no_ext: str,
    raw: bytes,
    text: str,
    max_inline_size: int,
    attachments_enabled: bool,
    attachments_dir: str,
) -> Tuple[List[CsvRow], List[AttachmentTask], Optional[str]]:
    folder = os.path.dirname(entry)
    name = os.path.basename(entry)

    tasks: List[AttachmentTask] = []
    rows: List[CsvRow] = []

    lines = text.splitlines()
    first_i, first_line = first_nonempty_line(lines)
    has_password_line = first_line is not None

    attachment_candidate = False
    reasons: List[str] = []
    if is_begin_end_block(text):
        attachment_candidate = True
        reasons.append("BEGIN/END")
    if not has_password_line:
        attachment_candidate = True
        reasons.append("no_nonempty_line")
    if len(raw) > max_inline_size:
        attachment_candidate = True
        reasons.append(f"size>{max_inline_size}")

    pass_entry_field = ("pass_entry", entry)

    if attachment_candidate:
        fields: List[Tuple[str, str]] = [pass_entry_field]
        notes = (
            "⚠️ Entrée traitée comme pièce jointe/candidat pièce jointe.\n"
            f"- pass_entry: {entry}\n"
            f"- raisons: {', '.join(reasons)}\n"
        )

        if attachments_enabled:
            ensure_dir(attachments_dir, 0o700)
            base = sanitize_filename_base(name)
            fname = f"{base}__{short_hash(entry, 8)}.txt"
            fpath = os.path.join(attachments_dir, fname)

            with open(fpath, "wb") as fp:
                fp.write(raw)
            chmod_safely(fpath, 0o600)

            fields.extend(
                [
                    ("attachment_file", fname),
                    ("attachment_sha256", sha256_hex(raw)),
                    ("attachment_size_bytes", str(len(raw))),
                ]
            )
            notes += "- contenu exporté en fichier (upload via bw possible)\n"
            tasks.append(
                AttachmentTask(
                    file_path=fpath,
                    file_name=fname,
                    item_name=name,
                    pass_entry=entry,
                )
            )
        else:
            if len(raw) <= max_inline_size:
                notes += (
                    "\n---\nContenu (inline, car petit et --attachments désactivé):\n"
                )
                notes += text
            else:
                notes += "- contenu NON exporté (activer --attachments)\n"

        row = CsvRow(
            folder=folder,
            favorite="",
            type="note",
            name=name,
            notes=notes.strip("\n"),
            fields=fields_to_cell(fields),
            reprompt="0",
            login_uri="",
            login_username="",
            login_password="",
            login_totp="",
        )
        rows.append(row)
        return rows, tasks, None

    # Cas "login"
    # Mot de passe = première ligne non vide
    pw = first_line.strip("\n") if first_line is not None else ""

    rest_lines = lines[first_i + 1 :] if first_i is not None else []

    username: str = ""
    email: str = ""
    uri: str = ""
    totp: str = ""

    other_fields: List[Tuple[str, str]] = [pass_entry_field]
    notes_lines: List[str] = []

    uri_candidates: List[str] = []

    i = 0
    while i < len(rest_lines):
        raw_line = rest_lines[i]
        i += 1

        m = OTPAUTH_RE.search(raw_line)
        if m and not totp:
            totp = m.group(1).strip()
            continue

        murl = URL_LINE_RE.match(raw_line)
        if murl:
            uri_candidates.append(murl.group(1).strip())
            continue

        mkv = KV_RE.match(raw_line)
        if not mkv:
            notes_lines.append(raw_line)
            continue

        k_raw = mkv.group(1).strip()
        v_raw = mkv.group(2)

        k = k_raw.lower()
        v = v_raw.rstrip("\n")

        multiline = False
        if (
            v.strip() == ""
            and i < len(rest_lines)
            and (rest_lines[i].startswith(" ") or rest_lines[i].startswith("\t"))
        ):
            multiline = True
            cont: List[str] = []
            while i < len(rest_lines) and (
                rest_lines[i].startswith(" ") or rest_lines[i].startswith("\t")
            ):
                cont.append(rest_lines[i].lstrip(" \t"))
                i += 1
            v = "\n".join(cont)

        v_stripped = v.strip()

        if k in USERNAME_KEYS:
            if multiline:
                notes_lines.append(f"[{k_raw}]")
                notes_lines.append(v)
            elif not username and v_stripped:
                username = v_stripped
            else:
                if v_stripped:
                    other_fields.append((k_raw, v_stripped))
            continue

        if k in EMAIL_KEYS:
            if multiline:
                notes_lines.append(f"[{k_raw}]")
                notes_lines.append(v)
            elif not email and v_stripped:
                email = v_stripped
            else:
                if v_stripped:
                    other_fields.append((k_raw, v_stripped))
            continue

        if k in URL_KEYS:
            if multiline:
                notes_lines.append(f"[{k_raw}]")
                notes_lines.append(v)
            else:
                if v_stripped:
                    uri_candidates.append(v_stripped)
            continue

        if k in OTP_KEYS:
            if multiline:
                notes_lines.append(f"[{k_raw}]")
                notes_lines.append(v)
            elif not totp and v_stripped:
                totp = v_stripped
            else:
                if v_stripped:
                    other_fields.append((k_raw, v_stripped))
            continue

        if multiline:
            notes_lines.append(f"[{k_raw}]")
            notes_lines.append(v)
        else:
            if v_stripped:
                other_fields.append((k_raw, v_stripped))

    if not username and email:
        username = email
    if email and username and email != username:
        other_fields.append(("email", email))

    # URI: prend la première; extras vont en champs custom
    if uri_candidates:
        uri = uri_candidates[0].strip()
        for n, u in enumerate(uri_candidates[1:], start=2):
            other_fields.append((f"uri_alt_{n}", u.strip()))
    else:
        inferred = infer_uri_from_entry(entry)
        if inferred:
            uri = inferred

    notes = "\n".join(notes_lines).strip("\n")

    row = CsvRow(
        folder=folder,
        favorite="",
        type="login",
        name=name,
        notes=notes,
        fields=fields_to_cell(other_fields),
        reprompt="0",
        login_uri=uri,
        login_username=username,
        login_password=pw,
        login_totp=totp,
    )
    rows.append(row)
    return rows, tasks, uri if uri else None


def write_csv(path: str, rows: List[CsvRow]) -> None:
    out_dir = os.path.dirname(os.path.abspath(path)) or "."
    ensure_dir(out_dir, 0o700)
    with open(path, "w", encoding="utf-8", newline="") as fp:
        w = csv.writer(fp, lineterminator="\n")
        w.writerow(BITWARDEN_HEADER)
        for r in rows:
            w.writerow(r.as_list())
    chmod_safely(path, 0o600)


def now_iso() -> str:
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())
    except Exception:
        return str(int(time.time()))


def bw_status(env: Dict[str, str]) -> Tuple[bool, Optional[dict], str]:
    rc, out, err = run_cmd(["bw", "status"], env=env, capture=True)
    if rc != 0:
        return (
            False,
            None,
            (err.decode("utf-8", "replace") or out.decode("utf-8", "replace")).strip(),
        )
    txt = out.decode("utf-8", "replace").strip()
    try:
        return True, json.loads(txt), ""
    except Exception:
        return False, None, f"bw status non-JSON: {txt[:200]}"


def bw_sync(env: Dict[str, str]) -> bool:
    rc, out, err = run_cmd(["bw", "sync", "--nointeraction"], env=env, capture=True)
    return rc == 0


_SESSION_LINE_RE = re.compile(r"^[A-Za-z0-9+/=_-]{20,}$")


def bw_unlock_raw_with_pty(env: Dict[str, str], verbose: bool) -> Tuple[bool, str]:
    if pty is None:
        return (
            False,
            "pty indisponible, impossible de capturer bw unlock --raw sans fuite",
        )

    master_fd, slave_fd = pty.openpty()
    cmd = ["bw", "unlock", "--raw"]
    proc = subprocess.Popen(
        cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, env=env, close_fds=True
    )
    os.close(slave_fd)

    old = termios.tcgetattr(sys.stdin.fileno())
    session_key = ""
    buf = b""

    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            rlist, _, _ = select.select([master_fd, sys.stdin.fileno()], [], [], 0.05)

            if sys.stdin.fileno() in rlist:
                try:
                    data_in = os.read(sys.stdin.fileno(), 1024)
                except OSError:
                    data_in = b""
                if data_in:
                    os.write(master_fd, data_in)

            if master_fd in rlist:
                try:
                    data = os.read(master_fd, 1024)
                except OSError:
                    data = b""
                if data:
                    buf += data
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        s = line.decode("utf-8", "replace").strip()
                        if _SESSION_LINE_RE.match(s):
                            session_key = s
                        else:
                            sys.stdout.write(line.decode("utf-8", "replace") + "\n")
                            sys.stdout.flush()

            if proc.poll() is not None:
                break

        if buf:
            s = buf.decode("utf-8", "replace").strip()
            if _SESSION_LINE_RE.match(s):
                session_key = s
            else:
                if s:
                    sys.stdout.write(s)
                    sys.stdout.flush()

    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
        os.close(master_fd)

    rc = proc.wait()
    if rc != 0:
        return False, f"bw unlock --raw a échoué (code {rc})"
    if not session_key:
        return False, "session key introuvable (bw unlock --raw n'a rien retourné)"
    return True, session_key


def ensure_bw_session(verbose: bool) -> Tuple[bool, Dict[str, str], str]:
    env = os.environ.copy()

    ok, st, msg = bw_status(env)
    status = (st or {}).get("status") if ok and st else None

    if verbose:
        eprint(f"[bw] status initial: {status or 'unknown'}")

    if env.get("BW_SESSION"):
        if ok and status == "unlocked":
            return True, env, ""
        if bw_sync(env):
            ok2, st2, _ = bw_status(env)
            if ok2 and st2 and st2.get("status") == "unlocked":
                return True, env, ""
        if verbose:
            eprint(
                "[bw] BW_SESSION présent mais statut non-unlocked; tentative unlock."
            )

    if ok and status == "unauthenticated":
        eprint("[bw] login requis (bw login interactif).")
        rc = subprocess.run(["bw", "login"], env=env).returncode
        if rc != 0:
            return False, env, "bw login a échoué"
        ok, st, _ = bw_status(env)
        status = (st or {}).get("status") if ok and st else None

    if ok and status != "unlocked":
        if not sys.stdin.isatty():
            return (
                False,
                env,
                "vault locked + pas de TTY pour unlock; exportez BW_SESSION puis relancez",
            )
        eprint("[bw] unlock requis (bw unlock --raw interactif).")
        ok_u, sess_or_err = bw_unlock_raw_with_pty(env, verbose)
        if not ok_u:
            return False, env, sess_or_err
        env["BW_SESSION"] = sess_or_err

    if not bw_sync(env):
        if verbose:
            eprint("[bw] bw sync a échoué (continuer quand même).")

    ok3, st3, msg3 = bw_status(env)
    if not ok3 or not st3:
        return False, env, f"bw status final invalide: {msg3}"
    if st3.get("status") != "unlocked":
        return False, env, f"vault non unlocked: {st3.get('status')}"
    return True, env, ""


def bw_import_formats(env: Dict[str, str]) -> List[str]:
    rc, out, err = run_cmd(
        ["bw", "import", "--formats", "--nointeraction"], env=env, capture=True
    )
    if rc != 0:
        return []
    txt = out.decode("utf-8", "replace")
    formats: List[str] = []
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        for p in parts:
            if re.fullmatch(r"[a-z0-9_-]+", p):
                formats.append(p)
    seen = set()
    uniq = []
    for f in formats:
        if f not in seen:
            seen.add(f)
            uniq.append(f)
    return uniq


def pick_bitwarden_csv_format(formats: List[str]) -> str:
    if "bitwardencsv" in formats:
        return "bitwardencsv"
    for f in formats:
        if "bitwarden" in f and "csv" in f:
            return f
    return "bitwardencsv"


def bw_import_csv(
    env: Dict[str, str], csv_path: str, verbose: bool
) -> Tuple[bool, str]:
    formats = bw_import_formats(env)
    fmt = pick_bitwarden_csv_format(formats)
    if verbose:
        eprint(f"[bw] import format: {fmt}")
    rc, out, err = run_cmd(
        ["bw", "import", fmt, csv_path, "--nointeraction"], env=env, capture=True
    )
    if rc == 0:
        return True, ""
    msg = (err.decode("utf-8", "replace") or out.decode("utf-8", "replace")).strip()
    return False, msg[:500]


def bw_list_items_search(
    env: Dict[str, str], term: str
) -> Tuple[bool, List[dict], str]:
    rc, out, err = run_cmd(
        ["bw", "list", "items", "--search", term, "--nointeraction"],
        env=env,
        capture=True,
    )
    if rc != 0:
        msg = (err.decode("utf-8", "replace") or out.decode("utf-8", "replace")).strip()
        return False, [], msg[:500]
    try:
        data = json.loads(out.decode("utf-8", "replace"))
        if isinstance(data, list):
            return True, data, ""
        return False, [], "bw list items n'a pas retourné une liste JSON"
    except Exception as ex:
        return False, [], f"JSON invalide: {ex}"


def extract_pass_entry_field(item: dict) -> str:
    fields = item.get("fields") or []
    if not isinstance(fields, list):
        return ""
    for f in fields:
        if isinstance(f, dict) and f.get("name") == "pass_entry":
            v = f.get("value")
            return v if isinstance(v, str) else ""
    return ""


def resolve_item_id_for_attachment(
    env: Dict[str, str],
    task: AttachmentTask,
    interactive: bool,
    concurrency: int,
    verbose: bool,
) -> Tuple[str, str]:
    candidates: List[str] = []

    # priorité: nom attendu (basename pass)
    if task.item_name:
        candidates.append(task.item_name)

    # dérivation depuis le fichier: base__hash.ext
    fname = task.file_name
    base = os.path.splitext(fname)[0]
    m = re.match(r"^(.*)__([0-9a-fA-F]{6,64})$", base)
    if m:
        base = m.group(1)

    variants: List[str] = []
    variants.append(base)
    variants.append(base.replace("_", " "))
    if "__" in base:
        variants.append(base.split("__")[-1])
        variants.append(base.split("__")[-1].replace("_", " "))

    for v in variants:
        v = v.strip()
        if v and v not in candidates:
            candidates.append(v)

    for cand in candidates:
        ok, items, msg = bw_list_items_search(env, cand)
        if not ok:
            if verbose:
                eprint(f"[bw] list items échoue sur '{cand}': {msg}")
            continue

        exact = [it for it in items if isinstance(it, dict) and it.get("name") == cand]
        if len(exact) == 1:
            return exact[0].get("id", ""), ""

        if len(exact) > 1:
            # tentative de disambiguïsation via pass_entry
            pe = task.pass_entry
            if pe:
                pe_matches = [it for it in exact if extract_pass_entry_field(it) == pe]
                if len(pe_matches) == 1:
                    return pe_matches[0].get("id", ""), ""

            if interactive and sys.stdin.isatty() and concurrency == 1:
                eprint(
                    f"[bw] Ambiguïté: {len(exact)} items nommés exactement '{cand}'."
                )
                for idx, it in enumerate(exact, start=1):
                    it_id = it.get("id", "")
                    it_type = it.get("type", "")
                    it_pe = extract_pass_entry_field(it)
                    eprint(f"  [{idx}] id={it_id} type={it_type} pass_entry={it_pe}")
                eprint("  [0] ignorer")
                try:
                    choice = input("Choix: ").strip()
                except EOFError:
                    choice = "0"
                if choice.isdigit():
                    n = int(choice)
                    if 1 <= n <= len(exact):
                        return exact[n - 1].get("id", ""), ""
                return "", f"ambiguous: {cand}"

            return "", f"ambiguous: {cand}"

    return "", "not_found"


def is_transient_bw_error(msg: str) -> bool:
    m = msg.lower()
    return any(
        x in m
        for x in [
            "too many requests",
            "rate",
            "timeout",
            "timed out",
            "temporar",
            "try again",
            "bad gateway",
            "gateway",
            "service unavailable",
            "connection reset",
            "econnreset",
            "etimedout",
            "429",
            "502",
            "503",
        ]
    )


def bw_create_attachment(
    env: Dict[str, str], file_path: str, item_id: str
) -> Tuple[bool, str, str]:
    rc, out, err = run_cmd(
        [
            "bw",
            "create",
            "attachment",
            "--file",
            file_path,
            "--itemid",
            item_id,
            "--nointeraction",
        ],
        env=env,
        capture=True,
    )
    if rc != 0:
        msg = (err.decode("utf-8", "replace") or out.decode("utf-8", "replace")).strip()
        return False, "", msg[:800]
    txt = out.decode("utf-8", "replace").strip()
    if not txt:
        return True, "", ""
    try:
        obj = json.loads(txt)
        if isinstance(obj, dict):
            att_id = obj.get("id") or obj.get("attachmentId")
            if isinstance(att_id, str):
                return True, att_id, ""
        return True, "", ""
    except Exception:
        return True, "", ""


def upload_one_with_retry(
    env: Dict[str, str],
    task: AttachmentTask,
    interactive: bool,
    concurrency: int,
    verbose: bool,
    max_attempts: int,
    backoff_base: float,
) -> UploadResult:
    ts = now_iso()

    item_id, why = resolve_item_id_for_attachment(
        env, task, interactive, concurrency, verbose
    )
    if not item_id:
        return UploadResult(
            file_name=task.file_name,
            file_path=task.file_path,
            item_name=task.item_name,
            pass_entry=task.pass_entry,
            item_id="",
            attachment_id="",
            status="not_found" if why == "not_found" else "ambiguous",
            message=why,
            attempts=0,
            timestamp=ts,
        )

    if not os.path.isfile(task.file_path):
        return UploadResult(
            file_name=task.file_name,
            file_path=task.file_path,
            item_name=task.item_name,
            pass_entry=task.pass_entry,
            item_id=item_id,
            attachment_id="",
            status="missing_file",
            message="fichier introuvable",
            attempts=0,
            timestamp=ts,
        )

    attempt = 1
    delay = backoff_base
    last_err = ""

    while attempt <= max_attempts:
        ok, att_id, err_msg = bw_create_attachment(env, task.file_path, item_id)
        if ok:
            return UploadResult(
                file_name=task.file_name,
                file_path=task.file_path,
                item_name=task.item_name,
                pass_entry=task.pass_entry,
                item_id=item_id,
                attachment_id=att_id,
                status="uploaded",
                message="OK",
                attempts=attempt,
                timestamp=ts,
            )

        last_err = err_msg
        if not is_transient_bw_error(err_msg) or attempt == max_attempts:
            return UploadResult(
                file_name=task.file_name,
                file_path=task.file_path,
                item_name=task.item_name,
                pass_entry=task.pass_entry,
                item_id=item_id,
                attachment_id="",
                status="upload_failed",
                message=err_msg[:500],
                attempts=attempt,
                timestamp=ts,
            )

        jitter = random.uniform(0.0, 0.5)
        time.sleep(delay + jitter)
        delay *= 2.0
        attempt += 1

    return UploadResult(
        file_name=task.file_name,
        file_path=task.file_path,
        item_name=task.item_name,
        pass_entry=task.pass_entry,
        item_id=item_id,
        attachment_id="",
        status="upload_failed",
        message=(last_err or "unknown")[:500],
        attempts=max_attempts,
        timestamp=ts,
    )


def write_report(path: str, results: List[UploadResult]) -> None:
    out_dir = os.path.dirname(os.path.abspath(path)) or "."
    ensure_dir(out_dir, 0o700)

    if path.endswith(".json"):
        data = []
        for r in results:
            data.append(
                {
                    "timestamp": r.timestamp,
                    "filename": r.file_name,
                    "path": r.file_path,
                    "item_name": r.item_name,
                    "pass_entry": r.pass_entry,
                    "item_id": r.item_id,
                    "attachment_id": r.attachment_id,
                    "status": r.status,
                    "attempts": r.attempts,
                    "message": r.message,
                }
            )
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, ensure_ascii=False, indent=2)
        chmod_safely(path, 0o600)
        return

    with open(path, "w", encoding="utf-8", newline="") as fp:
        w = csv.writer(fp, lineterminator="\n")
        w.writerow(
            [
                "timestamp",
                "filename",
                "path",
                "item_name",
                "pass_entry",
                "item_id",
                "attachment_id",
                "status",
                "attempts",
                "message",
            ]
        )
        for r in results:
            w.writerow(
                [
                    r.timestamp,
                    r.file_name,
                    r.file_path,
                    r.item_name,
                    r.pass_entry,
                    r.item_id,
                    r.attachment_id,
                    r.status,
                    str(r.attempts),
                    r.message,
                ]
            )
    chmod_safely(path, 0o600)


def main() -> int:
    os.umask(0o077)

    ap = argparse.ArgumentParser(
        description="Convertit un password-store en CSV Bitwarden + import bw + upload pièces jointes."
    )
    ap.add_argument("--store", default=os.path.expanduser("~/.password-store"))
    ap.add_argument(
        "--out",
        default="bitwarden.csv",
        help="Sans --import-bw: chemin du CSV Bitwarden. Avec --import-bw: chemin du rapport final (CSV/JSON).",
    )
    ap.add_argument(
        "--attachments",
        action="store_true",
        help="Exporte les pièces jointes candidates en fichiers dans --attachments-dir.",
    )
    ap.add_argument("--attachments-dir", default="/dev/shm/bw_att")
    ap.add_argument("--max-inline-size", type=int, default=1024)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument(
        "--add-url",
        action="store_true",
        help="Ajoute url: <...> aux entrées pass quand l'URL est inférée (désactivé par défaut).",
    )
    ap.add_argument("--skip-errors", action="store_true")
    ap.add_argument(
        "--import-bw",
        action="store_true",
        help="Importe le CSV via bw puis uploade les pièces jointes exportées.",
    )
    ap.add_argument(
        "--interactive",
        action="store_true",
        help="Autorise les prompts en cas d'ambiguïté (nécessite TTY et concurrency=1).",
    )
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--allow-nonascii", action="store_true")
    ap.add_argument("--max-attempts", type=int, default=5)
    ap.add_argument("--backoff-base", type=float, default=1.0)
    args = ap.parse_args()

    store = os.path.abspath(os.path.expanduser(args.store))
    if not os.path.isdir(store):
        eprint(f"[x] store introuvable: {store}")
        return 2

    if args.verbose:
        eprint(f"[i] store={store}")

    # Scan *.gpg
    gpg_files: List[str] = []
    for root, dirs, files in os.walk(store):
        # évite de traverser .git (souvent présent)
        dirs[:] = [d for d in dirs if d != ".git"]
        for fn in files:
            if fn.endswith(".gpg"):
                gpg_files.append(os.path.join(root, fn))

    gpg_files.sort()

    rows: List[CsvRow] = []
    attachment_tasks: List[AttachmentTask] = []
    nonascii_skipped: List[str] = []
    errors: List[str] = []
    urls_appended: int = 0

    for fpath in gpg_files:
        rel = os.path.relpath(fpath, store)
        rel_no_ext = strip_gpg_ext(rel)
        entry = to_pass_entry(rel_no_ext)

        if (not args.allow_nonascii) and (not is_ascii(entry)):
            nonascii_skipped.append(entry)
            continue

        raw, err = pass_show(entry, store)
        source = "pass"
        used_fallback = False
        if raw is None:
            raw, err2 = gpg_decrypt(fpath, store)
            source = "gpg"
            used_fallback = True
            err = err2 or err

        if raw is None:
            msg = f"{entry}: decrypt_failed: {err}"
            errors.append(msg)
            if args.verbose:
                eprint("[x] " + msg)
            if args.skip_errors:
                continue
            eprint("[x] " + msg)
            return 1

        text = decode_text(raw)

        entry_rows, tasks, inferred_uri = parse_entry_to_rows(
            entry=entry,
            rel_no_ext=rel_no_ext,
            raw=raw,
            text=text,
            max_inline_size=args.max_inline_size,
            attachments_enabled=args.attachments and (not args.dry_run),
            attachments_dir=os.path.abspath(os.path.expanduser(args.attachments_dir)),
        )
        rows.extend(entry_rows)
        attachment_tasks.extend(tasks)

        if args.add_url and (not args.dry_run) and source == "pass" and inferred_uri:
            if not re.search(r"(?im)^\s*(url|uri|website|site|web)\s*:\s*\S+", text):
                new_text = text.rstrip("\n") + "\n" + f"url: {inferred_uri}\n"
                ok, werr = pass_insert_multiline(entry, store, new_text)
                if ok:
                    urls_appended += 1
                else:
                    msg = f"{entry}: add-url failed: {werr}"
                    errors.append(msg)
                    if args.verbose:
                        eprint("[x] " + msg)
                    if not args.skip_errors:
                        eprint("[x] " + msg)
                        return 1

        if args.verbose:
            eprint(
                f"[ok] {entry} ({source}) rows={len(entry_rows)} attachments={len(tasks)}"
            )

    if args.dry_run:
        eprint(
            f"[dry-run] .gpg={len(gpg_files)} rows_csv={len(rows)} attachments={len(attachment_tasks)}"
        )
        if nonascii_skipped:
            eprint(
                f"[dry-run] non-ascii ignorés: {len(nonascii_skipped)} (utiliser --allow-nonascii)"
            )
        if errors:
            eprint(f"[dry-run] erreurs: {len(errors)}")
        return 0

    # Export CSV
    csv_path = ""
    report_path = ""

    if args.import_bw:
        # mode "pipeline complet": --out = rapport; CSV import = fichier temporaire
        report_path = os.path.abspath(os.path.expanduser(args.out))
        tmp_dir = tempfile.mkdtemp(
            prefix="pass2bw_", dir="/dev/shm" if os.path.isdir("/dev/shm") else None
        )
        chmod_safely(tmp_dir, 0o700)
        csv_path = os.path.join(tmp_dir, "bitwarden-import.csv")
    else:
        csv_path = os.path.abspath(os.path.expanduser(args.out))

    write_csv(csv_path, rows)
    if args.verbose:
        eprint(f"[ok] CSV écrit: {csv_path} (lignes={len(rows)})")
    else:
        eprint(f"[ok] CSV écrit: {csv_path}")

    if args.import_bw:
        eprint(
            "[!] Attention: import CSV et fichiers de pièces jointes sont en clair localement. Supprimez-les après migration."
        )

        ok_sess, bw_env, msg = ensure_bw_session(args.verbose)
        if not ok_sess:
            eprint(f"[x] Session bw impossible: {msg}")
            return 1

        ok_imp, msg_imp = bw_import_csv(bw_env, csv_path, args.verbose)
        if not ok_imp:
            eprint(f"[x] bw import a échoué: {msg_imp}")
            return 1

        bw_sync(bw_env)

        if not attachment_tasks:
            eprint("[ok] Aucun fichier de pièce jointe à uploader.")
            results: List[UploadResult] = []
            write_report(report_path, results)
            eprint(f"[ok] Rapport: {report_path}")
            try:
                shutil.rmtree(os.path.dirname(csv_path), ignore_errors=True)
            except Exception:
                pass
            return 0

        eprint(
            f"[i] Upload pièces jointes: {len(attachment_tasks)} fichier(s), concurrency={args.concurrency}, max_attempts={args.max_attempts}"
        )

        results: List[UploadResult] = []
        with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
            futs = [
                ex.submit(
                    upload_one_with_retry,
                    bw_env,
                    t,
                    args.interactive,
                    args.concurrency,
                    args.verbose,
                    args.max_attempts,
                    args.backoff_base,
                )
                for t in attachment_tasks
            ]
            for fut in as_completed(futs):
                r = fut.result()
                results.append(r)
                if args.verbose:
                    eprint(
                        f"[att] {r.file_name} -> {r.status} item_id={r.item_id} att_id={r.attachment_id}"
                    )

        results.sort(key=lambda x: x.file_name)
        write_report(report_path, results)
        eprint(f"[ok] Rapport: {report_path}")

        # Nettoyage CSV temporaire
        try:
            shutil.rmtree(os.path.dirname(csv_path), ignore_errors=True)
        except Exception:
            pass

        ok_count = sum(1 for r in results if r.status == "uploaded")
        fail_count = len(results) - ok_count
        eprint(f"[ok] Upload: OK={ok_count} KO={fail_count}")

        return 0 if (fail_count == 0 or args.skip_errors) else 1

    # mode export-only
    if nonascii_skipped:
        eprint(
            f"[!] non-ascii ignorés: {len(nonascii_skipped)} (utiliser --allow-nonascii)"
        )
    if urls_appended:
        eprint(f"[ok] url ajoutées dans pass: {urls_appended}")
    if errors:
        eprint(f"[!] erreurs: {len(errors)}")
    return 0 if (not errors or args.skip_errors) else 1


if __name__ == "__main__":
    raise SystemExit(main())
