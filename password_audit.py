#!/usr/bin/env python3
"""
password_audit.py
A lightweight, DPAT-style (github.com/clr2of8/DPAT) password audit tool.
Combines an NTDS dump (secretsdump.py format) with a hashcat potfile of
cracked NT hashes and produces a report covering:

  - Total cracked hashes (including duplicate/shared-password accounts)
  - Percentage cracked
  - Unique cracked hashes / unique password count
  - Full list of cracked username:password pairs
  - Password complexity/character-class audit
  - Shared password groups (which accounts reuse the same password)
  - Top N most common cracked passwords

Prompts for: NTDS file, potfile, export file, include machine accounts,
include password history entries, include blank passwords, top N.
Exports a text report (same format as the console) plus a CSV of every
cracked account written alongside the export file:
    <export>_cracked.csv

Default export is <NTDS file name>_password_audit.txt next to the NTDS file
(e.g. /path/to/ntds.txt -> /path/to/ntds_password_audit.txt).

Notes:
  - Machine accounts (usernames ending in '$') are excluded by default,
    matching DPAT's default behavior.
  - Password history entries (user_history0, user_history1, ... from
    secretsdump -history) are excluded by default so they don't count as
    extra accounts. Include them to see old cracked passwords as well.
  - Account status isn't checked; disabled accounts are included.
  - $HEX[...] plaintexts in the potfile are decoded as UTF-8.
  - The report and CSV contain cleartext passwords - handle them accordingly.
"""

import csv
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
HEX_PATTERN = re.compile(r"^\$HEX\[([0-9a-fA-F]+)\]$")
HISTORY_PATTERN = re.compile(r"_history\d+$")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ---------------------------------------------------------------- input helpers

def clean_path(p):
    """Strip whitespace/quotes, expand ~ and env vars."""
    p = p.strip().strip("'\"")
    return os.path.abspath(os.path.expandvars(os.path.expanduser(p))) if p else ""


def enable_tab_completion():
    try:
        import glob
        import readline

        def complete(text, state):
            matches = glob.glob(os.path.expanduser(text) + "*")
            matches = [m + "/" if os.path.isdir(m) else m for m in matches]
            return matches[state] if state < len(matches) else None

        readline.set_completer_delims(" \t\n;")
        readline.parse_and_bind("tab: complete")
        readline.set_completer(complete)
    except ImportError:
        pass


def ask_file(prompt):
    path = clean_path(input(f"{prompt} (full path): "))
    while not os.path.isfile(path):
        path = clean_path(input(f"{RED}Not found.{RESET} {prompt} (full path): "))
    return path


def ask_yes_no(prompt, default=False):
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        ans = input(f"{prompt} {suffix}: ").strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print(f"{RED}Enter y or n.{RESET}")


# ---------------------------------------------------------------- progress

def progress_bar(done, total, current="", width=40):
    pct = done / total if total else 1
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    label = (current[:45] + "…") if len(current) > 46 else current
    sys.stdout.write(f"\r{CYAN}[{bar}]{RESET} {pct:6.1%}  {label:<47}")
    sys.stdout.flush()


def fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def read_lines_with_progress(path):
    """Yields decoded lines from a file while drawing a byte-based progress bar."""
    total_bytes = os.path.getsize(path)
    bytes_read = lines = 0
    with open(path, "rb") as f:
        for raw in f:
            lines += 1
            bytes_read += len(raw)
            yield raw.decode("utf-8", errors="ignore")
            if lines % 2000 == 0:
                progress_bar(bytes_read, total_bytes,
                             f"{fmt_size(bytes_read)} / {fmt_size(total_bytes)}")
    progress_bar(total_bytes, total_bytes, "done")
    print()


# ---------------------------------------------------------------- parsing

def parse_ntds_line(line):
    """Returns (username, nt_hash) or None if the line can't be parsed."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(":")
    if len(parts) < 4:
        return None
    nt_hash = parts[3].lower()
    if len(nt_hash) != 32:
        return None
    return parts[0], nt_hash


def parse_pot_line(line):
    """Returns (nt_hash, plaintext) or None, decoding $HEX[...] values."""
    line = line.rstrip("\r\n")
    if not line.strip() or ":" not in line:
        return None
    nt_hash, plain = line.split(":", 1)
    nt_hash = nt_hash.strip().lower()
    if len(nt_hash) != 32:
        return None
    match = HEX_PATTERN.match(plain)
    if match:
        plain = bytes.fromhex(match.group(1)).decode("utf-8", errors="replace")
    return nt_hash, plain


def is_machine_account(username):
    """Machine accounts are of the form HOSTNAME$ (sometimes DOMAIN\\HOSTNAME$)."""
    return username.split("\\")[-1].endswith("$")


def is_history_entry(username):
    """secretsdump -history entries look like user_history0, user_history1, ..."""
    return bool(HISTORY_PATTERN.search(username))


# ---------------------------------------------------------------- complexity

def classify_password(password):
    """
    Returns a dict describing character classes used and whether the
    password meets a Windows-style complexity bar (3+ of 4 classes, length 8+).
    """
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    class_count = sum([has_lower, has_upper, has_digit, has_special])
    return {
        "length": len(password),
        "class_count": class_count,
        "meets_complexity": class_count >= 3 and len(password) >= 8,
    }


def length_bucket(length):
    if length == 0:
        return "0 (blank)"
    if length < 8:
        return "1-7"
    if length <= 11:
        return "8-11"
    if length <= 15:
        return "12-15"
    return "16+"


# ---------------------------------------------------------------- reporting

class Tee:
    """Writes to the console (with color) and the export file (without)."""

    def __init__(self, fh):
        self.fh = fh

    def __call__(self, text="", color=""):
        print(f"{color}{text}{RESET}" if color else text)
        self.fh.write(text + "\n")


# ---------------------------------------------------------------- main

def main():
    enable_tab_completion()
    print(f"{BOLD}Password Audit (DPAT-style){RESET}\n")

    ntds_file = ask_file("NTDS dump file")
    potfile = ask_file("Potfile")

    # --- export file (full path) ---
    ntds_base = os.path.splitext(os.path.basename(ntds_file))[0]
    default_out = os.path.join(os.path.dirname(ntds_file), f"{ntds_base}_password_audit.txt")
    export_file = clean_path(input(f"Export file (full path) [{default_out}]: ")) or default_out
    if os.path.isdir(export_file):
        export_file = os.path.join(export_file, os.path.basename(default_out))
    while export_file in (ntds_file, potfile):
        print(f"{RED}Export can't be one of the input files.{RESET}")
        export_file = clean_path(input(f"Export file (full path) [{default_out}]: ")) or default_out
    out_dir = os.path.dirname(export_file)
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        print(f"{YELLOW}[*] Created {out_dir}{RESET}")
    csv_file = os.path.splitext(export_file)[0] + "_cracked.csv"

    # --- options ---
    include_machine = ask_yes_no("Include machine accounts (ending in $)?", default=False)
    include_history = ask_yes_no("Include password history entries (_historyN)?", default=False)
    include_empty = ask_yes_no("Include blank passwords in shared/top/complexity stats?", default=False)
    top_n = input("How many top passwords to show [10]: ").strip() or "10"
    while not (top_n.isdigit() and int(top_n) >= 1):
        top_n = input(f"{RED}Enter a number 1 or higher.{RESET} Top passwords [10]: ").strip() or "10"
    top_n = int(top_n)

    start = time.time()

    # --- Load potfile: hash -> plaintext ---
    print(f"\n{BOLD}[*] Reading potfile ({fmt_size(os.path.getsize(potfile))}){RESET}")
    hash_to_password = {}
    for line in read_lines_with_progress(potfile):
        result = parse_pot_line(line)
        if result:
            nt_hash, plain = result
            hash_to_password[nt_hash] = plain
    print(f"[*] Loaded {len(hash_to_password)} cracked hash(es)")

    # --- Load NTDS dump ---
    print(f"\n{BOLD}[*] Reading NTDS dump ({fmt_size(os.path.getsize(ntds_file))}){RESET}")
    accounts = {}  # username -> nt_hash (accounts we're actually counting)
    skipped_machine = skipped_history = 0
    for line in read_lines_with_progress(ntds_file):
        result = parse_ntds_line(line)
        if not result:
            continue
        username, nt_hash = result
        if not include_machine and is_machine_account(username):
            skipped_machine += 1
        elif not include_history and is_history_entry(username):
            skipped_history += 1
        else:
            accounts[username] = nt_hash
    print(f"[*] {len(accounts)} account(s) counted "
          f"({skipped_machine} machine, {skipped_history} history entries excluded)")

    # --- Cross-reference ---
    print(f"\n{BOLD}[*] Matching accounts to cracked hashes{RESET}")
    cracked_users = {}  # username -> password
    items = list(accounts.items())
    step = max(1, len(items) // 200)
    for i, (username, nt_hash) in enumerate(items):
        if nt_hash in hash_to_password:
            cracked_users[username] = hash_to_password[nt_hash]
        if i % step == 0:
            progress_bar(i, len(items), f"{i}/{len(items)} accounts")
    progress_bar(len(items), len(items), "done")
    print()

    total_accounts = len(accounts)
    total_cracked = len(cracked_users)  # includes duplicates (shared passwords)
    pct_cracked = (total_cracked / total_accounts * 100) if total_accounts else 0
    unique_hashes_total = len(set(accounts.values()))
    unique_hashes_cracked = len({h for h in accounts.values() if h in hash_to_password})
    pct_unique_cracked = (unique_hashes_cracked / unique_hashes_total * 100) if unique_hashes_total else 0

    # --- Shared passwords / top N ---
    password_to_users = defaultdict(list)
    for username, password in cracked_users.items():
        password_to_users[password].append(username)
    sorted_shared = sorted(
        ((pw, users) for pw, users in password_to_users.items()
         if len(users) >= 2 and (include_empty or pw != "")),
        key=lambda kv: len(kv[1]), reverse=True,
    )
    top_passwords = Counter(
        pw for pw in cracked_users.values() if include_empty or pw != ""
    ).most_common(top_n)

    # --- Complexity audit ---
    print(f"\n{BOLD}[*] Auditing password complexity{RESET}")
    length_dist, class_dist = Counter(), Counter()
    meets_complexity_count = audited_count = 0
    classified = {}
    pw_items = list(cracked_users.items())
    step = max(1, len(pw_items) // 200)
    for i, (username, password) in enumerate(pw_items):
        info = classify_password(password)
        classified[username] = info
        if include_empty or password != "":
            audited_count += 1
            length_dist[length_bucket(info["length"])] += 1
            class_dist[info["class_count"]] += 1
            meets_complexity_count += info["meets_complexity"]
        if i % step == 0:
            progress_bar(i, len(pw_items), f"{i}/{len(pw_items)} passwords")
    progress_bar(len(pw_items), len(pw_items), "done")
    print()
    pct_meets = (meets_complexity_count / audited_count * 100) if audited_count else 0

    # ----------------------------------------------------------------
    # Report (console + export file)
    # ----------------------------------------------------------------
    print()
    with open(export_file, "w", encoding="utf-8") as fh:
        fh.write(f"Password Audit - {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        fh.write(f"NTDS file: {ntds_file}\n")
        fh.write(f"Potfile: {potfile}\n")
        fh.write(f"Machine accounts included: {include_machine}\n")
        fh.write(f"History entries included: {include_history}\n")
        fh.write(f"Blank passwords in stats: {include_empty}\n")
        out = Tee(fh)

        out("=" * 70)
        out("PASSWORD AUDIT REPORT", BOLD)
        out("=" * 70)
        out()
        out("--- Summary ---", BOLD)
        out(f"Total accounts audited        : {total_accounts}")
        out(f"Total cracked (incl. dupes)    : {total_cracked}")
        out(f"Percent cracked                : {pct_cracked:.1f}%", RED if total_cracked else "")
        out(f"Unique hashes (accounts)       : {unique_hashes_total}")
        out(f"Unique hashes cracked          : {unique_hashes_cracked}")
        out(f"Percent unique hashes cracked  : {pct_unique_cracked:.1f}%")
        out()

        out("--- Cracked Users ---", BOLD)
        for username in sorted(cracked_users):
            out(f"  {username}: {cracked_users[username]}")
        if not cracked_users:
            out("  None.")
        out()

        out("--- Password Complexity Audit ---", BOLD)
        out(f"Passwords audited ({'includes' if include_empty else 'excludes'} blanks): {audited_count}")
        out(f"Meet 3+ character classes AND length >= 8: {meets_complexity_count} ({pct_meets:.1f}%)")
        out()
        out("Length distribution:")
        for bucket in ["0 (blank)", "1-7", "8-11", "12-15", "16+"]:
            if length_dist.get(bucket):
                out(f"  {bucket:10s}: {length_dist[bucket]}")
        out()
        out("Character class usage (count of character types used: lower/upper/digit/special):")
        for cc in sorted(class_dist):
            out(f"  {cc} class(es): {class_dist[cc]}")
        out()

        out("--- Shared Passwords ---", BOLD)
        if not sorted_shared:
            out("No shared passwords found.", GREEN)
        for password, users in sorted_shared:
            label = "(blank)" if password == "" else password
            out(f"Password: {label}  (shared by {len(users)} accounts)", RED)
            for u in sorted(users):
                out(f"    - {u}")
        out()

        out(f"--- Top {top_n} Passwords ---", BOLD)
        if not top_passwords:
            out("No cracked passwords to rank.")
        for i, (password, count) in enumerate(top_passwords, 1):
            label = "(blank)" if password == "" else password
            out(f"  {i}. {label}  -  used by {count} account(s)")
        out()

    # --- CSV of cracked accounts ---
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["username", "nt_hash", "password", "length", "char_classes",
                    "meets_complexity", "accounts_sharing_password"])
        for username in sorted(cracked_users):
            pw = cracked_users[username]
            info = classified[username]
            w.writerow([username, accounts[username], pw, info["length"], info["class_count"],
                        info["meets_complexity"], len(password_to_users[pw])])

    print("-" * 70)
    print(f"[*] {total_cracked}/{total_accounts} accounts cracked ({pct_cracked:.1f}%) "
          f"({time.time() - start:.1f}s)")
    print(f"\n[+] Report: {export_file}")
    print(f"[+] CSV:    {csv_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted.{RESET}")
        sys.exit(130)
