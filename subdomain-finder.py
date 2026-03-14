#!/usr/bin/env python3
"""
===============================================================
  SubFinder - Subdomain Enumeration Tool
  Author  : [Your Name]
  Version : 3.6
  Purpose : Fast, threaded, active DNS-based subdomain discovery
  Usage   : python3 subfinder.py

  Changelog v3.6:
    - ADDED: All results saved inside a results/ folder
    - ADDED: Same domain = same file (appends, no duplicates)
    - ADDED: Scan history — see all previous scans at startup
    - KEPT:  All v3.3 fixes (smart retry, wildcard, threading)
===============================================================
"""

import socket
import os
import datetime
import random
import string
import threading
import time
from queue import Queue, Empty
from urllib.parse import urlparse


# ══════════════════════════════════════════════════════════════
# GLOBALS
# ══════════════════════════════════════════════════════════════

lock             = threading.Lock()
found_subdomains = []
tested_count     = 0
start_time       = None
last_bar_update  = 0

RESULTS_DIR      = "results"   # All output files live here


# ══════════════════════════════════════════════════════════════
# SECTION 1: BANNER
# ══════════════════════════════════════════════════════════════

def print_banner():
    print("""
    ╔══════════════════════════════════════════════════╗
    ║            S U B F I N D E R  v3.6               ║
    ║   Fast Threaded Subdomain Enumeration Tool        ║
    ║   For authorized penetration testing only         ║
    ╚══════════════════════════════════════════════════╝
    """)


# ══════════════════════════════════════════════════════════════
# SECTION 2: RESULTS FOLDER MANAGEMENT
#
# CONCEPT: Instead of dumping result files into the project
# root, we create a results/ subfolder. One file per domain,
# named results/tesla.com.txt — scans append to it so you
# build up a history of findings over time without clutter.
# ══════════════════════════════════════════════════════════════

def setup_results_dir():
    """Creates the results/ folder if it doesn't exist."""
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
        print(f"  [INFO] Created results folder: {RESULTS_DIR}/\n")


def get_output_file(domain):
    """
    Returns the output file path for a domain.
    Always the same file per domain → appends across scans.

    Example: results/tesla.com.txt
    """
    return os.path.join(RESULTS_DIR, f"{domain}.txt")


def show_scan_history():
    """
    Shows all previous result files in results/ folder
    so the user knows what they've already scanned.
    """
    if not os.path.exists(RESULTS_DIR):
        return

    files = [f for f in os.listdir(RESULTS_DIR) if f.endswith(".txt")]
    if not files:
        return

    print(f"  [HISTORY] Previous scans found in {RESULTS_DIR}/:")
    for fname in sorted(files):
        fpath = os.path.join(RESULTS_DIR, fname)
        # Count discovered subdomains (lines that don't start with #)
        with open(fpath) as f:
            entries = [l for l in f if l.strip() and not l.startswith("#") and not l.startswith("-")]
        # Get last modified time
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(fpath))
        print(f"             {fname:<30} {len(entries):>3} subdomains  (last: {mtime.strftime('%Y-%m-%d %H:%M')})")
    print()


def write_scan_header(output_file, domain, thread_count):
    """
    Appends a scan session header to the results file.
    If same domain is scanned twice, both sessions are recorded.

    File structure:
      # SubFinder v3.6 — Scan Results
      # Target  : tesla.com
      # ── Scan Session ─────────────────
      # Date    : 2026-03-14 15:53:47
      # Threads : 20
      # ─────────────────────────────────
      www.tesla.com,23.208.64.57
      ...
    """
    file_exists = os.path.exists(output_file)

    with open(output_file, "a") as f:
        # Write file header only on first scan of this domain
        if not file_exists:
            f.write("# ═══════════════════════════════════════════\n")
            f.write("# SubFinder v3.6 — Scan Results\n")
            f.write(f"# Target  : {domain}\n")
            f.write("# Format  : subdomain,ip_address\n")
            f.write("# ═══════════════════════════════════════════\n\n")

        # Always write a per-session separator
        f.write(f"# ── Scan Session ────────────────────────────\n")
        f.write(f"# Date    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Threads : {thread_count}\n")
        f.write(f"# ─────────────────────────────────────────────\n")


def write_scan_footer(output_file, found_count, duration):
    """Appends a summary footer after each scan session."""
    with open(output_file, "a") as f:
        f.write(f"# Found   : {found_count} subdomains\n")
        f.write(f"# Duration: {duration}\n")
        f.write(f"# ─────────────────────────────────────────────\n\n")


# ══════════════════════════════════════════════════════════════
# SECTION 3: INPUT CLEANING
# ══════════════════════════════════════════════════════════════

def clean_domain(raw_input):
    """'https://example.com/' → 'example.com'"""
    raw_input = raw_input.strip()
    if "://" in raw_input:
        raw_input = urlparse(raw_input).netloc
    return raw_input.strip("/").lower()


# ══════════════════════════════════════════════════════════════
# SECTION 4: ADAPTIVE TIMEOUT + THREAD VALIDATOR
# ══════════════════════════════════════════════════════════════

def get_adaptive_timeout(thread_count):
    if thread_count <= 20:   return 2
    elif thread_count <= 50: return 3
    else:                    return 5

def validate_thread_count(thread_count):
    if thread_count > 50:
        print(f"\n  [WARN] ⚠️  {thread_count} threads may flood DNS → 0 results.")
        print(f"  [WARN] Professional tools default to 10–50 threads.\n")
        confirm = input(f"  Keep {thread_count} threads? (y/N): ").strip().lower()
        if confirm != 'y':
            thread_count = 20
            print(f"  [INFO] Reset to 20 threads.\n")
    return thread_count


# ══════════════════════════════════════════════════════════════
# SECTION 5: WILDCARD DETECTION
# ══════════════════════════════════════════════════════════════

def detect_wildcard(domain):
    noise = ''.join(random.choices(string.ascii_lowercase, k=12))
    try:
        ip = socket.gethostbyname(f"{noise}.{domain}")
        print(f"  [!] WILDCARD DNS detected → {ip} (will be filtered)\n")
        return ip
    except socket.gaierror:
        print(f"  [OK] No wildcard DNS detected.\n")
        return None


# ══════════════════════════════════════════════════════════════
# SECTION 6: WORDLIST LOADER
# ══════════════════════════════════════════════════════════════

def load_wordlist(filepath):
    if not os.path.exists(filepath):
        print(f"\n  [ERROR] Wordlist not found: {filepath}")
        print("  [TIP]   sudo apt install seclists")
        print("          /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt\n")
        raise SystemExit(1)
    with open(filepath, "r") as f:
        words = [line.strip() for line in f if line.strip()]
    print(f"  [INFO] Loaded {len(words)} words from: {filepath}")
    return words


# ══════════════════════════════════════════════════════════════
# SECTION 7: DNS RESOLVER
# ══════════════════════════════════════════════════════════════

def resolve(subdomain):
    """Smart resolver — retries only on temporary DNS failure."""
    for attempt in range(2):
        try:
            return socket.gethostbyname(subdomain)
        except socket.gaierror as e:
            err = e.args[0]
            if err in (-2, 11001):   # NXDOMAIN — definitive miss
                return None
            if err == -3 and attempt == 0:
                continue             # Temp failure — retry once
            return None
        except Exception:
            return None


# ══════════════════════════════════════════════════════════════
# SECTION 8: PROGRESS BAR
# ══════════════════════════════════════════════════════════════

def update_progress(total):
    global last_bar_update
    now = time.time()
    if now - last_bar_update < 0.2:
        return
    last_bar_update = now
    elapsed   = max(now - start_time, 0.001)
    rate      = tested_count / elapsed
    pct       = int((tested_count / total) * 100)
    bar       = "█" * (pct // 5) + "░" * (20 - pct // 5)
    remaining = total - tested_count
    eta       = f"ETA {int(remaining/rate)}s" if rate > 0 else "..."
    print(f"\r  [{bar}] {pct:>3}%  {tested_count}/{total}  {int(rate)}/sec  {eta}   ",
          end="", flush=True)


# ══════════════════════════════════════════════════════════════
# SECTION 9: THREAD WORKER
# ══════════════════════════════════════════════════════════════

def worker(domain, queue, output_file, wildcard_ip, total):
    global tested_count
    while True:
        try:
            word = queue.get(timeout=2)
        except Empty:
            break

        ip = resolve(f"{word}.{domain}")

        with lock:
            tested_count += 1
            if ip and ip != wildcard_ip:
                sub = f"{word}.{domain}"
                found_subdomains.append((sub, ip))
                print(f"\r  [FOUND] {sub:<45} → {ip}")
                with open(output_file, "a") as f:
                    f.write(f"{sub},{ip}\n")
            update_progress(total)

        queue.task_done()   # exactly once, always here


# ══════════════════════════════════════════════════════════════
# SECTION 10: SCAN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════

def run_threaded_scan(domain, wordlist, output_file, wildcard_ip, thread_count):
    global start_time
    total      = len(wordlist)
    start_time = time.time()

    print(f"\n  [SCAN] Target      : {domain}")
    print(f"  [SCAN] Subdomains  : {total}")
    print(f"  [SCAN] Threads     : {thread_count}")
    print(f"  [SCAN] DNS Timeout : {get_adaptive_timeout(thread_count)}s")
    print(f"  [SCAN] Results     : {output_file}")
    print(f"\n  {'─' * 62}\n")

    q = Queue()
    for word in wordlist:
        q.put(word)

    for _ in range(thread_count):
        threading.Thread(
            target=worker,
            args=(domain, q, output_file, wildcard_ip, total),
            daemon=True
        ).start()

    q.join()
    print("\r" + " " * 75 + "\r", end="")


# ══════════════════════════════════════════════════════════════
# SECTION 11: SUMMARY
# ══════════════════════════════════════════════════════════════

def print_summary(domain, output_file):
    duration     = time.time() - start_time
    mins, secs   = divmod(int(duration), 60)
    rate         = int(tested_count / max(duration, 0.001))
    duration_str = f"{mins}m {secs}s"

    # Write footer to file
    write_scan_footer(output_file, len(found_subdomains), duration_str)

    print(f"  {'─' * 62}")
    print(f"\n  [DONE] Target           : {domain}")
    print(f"  [DONE] Total tested     : {tested_count}")
    print(f"  [DONE] Subdomains found : {len(found_subdomains)}")
    print(f"  [DONE] Duration         : {duration_str}  ({rate}/sec avg)")
    print(f"  [DONE] Results saved to : {output_file}")
    print(f"  [DONE] (appended — all scans of {domain} in one file)\n")

    if found_subdomains:
        print(f"  {'─' * 62}")
        print(f"  {'SUBDOMAIN':<45} IP ADDRESS")
        print(f"  {'─' * 62}")
        for sub, ip in sorted(found_subdomains):
            print(f"  [+]  {sub:<45} {ip}")
        print(f"  {'─' * 62}\n")
    else:
        print(f"  [INFO] No subdomains found. Try a larger wordlist.\n")


# ══════════════════════════════════════════════════════════════
# SECTION 12: MAIN
# ══════════════════════════════════════════════════════════════

def main():
    print_banner()
    setup_results_dir()
    show_scan_history()

    raw_domain = input("  [INPUT] Target domain  (e.g. tesla.com)    : ")
    domain     = clean_domain(raw_domain)
    if not domain:
        print("  [ERROR] No domain entered. Exiting.")
        raise SystemExit(1)

    wordlist_path = input("  [INPUT] Wordlist path  (Enter = wordlist.txt): ").strip()
    if not wordlist_path:
        wordlist_path = "wordlist.txt"

    threads_input = input("  [INPUT] Thread count   (Enter = 20)         : ").strip()
    thread_count  = int(threads_input) if threads_input.isdigit() else 20
    thread_count  = validate_thread_count(thread_count)

    socket.setdefaulttimeout(get_adaptive_timeout(thread_count))
    print()

    print("  [*] Checking for wildcard DNS...")
    wildcard_ip = detect_wildcard(domain)

    # One file per domain, inside results/ folder
    output_file = get_output_file(domain)
    write_scan_header(output_file, domain, thread_count)

    wordlist = load_wordlist(wordlist_path)
    run_threaded_scan(domain, wordlist, output_file, wildcard_ip, thread_count)
    print_summary(domain, output_file)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        elapsed = time.time() - start_time if start_time else 0
        print(f"\n\n  [!] Interrupted. {len(found_subdomains)} found in {int(elapsed)}s.")
        print("  [!] Partial results saved.\n")
