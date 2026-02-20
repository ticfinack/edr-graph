#!/usr/bin/env python3
"""Menu-driven attack simulation harness for live EDR testing.

All simulations are SAFE and REVERSIBLE — no actual exploitation.
We are testing telemetry capture and detection, not breaking things.

Usage:
    python tests/live/attack_simulations.py

Run this while the agent is running (use run_live_tests.py first).
"""

from __future__ import annotations

import base64
import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import time

# Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


def print_banner(text: str) -> None:
    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}\n")


def print_step(text: str) -> None:
    print(f"  {GREEN}>>>{RESET} {text}")


def print_expected(text: str) -> None:
    print(f"  {YELLOW}[EXPECTED]{RESET} {text}")


def wait_and_confirm(description: str) -> bool:
    """Print what the test will do and ask for confirmation."""
    print(f"\n  {BOLD}About to:{RESET} {description}")
    resp = input(f"  {CYAN}Continue? [Y/n]:{RESET} ").strip().lower()
    return resp in ("", "y", "yes")


# ── Test 1: Process Chain ────────────────────────────────────────────────────


def test_process_chain() -> None:
    """Spawn a chain: python -> sh/cmd -> whoami to test parent-child tracking."""
    print_banner("Test 1: Process Chain")

    if not wait_and_confirm("Spawn a 3-level process chain (python -> shell -> whoami)"):
        return

    print_step("Spawning process chain...")
    if IS_WINDOWS:
        proc = subprocess.Popen(
            ["cmd", "/c", "whoami & hostname & ipconfig"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    else:
        proc = subprocess.Popen(
            ["sh", "-c", "whoami && id && uname -a"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    stdout, _ = proc.communicate(timeout=10)
    shell_name = "cmd" if IS_WINDOWS else "sh"

    print_step(f"Chain: python (PID {os.getpid()}) -> {shell_name} (PID {proc.pid}) -> whoami")
    print_step(f"Output: {stdout.decode().strip()[:200]}")
    print()
    print_expected("Agent should show: 3-level process chain with correct PPIDs")
    print_expected("Graph: User -> Process(python) -> Process(sh/cmd)")
    print_expected("build_attack_chain() should show the full lineage")
    print()
    time.sleep(3)


# ── Test 2: Suspicious DNS ───────────────────────────────────────────────────


def test_dns_resolution() -> None:
    """Resolve good and DGA-like domains to test DNS capture and DGA detection."""
    print_banner("Test 2: Suspicious DNS Resolution")

    if not wait_and_confirm("Resolve 5 domains (2 legit, 2 DGA-like, 1 real high-entropy)"):
        return

    # Known-good domains
    for domain in ["google.com", "github.com"]:
        print_step(f"Resolving {domain} (legitimate)...")
        try:
            result = socket.getaddrinfo(domain, 80)
            print_step(f"  -> {result[0][4][0]}")
        except socket.gaierror as e:
            print_step(f"  -> Failed: {e}")
        time.sleep(1)

    # DGA-like domains (will fail to resolve — that's expected)
    dga_domains = ["xjk82mfq3p9a2z.xyz", "a8f3kq9xm2p7b4.top"]
    for domain in dga_domains:
        print_step(f"Resolving {domain} (DGA-like, expect failure)...")
        try:
            socket.getaddrinfo(domain, 80)
        except socket.gaierror:
            print_step("  -> Resolution failed (expected)")
        time.sleep(1)

    # Real domain with high entropy
    print_step("Resolving neverssl.com (real domain)...")
    try:
        result = socket.getaddrinfo("neverssl.com", 80)
        print_step(f"  -> {result[0][4][0]}")
    except socket.gaierror as e:
        print_step(f"  -> Failed: {e}")

    print()
    print_expected("Domain 'xjk82mfq3p9a2z.xyz' flagged as DGA candidate (score > 0.6)")
    print_expected("Domain 'a8f3kq9xm2p7b4.top' flagged as DGA candidate")
    print_expected("Domain 'google.com' should NOT be flagged")
    print_expected("Domain nodes created in graph with RESOLVED edges from python process")
    print()
    time.sleep(3)


# ── Test 3: File Modification (FIM) ─────────────────────────────────────────


def test_file_modification() -> None:
    """Create and modify files to test FIM tracking."""
    print_banner("Test 3: File Modification (FIM)")

    if not wait_and_confirm("Create, modify, and delete test files in a temp directory"):
        return

    test_dir = tempfile.mkdtemp(prefix="edr_test_")
    print_step(f"Created temp directory: {test_dir}")

    # Create a file
    test_file = os.path.join(test_dir, "test_payload.txt")
    with open(test_file, "w") as f:
        f.write("initial content")
    print_step(f"Created: {test_file}")
    time.sleep(2)

    # Modify the file
    with open(test_file, "a") as f:
        f.write("\nmodified content - simulating data staging")
    print_step(f"Modified: {test_file}")
    time.sleep(2)

    # Create a suspicious file extension
    suspicious_file = os.path.join(test_dir, "backdoor.php")
    with open(suspicious_file, "w") as f:
        f.write("<?php echo 'test'; ?>")
    print_step(f"Created suspicious file: {suspicious_file}")
    time.sleep(2)

    # Cleanup
    os.remove(test_file)
    os.remove(suspicious_file)
    os.rmdir(test_dir)
    print_step("Cleaned up all test files")

    print()
    print_expected("File 'test_payload.txt' CREATED then MODIFIED")
    print_expected("File 'backdoor.php' CREATED")
    print_expected("File nodes in graph with CREATED_FILE and MODIFIED_FILE edges from python process")
    print()
    time.sleep(3)


# ── Test 4: Persistence Mechanism ────────────────────────────────────────────


def test_persistence() -> None:
    """Write to platform-specific persistence locations."""
    print_banner("Test 4: Persistence Mechanism")

    if IS_MACOS:
        plist_path = os.path.expanduser("~/Library/LaunchAgents/com.edr.test.fake.plist")
        if not wait_and_confirm(f"Create a fake LaunchAgent plist at {plist_path}"):
            return

        import plistlib

        plist_data = {
            "Label": "com.edr.test.fake",
            "ProgramArguments": ["/usr/bin/true"],
            "RunAtLoad": True,
        }
        os.makedirs(os.path.dirname(plist_path), exist_ok=True)
        with open(plist_path, "wb") as f:
            plistlib.dump(plist_data, f)
        print_step(f"Created test LaunchAgent: {plist_path}")
        print_expected("Persistence detected: T1543.001 - Launch Agent")

        time.sleep(5)

        os.remove(plist_path)
        print_step("Cleaned up test LaunchAgent")

    elif IS_WINDOWS:
        if not wait_and_confirm("Write a harmless test value to HKCU Run key"):
            return

        import winreg

        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        value_name = "EDRGraphTest"
        value_data = r"C:\Windows\System32\cmd.exe /c echo test"

        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
            winreg.CloseKey(key)
            print_step(f"Created test Run key: HKCU\\{key_path}\\{value_name}")
            print_expected("Persistence detected: T1547.001 - Registry Run Key")

            time.sleep(5)

            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)
            print_step("Cleaned up test Run key")
        except PermissionError:
            print(f"  {RED}ERROR: Need Administrator privileges to write Run keys.{RESET}")

    elif IS_LINUX:
        cron_file = "/tmp/edr_test_cron"
        if not wait_and_confirm(f"Create a fake cron file at {cron_file}"):
            return

        with open(cron_file, "w") as f:
            f.write("* * * * * /usr/bin/true\n")
        print_step(f"Created test cron file: {cron_file}")

        if os.geteuid() == 0:
            import shutil

            actual_cron = "/etc/cron.d/edr_test_fake"
            shutil.copy(cron_file, actual_cron)
            print_step(f"Copied to {actual_cron}")
            print_expected("Persistence detected: T1053.003 - Cron")

            time.sleep(5)

            os.remove(actual_cron)
            print_step("Cleaned up")
        else:
            print(f"  {YELLOW}Not running as root — agent may not detect /tmp writes as persistence.{RESET}")
            print(f"  {YELLOW}For full test, run simulation as root in the test VM.{RESET}")

        os.remove(cron_file)
        print_step("Cleaned up test cron file")

    else:
        print(f"  {YELLOW}Unsupported platform for persistence test.{RESET}")

    print()
    time.sleep(3)


# ── Test 5: Network Connection ───────────────────────────────────────────────


def test_network_connection() -> None:
    """Connect to known-good services to test outbound connection tracking."""
    print_banner("Test 5: Network Connection")

    targets = [
        ("1.1.1.1", 80, "Cloudflare DNS HTTP"),
        ("8.8.8.8", 53, "Google DNS"),
        ("93.184.216.34", 80, "example.com"),
    ]

    if not wait_and_confirm(f"Make TCP connections to {len(targets)} known-good IP addresses"):
        return

    for ip, port, desc in targets:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            print_step(f"Connected to {ip}:{port} ({desc})")
            sock.close()
        except Exception as e:
            print_step(f"Failed to connect to {ip}:{port}: {e}")
        time.sleep(1)

    print()
    print_expected("IP nodes created with addresses and ports")
    print_expected("CONNECTED_TO edges from the python process to each IP")
    print()
    time.sleep(3)


# ── Test 6: Encoded Command ──────────────────────────────────────────────────


def test_encoded_command() -> None:
    """Execute base64-encoded commands to test suspicious CLI detection."""
    print_banner("Test 6: Encoded Command")

    if IS_WINDOWS:
        desc = "Run PowerShell -EncodedCommand with base64 'whoami'"
    else:
        desc = "Run 'echo <base64> | base64 -d | sh' to execute 'whoami'"

    if not wait_and_confirm(desc):
        return

    if IS_WINDOWS:
        cmd = "whoami"
        encoded = base64.b64encode(cmd.encode("utf-16-le")).decode()
        print_step(f"Encoded command: {encoded}")
        result = subprocess.run(
            ["powershell", "-EncodedCommand", encoded],
            capture_output=True,
            text=True,
            timeout=10,
        )
        print_step(f"Output: {result.stdout.strip()}")
    else:
        encoded = base64.b64encode(b"whoami").decode()
        print_step(f"Encoded command: {encoded}")
        result = subprocess.run(
            ["sh", "-c", f"echo {encoded} | base64 -d | sh"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        print_step(f"Output: {result.stdout.strip()}")

    print()
    print_expected("Process with suspicious command line (-EncodedCommand or base64 pipe)")
    print_expected("LLM should flag this as suspicious technique")
    print()
    time.sleep(3)


# ── Test 7: Rapid Process Spawning ───────────────────────────────────────────


def test_rapid_spawning() -> None:
    """Spawn 20 short-lived processes rapidly to test ephemeral process capture."""
    print_banner("Test 7: Rapid Process Spawning")

    if not wait_and_confirm("Spawn 20 short-lived processes in rapid succession"):
        return

    print_step("Spawning 20 ephemeral processes...")
    start = time.time()

    for i in range(20):
        if IS_WINDOWS:
            subprocess.run(
                ["cmd", "/c", f"echo ephemeral_{i}"],
                capture_output=True,
                timeout=5,
            )
        else:
            subprocess.run(
                ["sh", "-c", f"echo ephemeral_{i}"],
                capture_output=True,
                timeout=5,
            )

    elapsed = time.time() - start
    print_step(f"Spawned 20 processes in {elapsed:.2f}s")

    print()
    print_expected("All 20 process_start events captured")
    print_expected("events_processed_total should increase by >= 20")
    print_expected("This proves ETW/auditd is working — psutil polling would miss most of these")
    print()
    time.sleep(3)


# ── Test 8: Full Kill Chain ──────────────────────────────────────────────────


def test_kill_chain() -> None:
    """Simulate a realistic 6-stage attack sequence."""
    print_banner("Test 8: Full Kill Chain Simulation")

    print(f"  {BOLD}This runs all 6 attack stages sequentially:{RESET}")
    print("    1. Initial access via encoded command")
    print("    2. System discovery (whoami, hostname, etc.)")
    print("    3. Persistence mechanism (platform-specific)")
    print("    4. C2 DNS beacon (DGA-like domains)")
    print("    5. Data staging (write to temp file)")
    print("    6. Exfiltration attempt (outbound connection)")
    print()

    if not wait_and_confirm("Run the full kill chain simulation"):
        return

    persistence_cleanup = None

    try:
        # Stage 1: Initial access via encoded command
        print_step("[Stage 1] Encoded command execution...")
        if IS_WINDOWS:
            encoded = base64.b64encode("whoami".encode("utf-16-le")).decode()
            subprocess.run(
                ["powershell", "-EncodedCommand", encoded],
                capture_output=True,
                timeout=10,
            )
        else:
            encoded = base64.b64encode(b"whoami").decode()
            subprocess.run(
                ["sh", "-c", f"echo {encoded} | base64 -d | sh"],
                capture_output=True,
                timeout=10,
            )
        time.sleep(2)

        # Stage 2: Discovery
        print_step("[Stage 2] System discovery...")
        if IS_WINDOWS:
            subprocess.run(
                ["cmd", "/c", "whoami & hostname & ipconfig & net user"],
                capture_output=True,
                timeout=10,
            )
        else:
            subprocess.run(
                ["sh", "-c", "whoami && hostname && ifconfig 2>/dev/null || ip addr && id"],
                capture_output=True,
                timeout=10,
            )
        time.sleep(2)

        # Stage 3: Persistence
        print_step("[Stage 3] Persistence mechanism...")
        if IS_MACOS:
            import plistlib

            plist_path = os.path.expanduser("~/Library/LaunchAgents/com.edr.killchain.test.plist")
            plist_data = {
                "Label": "com.edr.killchain.test",
                "ProgramArguments": ["/usr/bin/true"],
                "RunAtLoad": True,
            }
            os.makedirs(os.path.dirname(plist_path), exist_ok=True)
            with open(plist_path, "wb") as f:
                plistlib.dump(plist_data, f)

            def persistence_cleanup():
                return os.remove(plist_path)

            print_step(f"  Created LaunchAgent: {plist_path}")
        elif IS_WINDOWS:
            import winreg

            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    0,
                    winreg.KEY_SET_VALUE,
                )
                winreg.SetValueEx(
                    key,
                    "EDRKillChainTest",
                    0,
                    winreg.REG_SZ,
                    r"C:\Windows\System32\cmd.exe /c echo test",
                )
                winreg.CloseKey(key)

                def _cleanup_reg():
                    k = winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        0,
                        winreg.KEY_SET_VALUE,
                    )
                    winreg.DeleteValue(k, "EDRKillChainTest")
                    winreg.CloseKey(k)

                persistence_cleanup = _cleanup_reg
                print_step("  Created Run key: EDRKillChainTest")
            except PermissionError:
                print_step("  Skipped — need Administrator")
        else:
            print_step("  Skipped persistence on Linux (need root for /etc/cron.d)")
        time.sleep(2)

        # Stage 4: C2 beacon (DGA-like DNS)
        print_step("[Stage 4] C2 DNS beacon...")
        dga_domains = [
            "xjk82mfq3p9a2z.xyz",
            "q7w2m9f4p8k1.top",
            "b3x7n2k9m5p1.net",
        ]
        for domain in dga_domains:
            with contextlib.suppress(socket.gaierror):
                socket.getaddrinfo(domain, 443)
            time.sleep(0.5)
        time.sleep(2)

        # Stage 5: Staging
        print_step("[Stage 5] Data staging...")
        staging_dir = tempfile.mkdtemp(prefix="edr_staging_")
        staged_file = os.path.join(staging_dir, "exfil_data.enc")
        with open(staged_file, "w") as f:
            f.write("SIMULATED_SENSITIVE_DATA_" * 100)
        print_step(f"  Staged file: {staged_file}")
        time.sleep(2)

        # Stage 6: Exfiltration attempt
        print_step("[Stage 6] Exfiltration connection...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(("93.184.216.34", 443))  # example.com
            print_step("  Connected to 93.184.216.34:443 (example.com)")
            sock.close()
        except Exception as e:
            print_step(f"  Connection failed: {e} (still generates telemetry)")
        time.sleep(2)

        # Cleanup
        print_step("[Cleanup] Removing artifacts...")
        if persistence_cleanup:
            try:
                persistence_cleanup()
            except Exception as e:
                print(f"  {YELLOW}Persistence cleanup failed: {e}{RESET}")
        os.remove(staged_file)
        os.rmdir(staging_dir)

    except Exception as e:
        print(f"  {RED}Kill chain error: {e}{RESET}")
        # Best-effort cleanup
        if persistence_cleanup:
            with contextlib.suppress(Exception):
                persistence_cleanup()

    print()
    print_banner("Kill Chain Complete — Expected Detections")
    print("  1. Encoded command execution (suspicious command line)")
    print("  2. Discovery commands (whoami, ipconfig/ifconfig)")
    print("  3. Persistence mechanism (T1547.001 or T1543.001)")
    print("  4. DGA domain resolution (3 candidates, score > 0.6)")
    print("  5. File staging (CREATED edge to temp file)")
    print("  6. Outbound connection (CONNECTED_TO edge)")
    print("  7. Full attack chain should link all 6 stages through process tree")
    print()
    print(f"  {CYAN}Check: build_attack_chain() for PID {os.getpid()} should show all of the above.{RESET}")
    print()
    time.sleep(3)


# ── Menu ─────────────────────────────────────────────────────────────────────

TESTS = {
    "1": ("Process Chain Test", test_process_chain),
    "2": ("Suspicious DNS Resolution", test_dns_resolution),
    "3": ("File Modification (FIM) Test", test_file_modification),
    "4": ("Persistence Mechanism Test", test_persistence),
    "5": ("Network Connection Test", test_network_connection),
    "6": ("Encoded Command Test", test_encoded_command),
    "7": ("Rapid Process Spawning", test_rapid_spawning),
    "8": ("Full Kill Chain Simulation", test_kill_chain),
}


def run_all() -> None:
    """Run all tests sequentially."""
    for key in sorted(TESTS.keys()):
        name, func = TESTS[key]
        print(f"\n{BOLD}Running test {key}: {name}{RESET}")
        func()


def main() -> None:
    while True:
        print_banner("EDR Agent Live Test Suite")
        print("  Select a test to run:\n")
        for key in sorted(TESTS.keys()):
            name, _ = TESTS[key]
            print(f"    [{key}] {name}")
        print("    [0] Run All Tests Sequentially")
        print("    [q] Quit")
        print()

        choice = input(f"  {CYAN}>>>{RESET} ").strip().lower()

        if choice == "q":
            print("\nExiting.")
            break
        elif choice == "0":
            run_all()
        elif choice in TESTS:
            _, func = TESTS[choice]
            func()
        else:
            print(f"  {RED}Invalid choice. Try again.{RESET}")


if __name__ == "__main__":
    main()
