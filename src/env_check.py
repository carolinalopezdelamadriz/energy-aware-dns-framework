import shutil
import subprocess
import sys
import importlib.util
from pathlib import Path


def _command_ok(command):
    return shutil.which(command) is not None


def _run(command):
    return subprocess.run(command, capture_output=True, text=True)


def _chrome_found():
    commands = ["google-chrome", "chrome", "chromium", "chromium-browser"]
    if any(_command_ok(command) for command in commands):
        return True

    macos_path = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    return macos_path.exists()


def run_environment_check(interface=None, check_doq=False, doq_resolver="quad9"):
    print("\n=== ENVIRONMENT CHECK ===")
    print(f"Python: {sys.version.split()[0]}")

    checks = {
        "tcpdump": _command_ok("tcpdump"),
        "kdig": _command_ok("kdig"),
        "chrome": _chrome_found(),
        # needed for overhead_breakdown.py's handshake/control/payload split
        # (decrypts TLS/QUIC with the saved session-key logs)
        "tshark": _command_ok("tshark"),
    }

    for name, ok in checks.items():
        status = "OK" if ok else "MISSING"
        print(f"{name}: {status}")

    python_packages = {
        "dnspython": "dns",
        "httpx": "httpx",
        "h2": "h2",
        "selenium": "selenium",
        "aioquic": "aioquic",
    }
    for package_name, import_name in python_packages.items():
        ok = importlib.util.find_spec(import_name) is not None
        status = "OK" if ok else "MISSING"
        print(f"python package {package_name}: {status}")

    if checks["kdig"]:
        help_result = _run(["kdig", "-h"])
        quic_supported = "+[no]quic" in help_result.stdout
        status = "OK" if quic_supported else "MISSING"
        print(f"kdig QUIC support: {status}")

    if checks["tcpdump"]:
        list_result = _run(["tcpdump", "-D"])
        if list_result.returncode == 0:
            print("\nAvailable tcpdump interfaces:")
            for line in list_result.stdout.splitlines():
                print(f"  {line}")
        else:
            print("\ntcpdump interfaces: could not list interfaces")
            print(list_result.stderr.strip())

    if interface:
        print(f"\nSelected interface: {interface}")

    if check_doq:
        print("\nDoQ resolver connectivity:")
        try:
            from doq_resolver import check_doq_resolvers

            for result in check_doq_resolvers(resolver_names=[doq_resolver]):
                status = "OK" if result["ok"] else "FAILED"
                print(
                    f"  {result['name']}: {status} "
                    f"({result['host']}, SNI {result['server_name']})"
                )
        except Exception as exc:
            print(f"  Could not run DoQ connectivity check: {exc}")

    print("\nRecommended macOS command:")
    selected_interface = interface or "en0"
    print(
        "python3 src/main.py --mode batch "
        "--sites-file data/sites_sample.csv --protocols dns doh doq "
        "--repetitions 5 --web-repetitions 1 "
        f"--interface {selected_interface} --doq-resolver quad9"
    )
    print(
        "(no sudo needed if tcpdump already has BPF permissions on this "
        "machine - check first; using sudo makes files under results/ "
        "owned by root, which then breaks --mode analyze run without sudo)"
    )
