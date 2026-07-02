import subprocess
import time


def _detect_default_interface():
    result = subprocess.run(
        ["route", "get", "default"],
        capture_output=True,
        text=True,
    )

    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split(":", 1)[1].strip()

    return "en0"


def start_capture(output_file, filter_rule=None, interface=None):
    interface = interface or _detect_default_interface()

    cmd = [
        "tcpdump",
        "-i",
        interface,
        "-n",
        "-U",
        "-w",
        output_file,
    ]

    if filter_rule:
        cmd.extend(filter_rule.split())
    else:
        # HTTP, HTTPS, classic DNS and DoQ
        cmd.extend(
            [
                "port",
                "80",
                "or",
                "port",
                "443",
                "or",
                "port",
                "53",
                "or",
                "port",
                "853",
            ]
        )

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    time.sleep(0.5)
    if process.poll() is not None:
        stderr = process.stderr.read() if process.stderr else ""
        raise RuntimeError(
            f"tcpdump could not start on interface '{interface}'. "
            f"Details: {stderr.strip()}"
        )

    return process


def stop_capture(process):
    process.terminate()  # the pcap file with all captured packets is already written at this point
    process.communicate()
