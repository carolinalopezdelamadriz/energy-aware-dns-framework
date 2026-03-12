import subprocess

def start_capture(output_file, filter_rule=None):

    cmd = [
    "tcpdump",
    "-i",
    "any",
    "-n",
    "-w",
    output_file,
    "port", "80",
    "or",
    "port", "443",
    "or",
    "port", "53",
    "or",
    "port", "853"
    ]

    if filter_rule:
        cmd.extend(filter_rule.split())

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return process


def stop_capture(process):
    process.terminate()
    process.wait()