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

    ## to capture traffic from HTTP (port 80), HTTPS (port 443), DNS (port 53) and DoQ (port 853)


    if filter_rule:
        cmd.extend(filter_rule.split())

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return process


def stop_capture(process):
    process.terminate() # aqui ya se genera un archivo pcap que contiene todos los paquetes capturados 
    process.wait()