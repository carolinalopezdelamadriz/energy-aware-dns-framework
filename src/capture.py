import subprocess

def start_capture(output_file):
    process = subprocess.Popen(
       # ["sudo", "tcpdump", "-i", "en0", "-w", output_file],
       ["tcpdump", "-i", "en0", "-w", output_file]
    )
    return process

# sudo .venv/bin/python src/main.py

def stop_capture(process):
    process.terminate()
    process.wait()