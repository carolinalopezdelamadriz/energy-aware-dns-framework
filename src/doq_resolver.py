import subprocess

def resolve_doq(domain):

    subprocess.run([
    "kdig",
    "@1.1.1.1",
    "+quic",
    domain
    ])