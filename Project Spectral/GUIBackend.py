import subprocess

def run_command(command):
    return subprocess.run(command, shell=True, text=True, capture_output=True).stdout.strip()

