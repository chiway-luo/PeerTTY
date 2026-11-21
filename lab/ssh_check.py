"""Open one signed test session between the two lab VMs and verify its destination."""
from contextlib import ExitStack
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


CTL = str(Path(__file__).with_name("ctl"))


def endpoint(role, *args):
    return [CTL, "exec", role, *args]


def command(role, *args, **kwargs):
    return subprocess.run(endpoint(role, *args), text=True, capture_output=True,
                          check=True, timeout=30, **kwargs).stdout.strip()


def identity(role):
    script = """set -eu
umask 077
dir="$HOME/.local/share/peertty-lab"
mkdir -p "$dir"
exec 9>"$dir/keygen.lock"
flock 9
key="$dir/identity.key"
if [ ! -f "$key" ]; then peertty keygen -out "$key" >/dev/null; fi
printf '%s\\n' "$key"
peertty fingerprint -key "$key"
"""
    key, fingerprint = command(role, "sh", "-c", script).splitlines()
    return key, fingerprint


def exchange(sender, receiver, directories, name):
    # The management channel carries the signed offer/answer out of band.
    path = f"{directories[sender]}/{name}"
    read = 'until [ -s "$1" ]; do sleep 0.1; done; cat "$1"'
    ticket = command(sender, "timeout", "22", "sh", "-c", read, "lab", path)
    target = f"{directories[receiver]}/{name}"
    command(receiver, "sh", "-c", 'umask 077; cat > "$1"', "lab", target, input=ticket)
    return target


def cleanup(role, directory):
    # Only these two transient files are ever produced in the unique mktemp dir.
    command(role, "sh", "-c",
            'rm -f -- "$1/session.offer" "$1/session.answer" && rmdir -- "$1"',
            "lab", directory)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def check(mode):
    with ExitStack() as stack:
        dirs = {}
        for role in ("engineer", "device"):
            dirs[role] = command(role, "mktemp", "-d", "/tmp/peertty-check.XXXXXXXX")
            stack.callback(cleanup, role, dirs[role])
        operator, op_fp = identity("engineer")
        device, dev_fp = identity("device")
        if op_fp == dev_fp:
            raise ValueError("Both guests returned the same PeerTTY fingerprint")
        logs = [stack.enter_context(tempfile.TemporaryFile(mode="w+t")) for _ in range(2)]
        host_args = ["peertty", "host", "-key", device, "-peer", op_fp,
                     "-offer", dirs["device"] + "/session.offer", "-ttl", "2m"]
        proxy = ["peertty", "connect", "-key", operator, "-peer", dev_fp,
                 "-offer", dirs["engineer"] + "/session.offer",
                 "-answer", dirs["engineer"] + "/session.answer"]
        # Empty also works with earlier lab binaries and keeps routed tests local.
        host_args.extend(["-stun", "" if mode == "routed" else "stun:198.19.1.2:3478"])
        proxy.extend(["-stun", "" if mode == "routed" else "stun:198.19.2.2:3478"])
        try:
            host = subprocess.Popen(endpoint("device", "timeout", "120", *host_args),
                                    text=True, stdin=subprocess.PIPE, stdout=logs[0], stderr=logs[0])
            stack.callback(stop, host)
            exchange("device", "engineer", dirs, "session.offer")
            ssh = ["ssh", "-T", "-o", "ControlPath=none", "-o", "BatchMode=yes",
                   "-o", "ConnectTimeout=65", "-o", "IdentitiesOnly=yes",
                   "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=peertty-device",
                   "-o", "UserKnownHostsFile=~/.ssh/peertty-lab-known-hosts",
                   "-i", "~/.ssh/peertty-lab", "-o", "ProxyCommand=" + shlex.join(proxy),
                   "ptlab@peertty-device", "hostname && id -un"]
            client = subprocess.Popen(endpoint("engineer", "timeout", "90", *ssh), text=True,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=logs[1])
            stack.callback(stop, client)
            answer = exchange("engineer", "device", dirs, "session.answer")
            host.stdin.write(answer + "\n")
            host.stdin.close()
            output, _ = client.communicate(timeout=95)
            if client.returncode or output.splitlines() != ["lima-device", "ptlab"]:
                raise RuntimeError(f"SSH check failed (exit {client.returncode}, stdout {output!r})")
            print(output.strip())
        finally:
            for log in logs:
                log.seek(0)
                for line in log:
                    if line.startswith(("Share ", "Return ", "To grant ")):
                        continue
                    print(line.strip(), file=sys.stderr)


if __name__ == "__main__":
    try:
        check(sys.argv[1])
    except subprocess.CalledProcessError as exc:
        sys.exit(f"lab SSH fixture failed: {exc.stderr or exc.returncode}")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        sys.exit(str(exc))
