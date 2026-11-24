"""Open one signed test session between the two lab VMs and verify its destination."""
from contextlib import ExitStack
from pathlib import Path
import hashlib
import os
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import time


CTL = str(Path(__file__).with_name("ctl"))


def endpoint(role, *args):
    return [CTL, "exec", role, *args]


def command(role, *args, **kwargs):
    return subprocess.run(endpoint(role, *args), text=True, capture_output=True,
                          check=True, timeout=30, **kwargs).stdout.strip()


def check_direct(expect_open):
    # The ordinary PeerTTY backend binds loopback only. Give plain SSH a
    # temporary listener on the isolated business interface for a fair control.
    address = "10.77.2.2"
    port = command("device", "python3", "-c",
                   "import socket; s=socket.socket(); s.bind(('10.77.2.2',0)); print(s.getsockname()[1])")
    unit = "peertty-direct-check-" + secrets.token_hex(6)
    args = ["env", "LC_ALL=C", "ssh", "-T", "-p", port, "-o", "ControlPath=none", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=3", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "HostKeyAlias=peertty-device", "-o", "UserKnownHostsFile=~/.ssh/peertty-lab-known-hosts",
            "-i", "~/.ssh/peertty-lab", "ptlab@10.77.2.2", "hostname && id -un"]
    command("device", "sudo", "-n", "systemd-run", "--quiet", "--collect", "--unit=" + unit,
            "--property=NetworkNamespacePath=/run/netns/pt-app", "--property=RuntimeMaxSec=45s",
            "/usr/sbin/sshd", "-D", "-e", "-f", "/etc/peertty-lab/sshd_config", "-p", port,
            "-o", "ListenAddress=" + address, "-o", "PidFile=none")
    try:
        until = time.monotonic() + 6
        while address + ":" + port not in command("device", "ss", "-Hnlt", "sport = :" + port):
            if time.monotonic() >= until:
                raise RuntimeError("temporary direct OpenSSH listener did not start")
            time.sleep(0.1)
        result = subprocess.run(endpoint("engineer", *args), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=12)
    finally:
        command("device", "sudo", "-n", "systemctl", "stop", unit)
    if expect_open:
        if result.returncode or result.stdout.splitlines() != ["lima-device", "ptlab"]:
            raise RuntimeError("direct OpenSSH did not reach the expected device account")
        print("direct SSH to device business interface: lima-device, ptlab", flush=True)
    elif result.returncode != 255 or "timed out" not in result.stderr.lower():
        raise RuntimeError("direct OpenSSH did not encounter the expected blocked device port")
    else:
        print("direct SSH to device business interface: timed out", flush=True)


def exchange(sender, receiver, directories, name):
    # The management channel carries the signed offer/answer out of band.
    path = f"{directories[sender]}/{name}"
    read = 'until [ -s "$1" ]; do sleep 0.1; done; cat "$1"'
    ticket = command(sender, "timeout", "22", "sh", "-c", read, "lab", path)
    target = f"{directories[receiver]}/{name}"
    command(receiver, "sh", "-c", 'umask 077; cat > "$1"', "lab", target, input=ticket)
    return target


def cleanup(role, directory):
    # The profile contains only this test grant and its role lock.
    command(role, "sh", "-c",
            'rm -f -- "$1/session.offer" "$1/session.answer" "$1/code" "$1/peertty" "$1/profile.peertty/grant.lock"; rmdir -- "$1/profile.peertty" 2>/dev/null || true; rmdir -- "$1"',
            "lab", directory)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def check(mode, binary=None, force_stun=False, expected_protocol=None):
    with ExitStack() as stack:
        dirs, programs = {}, {}
        for role in ("engineer", "device"):
            dirs[role] = command(role, "mktemp", "-d", "/tmp/peertty-check.XXXXXXXX")
            stack.callback(cleanup, role, dirs[role])
            programs[role] = "peertty"
            if binary:
                dest = dirs[role] + "/peertty"
                subprocess.run(["limactl", "copy", "--backend=scp", binary, f"{role}:{dest}"], check=True,
                               env=dict(os.environ, LIMA_HOME=str(Path(CTL).parent / ".lima")), timeout=60)
                command(role, "chmod", "700", dest)
                if command(role, "sha256sum", dest).split()[0] != hashlib.sha256(Path(binary).read_bytes()).hexdigest():
                    raise RuntimeError(f"{role}: incorrect ProxyCommand test build")
                programs[role] = dest
        logs = [stack.enter_context(tempfile.TemporaryFile(mode="w+t")) for _ in range(2)]
        host_args = [programs["device"], "host", "-key", dirs["device"] + "/profile",
                     "-offer", dirs["device"] + "/session.offer", "-ttl", "2m"]
        proxy = [programs["engineer"], "connect", "-key", dirs["engineer"] + "/profile", "-code-file", dirs["engineer"] + "/code",
                 "-offer", dirs["engineer"] + "/session.offer",
                 "-answer", dirs["engineer"] + "/session.answer"]
        stun = mode != "routed" or force_stun
        host_args.extend(["-stun", "stun:198.19.1.2:3478" if stun else "none"])
        proxy.extend(["-stun", "stun:198.19.2.2:3478" if stun else "none"])
        try:
            host = subprocess.Popen(endpoint("device", "timeout", "120", *host_args),
                                    text=True, stdin=subprocess.PIPE, stdout=logs[0], stderr=logs[0])
            stack.callback(stop, host)
            exchange("device", "engineer", dirs, "session.offer")
            for _ in range(100):
                log = os.pread(logs[0].fileno(), 8192, 0).decode()
                code = re.search(r"Pairing code \(deliver separately\): ([0-9A-F-]+)", log)
                if code:
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("Host did not display the code for this offer")
            command("engineer", "sh", "-c", 'umask 077; cat > "$1"', "lab", dirs["engineer"] + "/code",
                    input=code[1])
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
            if expected_protocol:
                for log in logs:
                    log.seek(0)
                    if not re.search(r"Direct path established \(" + expected_protocol + r" (host|srflx|prflx)/(host|srflx|prflx)\)", log.read()):
                        raise RuntimeError(f"ProxyCommand did not establish the expected {expected_protocol} path")
            print(output.strip())
        finally:
            for log in logs:
                log.seek(0)
                for line in log:
                    if line.startswith(("Share ", "Return ", "To grant ", "Pairing code ")):
                        continue
                    print(line.strip(), file=sys.stderr)


if __name__ == "__main__":
    try:
        check(sys.argv[1])
    except subprocess.CalledProcessError as exc:
        sys.exit(f"lab SSH fixture failed: {exc.stderr or exc.returncode}")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        sys.exit(str(exc))
