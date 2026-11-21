"""Exercise the terminal menus through native SSH on the two lab machines."""
from contextlib import ExitStack
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from ssh_check import command, endpoint, stop

LAB = Path(__file__).resolve().parent
STUN = {"engineer": "stun:198.19.2.2:3478", "device": "stun:198.19.1.2:3478"}
LAN = {"engineer": "10.77.1.2", "device": "10.77.2.2"}
WAN = {"engineer": "198.18.0.1", "device": "198.18.0.2"}
EXPIRY_SECONDS = 180


class Menu:
    def __init__(self, stack, role, directory, binary, arguments, prefix=()):
        self.log = stack.enter_context(tempfile.TemporaryFile())
        self.offset = 0
        self.process = subprocess.Popen(endpoint(
            role, *prefix, "env", f"XDG_CONFIG_HOME={directory}/config", f"TMPDIR={directory}/tmp",
            "timeout", "360", binary, *arguments),
            stdin=subprocess.PIPE, stdout=self.log, stderr=self.log)
        stack.callback(stop, self.process)

    def send(self, *lines):
        self.process.stdin.write(("\n".join(lines) + "\n").encode())
        self.process.stdin.flush()

    def expect(self, pattern, seconds=45):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            data = os.pread(self.log.fileno(), 256 * 1024, self.offset).decode(errors="replace")
            match = re.search(pattern, data)
            if match:
                self.offset += len(data[:match.end()].encode())
                return match
            if self.process.poll() is not None or "操作结束 ·" in data or "授权已到期。" in data:
                break
            time.sleep(0.1)
        # Never print full signed tickets in test logs.
        summary = [s[:240] for s in data.splitlines() if s.strip() and "{" not in s
                   and not s.startswith("本机指纹") and not re.fullmatch(r"[A-Za-z0-9+/=]+", s)]
        raise RuntimeError(f"menu did not reach {pattern!r}; recent output: {summary[-18:]}")

    def configure(self, stun):
        self.send("3", stun, "")
        self.expect("连接设置已应用")

    def ticket_text(self, label, file_contents):
        block = self.expect(label + r"\r?\n(-----BEGIN PEERTTY TICKET-----\r?\n"
                            r"[A-Za-z0-9+/=\r\n]+-----END PEERTTY TICKET-----)\r?\n")[1]
        payload = "".join(block.splitlines()[1:-1])
        if base64.b64decode(payload, validate=True).decode() != file_contents:
            raise RuntimeError("displayed ticket differs from its signed file")
        return "\n".join(block.splitlines())


def transfer(sender, source, receiver, dest):
    ticket = command(sender, "cat", source)
    command(receiver, "sh", "-c", 'umask 077; cat > "$1"', "exchange", dest, input=ticket)


def assert_busy(role, binary, key, extra):
    result = subprocess.run(endpoint(role, binary, extra[0], "-key", key, *extra[1:]),
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    if result.returncode == 0 or "已有一份授权" not in result.stderr:
        raise RuntimeError(f"{role}: concurrent role was not rejected by the identity lock")


def port22(target, state="listen"):
    args = ["-Hnlt"] if state == "listen" else ["-Hnt", "state", state]
    return command(target, "ss", *args, "sport = :22")


def system_fixture_dir(stack, role, binary):
    """Stage a protected test executable for a guest that will host on closed port 22."""
    rootdir = command(role, "sudo", "-n", "mktemp", "-d", "/usr/local/lib/peertty-menu.XXXXXXXX")
    if not re.fullmatch(r"/usr/local/lib/peertty-menu\.[A-Za-z0-9]{8}", rootdir):
        raise ValueError("unexpected guest fixture directory")
    stack.callback(command, role, "sudo", "-n", "rm", "-rf", "--", rootdir)
    source = binary if "/" in binary else command(role, "which", binary)
    command(role, "sudo", "-n", "install", "-m", "755", source, rootdir + "/peertty")
    command(role, "sudo", "-n", "chmod", "755", rootdir)
    return rootdir


def cold_fixture(stack, operator, target, control_dir, binary):
    """Give only this target process a test SSH policy in a private mount namespace."""
    if port22(target):
        raise RuntimeError(f"{target}: cold test needs an initially closed business port 22")
    username = command(target, "id", "-un")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", username) or username == "root":
        raise ValueError("expected a normal lab login account")
    rootdir = system_fixture_dir(stack, target, binary)
    conf = (f"Port 22\nListenAddress 127.0.0.1\nHostKey /etc/ssh/ssh_host_ed25519_key\n"
            f"AuthorizedKeysFile .ssh/authorized_keys\nAllowUsers {username}\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            "PermitRootLogin no\nUsePAM yes\nDisableForwarding yes\n")
    command(target, "sudo", "-n", "tee", rootdir + "/sshd_config", input=conf)
    public_host = command(target, "cat", "/etc/ssh/ssh_host_ed25519_key.pub").split()[:2]
    prefix = ("sudo", "-n", "unshare", "--mount", "--propagation", "private", "sh", "-ec",
              'mount --bind "$1" /etc/ssh/sshd_config; user=$2; shift 2; exec runuser -u "$user" -- "$@"',
              "test-sshd", rootdir + "/sshd_config", username)
    return rootdir + "/peertty", prefix, username, "", public_host


def private_endpoint(role):
    addresses = json.loads(command(role, "ip", "-j", "addr", "show"))
    global_ips = [a["local"] for nic in addresses for a in nic["addr_info"] if a["scope"] == "global"]
    default = json.loads(command(role, "ip", "-j", "-4", "route", "show", "default"))
    gateway = LAN[role].rpartition(".")[0] + ".1"
    if global_ips != [LAN[role]] or len(default) != 1 or default[0].get("gateway") != gateway:
        raise RuntimeError(f"{role}: business interface escaped its private LAN")


def check_ticket(role, ticket, mode, blocked):
    sdp = json.loads(ticket)["claims"]["sdp"]
    candidates = [s.split() for s in sdp.splitlines() if s.startswith("a=candidate:")]
    mapped = {c[4] for c in candidates if c[7] == "srflx"}
    if mapped != (set() if blocked else {WAN[role]}):
        raise RuntimeError(f"{role}: signed ticket has unexpected STUN mappings: {mapped}")
    if not any(c[7] == "host" and c[4] == LAN[role] for c in candidates):
        raise RuntimeError(f"{role}: private business address missing from signed ticket")
    if any(c[7] == "relay" for c in candidates):
        raise RuntimeError(f"{role}: unexpected relay candidate")
    for c in candidates:
        if c[7] == "srflx":
            local, mapped = int(c[c.index("rport") + 1]), int(c[5])
            if mode == "nat-remap" and mapped != (local ^ 256):
                raise RuntimeError(f"{role}: UDP port translation missing from ticket")
            if mode == "nat-dependent" and mapped != ((local & 16383) | 16384):
                raise RuntimeError(f"{role}: unexpected STUN port for destination-dependent NAT")


def check_sudo(operator, target, binary, key, username, allowed, window):
    """Exercise only id -u with the target lab account's existing sudo rules."""
    login_uid = command(target, "id", "-u", username)
    policy = subprocess.run(endpoint(target, "sudo", "-n", "-l", "-U", username, "-u", "root", "/usr/bin/id", "-u"),
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    if login_uid == "0" or (policy.returncode == 0) != allowed:
        raise RuntimeError(f"{target}: expected a normal test account with sudo allowed={allowed}")
    needs_password = False
    for flags, tty_check in (([], "test ! -t 0"), (["-t"], "test -t 0")):
        probe = f"{tty_check} || exit 98; /usr/bin/id -u; LC_ALL=C /usr/bin/sudo -n -u root -- /usr/bin/id -u"
        result = subprocess.run(endpoint(operator, binary, "link", "-key", key, *flags, "--", probe),
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=110)
        uids = [line for line in result.stdout.splitlines() if line.isdecimal()]
        expected = [login_uid, "0"] if allowed else [login_uid]
        if result.returncode != (0 if allowed else 1) or uids != expected:
            raise RuntimeError(f"{target}: {tty_check}, UID output {uids}, exit {result.returncode}: "
                               f"{result.stdout[-500:]} {result.stderr[-500:]}")
        if not flags and not allowed:
            needs_password = "a password is required" in result.stderr
    print(f"sudo policy: {username} (uid {login_uid}), allowed={allowed}; SSH command and PTY matched", flush=True)
    if needs_password:
        # The literal prompt appears only when sudo asks, not in the echoed command.
        window.send("LC_ALL=C /usr/bin/sudo -p 'PT_SUDO_''PASSWORD> ' -u root -- /usr/bin/id -u; "
                    "printf '\\nSUDO_EXIT_%s\\n' \"$?\"")
        window.expect("PT_SUDO_PASSWORD> ")
        window.process.stdin.write(b"\x04")  # EOF at sudo's password prompt
        window.process.stdin.flush()
        window.expect(r"\nSUDO_EXIT_1\r?\n")
        print("target sudo requested a password in the SSH terminal; cancelled with EOF, exit 1", flush=True)


def write_from_both_windows(resources, target, username, windows):
    # The login owns this file independently of the worker's own grant directory.
    # Both test accounts are unprivileged; management reads it again after SSH ends.
    as_user = ["sudo", "-n", "-u", username, "--"]
    path = command(target, *as_user, "mktemp", "/tmp/peertty-retained.XXXXXXXX")
    if not re.fullmatch(r"/tmp/peertty-retained\.[A-Za-z0-9]{8}", path):
        raise ValueError("unexpected guest test file")
    resources.callback(command, target, *as_user, "rm", "-f", "--", path)
    for index, window in enumerate(windows, 1):
        window.send(f"printf 'window-%s\\n' {index} >> {path} && printf 'WROTE_%s\\n' {index}")
        window.expect(rf"\nWROTE_{index}\r?\n")
    return path


def guest_clock(role):
    sample = command(role, "python3", "-c",
                     "import time; print(time.time_ns() // 1000000, time.monotonic_ns() // 1000000)")
    wall, monotonic = map(int, sample.split())
    return wall, monotonic


def deadline_offsets(expires_ms, timers):
    # Lima can step the guest wall clocks while the already-armed OS timers run.
    offsets = {}
    for role, deadline in timers.items():
        wall, monotonic = guest_clock(role)
        offsets[role] = (wall - expires_ms, monotonic - deadline)
    return offsets


def wait_near_expiry(expires_ms, timers, window):
    offsets = deadline_offsets(expires_ms, timers)
    remaining = -max(max(pair) for pair in offsets.values()) / 1000
    if not 5 < remaining <= EXPIRY_SECONDS:
        raise RuntimeError(f"expected two live terminals before expiry, {remaining:.1f}s left")
    print(f"waiting for signed expiry with both terminals open ({remaining:.1f}s left)", flush=True)
    try:
        window.process.wait(timeout=remaining - 5)
    except subprocess.TimeoutExpired:
        return
    raise RuntimeError("second SSH terminal exited before the grant deadline")


def check(mode, artifact, cold, ending, delay=0, fallback=False, outcome="open", verify_sudo=False):
    operator, target = ("device", "engineer") if cold else ("engineer", "device")
    nat = mode != "routed"
    failure = outcome in ("blocked", "incompatible")
    with ExitStack() as resources:
        dirs, programs = {}, {}
        for role in ("engineer", "device"):
            if nat:
                private_endpoint(role)
            d = command(role, "mktemp", "-d", "/tmp/peertty-menu.XXXXXXXX")
            if not re.fullmatch(r"/tmp/peertty-menu\.[A-Za-z0-9]{8}", d):
                raise ValueError("unexpected guest temp directory")
            dirs[role] = d
            resources.callback(command, role, "rm", "-rf", "--", d)
            command(role, "mkdir", "-m", "700", f"{d}/tmp")
            programs[role] = "peertty"
            if artifact:
                dest = f"{d}/peertty"
                subprocess.run(["limactl", "copy", "--backend=scp", artifact, f"{role}:{dest}"],
                               env=dict(os.environ, LIMA_HOME=str(LAB / ".lima")), check=True, timeout=60)
                command(role, "chmod", "700", dest)
                programs[role] = dest
        e, d = dirs[operator], dirs[target]
        if cold:
            programs[target], prefix, username, login, hostkey = cold_fixture(
                resources, operator, target, e, programs[target])
        else:
            # After login the operator switches to hosting with its own port 22 closed.
            programs[operator] = system_fixture_dir(resources, operator, programs[operator]) + "/peertty"
            prefix, username, login = (), "ptlab", "~/.ssh/peertty-lab"
            source = command(operator, "sh", "-c", 'cat "$HOME/.ssh/peertty-lab-known-hosts"')
            row = next(s.split() for s in source.splitlines() if s.startswith("peertty-device "))
            hostkey = row[1:3]
            service_pid = command(target, "systemctl", "show", "-p", "MainPID", "--value", "peertty-lab-sshd")
            if not port22(target) or int(service_pid) <= 0:
                raise RuntimeError("expected the existing lab SSH service")
        with ExitStack() as processes:
            # The device starts with no subcommand. All role selection is via stdin.
            for role in (operator, target):
                processes.callback(subprocess.run, endpoint(role, programs[role], "revoke", "-key",
                    f"{dirs[role]}/config/PeerTTY/device.key"), capture_output=True, timeout=20)
            host_args = []
            if failure:
                host_args = ["menu", "-ttl", "105s"]
            elif ending == "expire":
                host_args = ["menu", "-ttl", f"{EXPIRY_SECONDS}s"]
            device = Menu(processes, target, d, programs[target], host_args, prefix)
            control = Menu(processes, operator, e, programs[operator],
                           ["menu", "-ssh-config", f"{e}/ssh.conf"])
            device.expect("❯ ")
            control.expect("❯ ")
            # The menu learns these identities from the signed exchange.
            # The harness also uses them for the pinned CLI/role-lock check.
            device_fp = command(target, programs[target], "fingerprint", "-key", f"{d}/config/PeerTTY/device.key")
            control_fp = command(operator, programs[operator], "fingerprint", "-key", f"{e}/config/PeerTTY/device.key")
            if device_fp == control_fp:
                raise RuntimeError("devices returned the same identity")
            for menu, role in ((device, target), (control, operator)):
                spec = STUN[role] if nat else "-"
                if fallback:
                    # The observer listens only on 3478. The first server drops requests.
                    spec = spec.replace(":3478", ":3479") + "," + spec
                menu.configure(spec)

            device.send("5")
            readiness = "本机 22 端口已关闭，OpenSSH 配置检查通过" if cold else r"127\.0\.0\.1:22 的 SSH 服务可用"
            device.expect(readiness)
            device.expect("❯ ")
            if cold and port22(target):
                raise RuntimeError("checking host readiness started a listener")

            # Reuse the lab's pinned SSH host key, under the menu's device-specific alias.
            alias = "peertty-" + device_fp.removeprefix("sha256:")
            for name, content in (
                    ("known_hosts", f"{alias} {' '.join(hostkey)}\n"),
                    ("ssh.conf", f"Host *\n BatchMode yes\n StrictHostKeyChecking yes\n UserKnownHostsFile {e}/known_hosts\n")):
                command(operator, "sh", "-c", 'umask 077; cat > "$1"', "lab", f"{e}/{name}", input=content)

            device.send("2")
            device.expect(readiness)
            if ending == "expire":
                device.expect(r"授权时长[^\r\n]+> ")
                # The issuing worker starts its relative TTL after this input.
                _, start = guest_clock(target)
                timers = {target: start + EXPIRY_SECONDS * 1000}
            device.send("" if host_args else "24")
            offer = device.expect(r"邀请文件  ([^\r\n]+)\r?\n")[1]
            transfer(target, offer, operator, f"{e}/received.offer")
            offer_json = command(operator, "cat", f"{e}/received.offer")
            if nat:
                check_ticket(target, offer_json, mode, outcome == "blocked")
            displayed = device.ticket_text("邀请文本", offer_json)
            inputs = [displayed] if fallback else ["1", displayed]
            if ending == "expire":
                expires_ms = json.loads(offer_json)["claims"]["expires_ms"]
                # The controller converts the absolute signed deadline into a timer.
                wall, monotonic = guest_clock(operator)
                timers[operator] = monotonic + expires_ms - wall
            if cold:
                if len(base64.b64decode(json.loads(offer_json)["claims"].get("ssh_host_key", ""))) != 32:
                    raise RuntimeError("expected an offer for single-approval login")
                control.send(*inputs, "")
            else:
                control.send(*inputs, username, login)
            answer = control.expect(r"回执文件  ([^\r\n]+)\r?\n")[1]
            transfer(operator, answer, target, f"{d}/received.answer")
            answer_json = command(target, "cat", f"{d}/received.answer")
            if cold and len(base64.b64decode(json.loads(answer_json)["claims"].get("ssh_login_key", ""))) != 32:
                raise RuntimeError("missing one-use login key in signed answer")
            if json.loads(offer_json)["claims"].get("device_name") != f"lima-{target}" or \
                    json.loads(answer_json)["claims"].get("device_name") != f"lima-{operator}":
                raise RuntimeError("offer and answer did not carry their issuing devices' names")
            if nat:
                check_ticket(operator, answer_json, mode, outcome == "blocked")
            reply = control.ticket_text("回执文本", answer_json)
            assert_busy(target, programs[target], f"{d}/config/PeerTTY/device.key",
                        ["connect", "-peer", control_fp, "-offer", offer, "-answer", f"{d}/blocked.answer"])
            assert_busy(operator, programs[operator], f"{e}/config/PeerTTY/device.key",
                        ["host", "-peer", device_fp, "-offer", f"{e}/blocked.offer"])
            if cold and port22(target):
                raise RuntimeError("port 22 opened before local approval")
            if delay:
                time.sleep(delay)
            device.send(reply if cold else f"{d}/received.answer")
            device.expect("回执已核验")
            device.expect("y 批准本次连接")
            if cold and port22(target):
                raise RuntimeError("pasting a receipt opened port 22 without local approval")
            device.send("y")
            device.expect("已批准本次连接")
            if failure:
                count = "0" if outcome == "blocked" else "[1-9][0-9]*"
                device.expect(rf"未建立直连。被控方（[^）]*STUN 映射 {count}），控制方（[^）]*STUN 映射 {count}）", 75)
                control.expect(r"(?:操作结束|当前没有有效|本次授权已结束)", 75)
                if port22(target, "established") or (cold and port22(target)):
                    raise RuntimeError("SSH was reached without a direct path")
                for menu in (control, device):
                    menu.send("0")
                    if menu.process.wait(timeout=10):
                        raise RuntimeError("menu failed to exit after the negative test")
                detail = "no STUN mappings" if outcome == "blocked" else "STUN mappings on both sides"
                print(f"{outcome}: {detail}; no direct channel, port 22 remained closed")
                return
            host_route = device.expect(r"被控会话已连接 · ([^\r\n]+)\r?\n", 75)[1]
            route = control.expect(r"控制会话已连接 · ([^\r\n]+)\r?\n", 65)[1]
            if nat:
                for selected in (host_route, route):
                    if not re.fullmatch(r"udp (host|srflx|prflx)/(srflx|prflx)", selected):
                        raise RuntimeError(f"expected a translated UDP destination, selected {selected}")
                print(f"private endpoints {LAN[operator]} -> {LAN[target]}; selected {route} and {host_route}")
            control.send("test -t 0 && printf 'PTY_%s\\n' OK", "hostname", "id -un")
            try:
                control.expect(r"\nPTY_OK\r?\n", 100)
            except RuntimeError:
                print(command(target, programs[target], "status", "-key", f"{d}/config/PeerTTY/device.key"), flush=True)
                raise
            control.expect(r"\nlima-" + re.escape(target) + r"\r?\n")
            control.expect(r"\n" + re.escape(username) + r"\r?\n")
            if cold and ("127.0.0.1:22 " not in port22(target, "established") or port22(target)):
                raise RuntimeError("expected one loopback SSH connection and a closed listener")
            # Close the host UI while its first real SSH terminal is still open.
            device.process.stdin.close()
            if device.process.wait(timeout=10):
                raise RuntimeError("closing the menu failed")
            device = Menu(processes, target, d, programs[target], [], prefix)
            device.expect(r"被控端 · 已连接 · 1 个终端")
            other = Menu(processes, operator, e, programs[operator], ["link"])
            other.send("printf 'SECOND_%s\\n' OK")
            other.expect(r"\nSECOND_OK\r?\n", 100)
            device.send("/status")
            device.expect(r"被控端 · 已连接 · 2 个终端")
            key = f"{e}/config/PeerTTY/device.key"
            if verify_sudo:
                check_sudo(operator, target, programs[operator], key, username, allowed=cold, window=other)
            if ending == "exit":
                for window in (other, control):
                    window.send("exit")
                control.expect("控制会话已结束")
                if other.process.wait(timeout=20):
                    raise RuntimeError("second SSH terminal failed")
                control.send("0")
                control.process.wait(timeout=10)
                cmd=subprocess.run(endpoint(operator,programs[operator],"link","-key",key,"--","id","-un"),
                                   stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=110)
                if cmd.returncode or cmd.stdout.strip()!=username:
                    raise RuntimeError("command after closing all SSH windows returned the wrong account")
                control = Menu(processes, operator, e, programs[operator], [])
                control.expect("控制端 · 已连接")
            else:
                retained = write_from_both_windows(resources, target, username, (control, other))
                if ending == "expire":
                    wait_near_expiry(expires_ms, timers, other)
                device.send("/status")
                device.expect(r"被控端 · 已连接 · 2 个终端")
            if ending != "expire":
                device.send("/revoke")
                device.expect("本次授权已撤销")
            if ending != "exit":
                control.expect(r"(?:操作结束 · SSH 连接结束|控制会话已结束)")
                if other.process.wait(timeout=20) == 124:
                    raise RuntimeError("the lab timeout, not PeerTTY, closed the second terminal")
                if ending == "expire":
                    offsets = deadline_offsets(expires_ms, timers)
                    print(f"guest clocks at disconnect (wall, monotonic ms from deadline): {offsets}", flush=True)
                    if all(max(pair) < 0 for pair in offsets.values()):
                        raise RuntimeError("the SSH terminals closed before either guest reached its deadline")
            for role in (operator, target):
                until = time.monotonic() + 25
                role_key = f"{dirs[role]}/config/PeerTTY/device.key"
                while "没有有效" not in command(role, programs[role], "status", "-key", role_key):
                    if time.monotonic() >= until:
                        raise RuntimeError(f"{role} retained the ended grant")
                    time.sleep(0.3)
            rejected = subprocess.run(endpoint(operator, programs[operator], "link", "-key", key, "--", "id"),
                                      stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=12)
            if rejected.returncode == 0 or "没有有效" not in rejected.stderr:
                raise RuntimeError("new link did not report the ended grant")
            if ending != "exit":
                saved = command(target, "sudo", "-n", "-u", username, "--", "cat", "--", retained)
                if saved.splitlines() != ["window-1", "window-2"]:
                    raise RuntimeError("completed SSH edits did not survive the end of the grant")
                print(f"{ending}: two terminals closed, new link refused, both completed writes retained", flush=True)
            if control.process.poll() is not None:
                tail=os.pread(control.log.fileno(),2048,max(0,os.fstat(control.log.fileno()).st_size-2048)).decode(errors="replace")
                details=[line[:200] for line in tail.splitlines() if len(line)<200 and not re.fullmatch(r"[A-Za-z0-9+/=]+",line)]
                raise RuntimeError(f"controller menu exited after SSH with status {control.process.returncode}: {details[-12:]}")
            control.send("2", "")
            control.expect(r"邀请文件  [^\r\n]+\r?\n")
            control.send("q")
            control.expect("本次授权已撤销")
            for menu in (control, device):
                menu.send("0")
                if menu.process.wait(timeout=10) != 0:
                    raise RuntimeError("menu failed to exit")
            for role, temp in dirs.items():
                if command(role, "find", f"{temp}/tmp", "-maxdepth", "1", "-name", "peertty-*"):
                    raise RuntimeError(f"{role}: exchange directory still exists")
            if cold:
                if port22(target) or port22(target, "established"):
                    raise RuntimeError("temporary SSH still active after exit")
                end = {"exit": "exit", "revoke": "revocation", "expire": "expiry"}[ending]
                print(f"target port 22: closed before approval; one loopback connection; closed after {end}")
            elif service_pid != command(target, "systemctl", "show", "-p", "MainPID", "--value", "peertty-lab-sshd"):
                raise RuntimeError("pre-existing SSH listener was replaced")
            else:
                print(f"existing SSH listener retained PID {service_pid}")
            print(f"menu SSH: {route}; PTY_OK, lima-{target}, {username}")
            print("both opposite-role attempts rejected; role switch and revoke passed")


if __name__ == "__main__":
    check(sys.argv[1], sys.argv[2], sys.argv[3] == "closed", sys.argv[4],
          int(sys.argv[5]), sys.argv[6] == "fallback", sys.argv[7], "--check-sudo" in sys.argv[8:])
