"""Exercise the terminal menus through native SSH on the two lab machines."""
from contextlib import ExitStack
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import zlib

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
                   and "配对码" not in s and not s.startswith("本机指纹") and not re.fullmatch(r"[A-Za-z0-9+/=]+", s)]
        raise RuntimeError(f"menu did not reach {pattern!r}; recent output: {summary[-18:]}")

    def configure(self, stun):
        self.send("3", stun, "")
        self.expect("连接设置已应用")

    def ticket_text(self, label, file_contents):
        block = self.expect(label + r"\r?\n(-----BEGIN PEERTTY TICKET-----\r?\n"
                            r"[A-Za-z0-9+/=\r\n]+-----END PEERTTY TICKET-----)\r?\n")[1]
        payload = "".join(block.splitlines()[1:-1])
        data = base64.b64decode(payload, validate=True)
        if not data.lstrip().startswith(b"{"):
            decoder = zlib.decompressobj()
            data = decoder.decompress(data, 128 * 1024 + 1)
            if len(data) > 128 * 1024 or not decoder.eof or decoder.unused_data:
                raise RuntimeError("invalid compressed ticket in menu output")
        if data != file_contents.encode():
            raise RuntimeError("displayed ticket differs from its signed file")
        return "\n".join(block.splitlines())

    def expect_connected_terminals(self, role, count):
        # A status page is a snapshot. Ask again while streams finish opening or closing.
        deadline = time.monotonic() + 45
        pattern = rf"已连接 · {role}[^❯]{{0,500}}?已连终端\s+(\d+)\r?\n"
        while True:
            self.send("/status")
            match = self.expect(pattern, max(1, deadline - time.monotonic()))
            observed = int(match[1])
            if observed == count:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{role}: expected {count} connected terminals, observed {observed}")
            time.sleep(1)


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
            "PermitRootLogin no\nUsePAM yes\nDisableForwarding yes\nSubsystem sftp internal-sftp\n")
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


def tcp_listener(role, ticket, expected):
    sdp = json.loads(ticket)["claims"]["sdp"]
    rows = [line.split() for line in sdp.splitlines() if line.startswith("a=candidate:")]
    ports = {row[5] for row in rows if row[1] == "1" and row[2].lower() == "tcp"
             and row[4] == LAN[role] and row[7:10] == ["host", "tcptype", "passive"]}
    if len(ports) != int(expected):
        raise RuntimeError(f"{role}: unexpected signed TCP listeners on the business interface: {ports}")
    if ports:
        port, = ports
        if not command(role, "ss", "-Hnlt", "sport = :" + port):
            raise RuntimeError(f"{role}: signed TCP port {port} is not listening")
        return port


def check_tcp_closed(listeners):
    for role, port in listeners.items():
        if port and command(role, "ss", "-Hnlt", "sport = :" + port):
            raise RuntimeError(f"{role}: grant TCP listener {port} survived shutdown")


def check_tcp_socket(operator, accepting_role, port):
    sockets = command(operator, "ss", "-Hnt", "state", "established")
    for row in sockets.splitlines():
        ends = []
        for field in row.split()[-2:]:
            host, _, service = field.rpartition(":")
            ip = ipaddress.ip_address(host.strip("[]"))
            ends.append((str(getattr(ip, "ipv4_mapped", None) or ip), service))
        if {ip for ip, _ in ends} == set(LAN.values()) and (LAN[accepting_role], port) in ends:
            return
    raise RuntimeError(f"no established TCP socket matched the signed listener on {accepting_role}")


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


class GrantClockTrace:
    """Sample in the guest to retain wall steps that disappear between menu actions."""

    def __init__(self, stack, role, directory):
        self.log = stack.enter_context(tempfile.TemporaryFile())
        script = """
import os, sys, time
active = os.path.join(sys.argv[1], 'config/PeerTTY/device.key.active')
end = time.monotonic() + 360
seen = False
while os.path.isdir(sys.argv[1]) and time.monotonic() < end:
    live = os.path.exists(active)
    wall = time.time_ns()
    boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    print(int(live), wall, boot, time.monotonic_ns(), flush=True)
    if seen and not live:
        break
    seen |= live
    time.sleep(0.05)
"""
        process = subprocess.Popen(endpoint(role, "python3", "-c", script, directory),
                                   stdin=subprocess.DEVNULL, stdout=self.log)
        stack.callback(stop, process)

    def offsets(self, expires_ms, mono_deadline_ms):
        data = os.pread(self.log.fileno(), os.fstat(self.log.fileno()).st_size, 0)
        rows = [tuple(map(int, line.split())) for line in data.split(b"\n")[:-1]]
        live = [(wall, boot) for active, wall, boot, _ in rows if active]
        if not live:
            raise RuntimeError("no independent clock samples for the active grant")
        # Only wall observations during an active lease may shorten its budget.
        # Sample wall before boot so a descheduled probe cannot advance that bound.
        peak = max(wall - boot for wall, boot in live)
        _, wall, boot, mono = rows[-1]
        return ((wall - expires_ms * 1_000_000) // 1_000_000,
                mono // 1_000_000 - mono_deadline_ms,
                (boot + peak - expires_ms * 1_000_000) // 1_000_000)


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


def check_roaming(guest, windows, dirs, programs, offer, answer):
    roles = ("device", "engineer")
    keys = {r: f"{dirs[r]}/config/PeerTTY/device.key" for r in roles}

    def leases():
        return [(command(r, "cat", keys[r] + ".active"),
                 command(r, "sha256sum", file).split()[0]) for r, file in zip(roles, (offer, answer))]

    def addresses(role):
        return [a["local"] for nic in json.loads(command(role, "ip", "-j", "-4", "addr"))
                for a in nic["addr_info"] if a["scope"] == "global"]

    def shell_pid(window):
        window.send("printf 'ROAM_PID=%s\\n' \"$$\"")
        return window.expect(r"\nROAM_PID=(\d+)\r?\n", 35)[1]

    original = leases()
    pids = [shell_pid(w) for w in windows]
    if pids[0] == pids[1]:
        raise RuntimeError("expected two independent SSH shells")
    for role, new in zip(roles, ("10.78.2.2", "10.78.1.2")):
        old = addresses(role)
        if old != [LAN[role]]:
            raise RuntimeError(f"unexpected original addresses on {role}: {old}")
        guest(role, "roam-cut")
        if addresses(role):
            raise RuntimeError(f"{role} retained an alternate address before switching")
        if role == "engineer":
            # Exceed the established-stream timeout; both old shells must end.
            time.sleep(26)
        joined = time.monotonic()
        guest(role, "roam-join")
        if addresses(role) != [new] or "dev roam0" not in command(role, "ip", "route", "show", "default"):
            raise RuntimeError(f"{role} did not switch to the new network")
        if role == "device":
            if [shell_pid(w) for w in windows] != pids:
                raise RuntimeError("short handover replaced an existing SSH shell")
            print("two original SSH shell PIDs survived the device handover", flush=True)
        else:
            if windows[1].process.wait(timeout=10) == 0:
                raise RuntimeError("stalled SSH stream unexpectedly exited successfully")
        try:
            result = subprocess.run(endpoint("engineer", programs["engineer"], "link", "-key", keys["engineer"],
                "--", "hostname && id -un && ip -4 -o addr show dev roam0"),
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            for r in roles:
                print(r, command(r, programs[r], "status", "-key", keys[r]),
                      guest(r, "roam-count", stdout=subprocess.PIPE).stdout, flush=True)
            raise
        if result.returncode or "lima-device" not in result.stdout or "ptlab" not in result.stdout or "10.78.2.2/24" not in result.stdout:
            raise RuntimeError(f"SSH failed after switching {role}: {result.stdout} {result.stderr}")
        if leases() != original:
            raise RuntimeError("worker or signed grant changed during handover")
        if any("换网直连" not in command(r, programs[r], "status", "-key", keys[r]) for r in roles):
            raise RuntimeError("both workers must report the authenticated migrated path")
        counter = guest(role, "roam-count", stdout=subprocess.PIPE).stdout
        if not re.search(r"packets [1-9][0-9]* ", counter):
            raise RuntimeError(f"{role} sent no translated UDP traffic on its new gateway")
        print(f"{role}: {old[0]} -> {new} (WAN 198.18.1.{new.split('.')[2]}); new SSH verified hostname, user and device IP "
              f"in {time.monotonic() - joined:.1f}s after join; both workers and tickets identical", flush=True)
    command("device", programs["device"], "revoke", "-key", keys["device"])
    until = time.monotonic() + 15
    while any("没有有效" not in command(r, programs[r], "status", "-key", keys[r]) for r in roles):
        if time.monotonic() >= until:
            raise RuntimeError("revocation failed after both migrations")
        time.sleep(0.3)
    denied = subprocess.run(endpoint("engineer", programs["engineer"], "link", "-key", keys["engineer"], "--", "true"),
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=12)
    if denied.returncode == 0 or "没有有效" not in denied.stderr:
        raise RuntimeError("ended grant opened another terminal")
    print("revocation after migration ended both workers and refused a new SSH terminal", flush=True)


def check_third_identity(operator, target, dirs, programs, stun, username, invitation, pairing_code, approved, host, windows):
    def shell_pids():
        pids = []
        for window in windows:
            window.send("printf 'IDENTITY_PID=%s\\n' \"$$\"")
            pids.append(window.expect(r"\nIDENTITY_PID=(\d+)\r?\n", 45)[1])
        return pids

    original = shell_pids()
    if len(set(original)) != len(windows):
        raise RuntimeError("expected independent authorized shells")
    third_dir = f"{dirs[operator]}/third"
    third_key = f"{third_dir}/config/PeerTTY/device.key"
    command(operator, "mkdir", "-p", "-m", "700", f"{third_dir}/tmp")
    command(operator, "mkdir", "-p", "-m", "700", f"{third_dir}/config/PeerTTY")
    command(operator, "cp", f"{dirs[operator]}/config/PeerTTY/device.key", third_key)
    with ExitStack() as processes:
        binary = programs[operator]
        processes.callback(subprocess.run, endpoint(operator, binary, "revoke", "-key", third_key),
                           capture_output=True, timeout=20)
        third = Menu(processes, operator, third_dir, binary,
                     ["menu", "-stun", stun, "-ssh-config", "none", "-no-clipboard"])
        third.expect("❯ ")
        third.send("1", invitation, "0" * 32)
        third.expect("配对码与本次凭证不匹配")
        third.send("1", invitation, pairing_code, username)
        if not approved.get("ssh_login_key"):
            third.send("")  # The independent controller receives no SSH private key.
        reply_path = third.expect(r"回执文件  ([^\r\n]+)\r?\n")[1]
        reply_json = command(operator, "cat", reply_path)
        claims = json.loads(reply_json)["claims"]
        if (claims["issuer"] == approved["issuer"] or
                any(claims[k] != approved[k] for k in ("device_name", "session", "offer_digest", "recipient"))):
            raise RuntimeError("expected a different key on the same named machine answering the same invitation")
        reply_text = third.ticket_text("回执文本", reply_json)
        host.send("/host")
        host.expect("被控会话已连接")
        host.send(reply_text)
        host.expect("本次授权已绑定控制端，无法更换回执")
        host.send("b")
        result = subprocess.run(endpoint(operator, binary, "link", "-key", third_key, "--", "id", "-un"),
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        if result.returncode == 0 or result.stdout.strip() or "本机尚无已连接的控制授权" not in result.stderr:
            raise RuntimeError("unapproved identity did not receive the expected terminal refusal")
        if "等待被控方批准 · 0 个终端" not in command(operator, binary, "status", "-key", third_key):
            raise RuntimeError("independent identity left its own pending grant")
        command(target, "test", "!", "-e", f"{dirs[target]}/config/PeerTTY/known_peers.json")
        if approved.get("ssh_login_key"):
            owner_key = f"{dirs[operator]}/config/PeerTTY/device.key"
            home = command(target, "getent", "passwd", username).split(":")[5]
            for key in (third_key, owner_key):
                batch = subprocess.run(endpoint(operator, binary, "sftp", "-key", key, "-b", "-"),
                                       input="pwd\nquit\n", capture_output=True, text=True, timeout=100)
                if key == owner_key:
                    if batch.returncode or f"Remote working directory: {home}" not in batch.stdout:
                        raise RuntimeError(f"authorized batch SFTP failed: {batch.stderr[-300:]}")
                elif batch.returncode == 0 or batch.stdout.strip() or "本机尚无已连接的控制授权" not in batch.stderr:
                    raise RuntimeError("unapproved identity did not receive the expected SFTP refusal")
            print("scoped batch SFTP: independent identity refused; authorized identity read its home directory", flush=True)
    host.expect_connected_terminals("被控端", 2)
    if shell_pids() != original:
        raise RuntimeError("an authorized shell changed during the identity check")
    print(f"cloned legacy key: wrong pairing code and replacement receipt refused, link exit {result.returncode}, "
          f"0 terminals, no persistent trust; original shell PIDs {', '.join(original)} continued", flush=True)


def check(mode, artifact, cold, ending, delay=0, fallback=False, outcome="open", verify_sudo=False,
          roam=None, before_connect=False, verify_identity=False, expected_protocol=None, udp_only_peer=None,
          accepting_role=None):
    operator, target = ("device", "engineer") if cold else ("engineer", "device")
    nat = mode != "routed"
    failure = outcome in ("blocked", "incompatible")
    with ExitStack() as resources:
        dirs, programs, listeners = {}, {}, {}
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
            binary = udp_only_peer[1] if udp_only_peer and role == udp_only_peer[0] else artifact
            if binary:
                dest = f"{d}/peertty"
                subprocess.run(["limactl", "copy", "--backend=scp", binary, f"{role}:{dest}"],
                               env=dict(os.environ, LIMA_HOME=str(LAB / ".lima")), check=True, timeout=60)
                command(role, "chmod", "700", dest)
                programs[role] = dest
                if expected_protocol:
                    digest = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
                    if command(role, "sha256sum", dest).split()[0] != digest:
                        raise RuntimeError(f"{role}: binary differs from local build")
        if (roam or verify_identity) and artifact:
            digest = hashlib.sha256(Path(artifact).read_bytes()).hexdigest()
            if any(command(r, "sha256sum", p).split()[0] != digest for r, p in programs.items()):
                raise RuntimeError("the lab guests did not receive the same local build")
            print("both guests running Linux ARM64 build", digest, flush=True)
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
            if verify_identity:
                keys = {r: f"{dirs[r]}/config/PeerTTY/device.key" for r in (target, operator)}
                for role, key_path in keys.items():
                    idle = Menu(processes, role, dirs[role], programs[role], ["menu", "-stun", "none"])
                    idle.send("/quit")
                    if idle.process.wait(timeout=10) != 0:
                        raise RuntimeError("fresh menu failed")
                    command(role, "test", "!", "-e", key_path)
                command(operator, programs[operator], "keygen", "-out", keys[operator])
                transfer(operator, keys[operator], target, keys[target])
                if command(target, programs[target], "fingerprint", "-key", keys[target]) != command(
                        operator, programs[operator], "fingerprint", "-key", keys[operator]):
                    raise RuntimeError("factory image fixture keys differ")
                print("clean menu created no device key; starting both peers from identical legacy image keys", flush=True)
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
            for menu, role in ((device, target), (control, operator)):
                spec = STUN[role] if nat else "-"
                if fallback:
                    # The observer listens only on 3478. The first server drops requests.
                    spec = spec.replace(":3478", ":3479") + "," + spec
                menu.configure(spec)

            device.send("5")
            readiness = "本机 22 端口已关闭，临时 SSH 配置检查通过" if cold else r"127\.0\.0\.1:22 的 SSH 服务可用"
            device.expect(readiness)
            device.expect("❯ ")
            if cold and port22(target):
                raise RuntimeError("checking host readiness started a listener")

            device.send("2")
            device.expect(readiness)
            if ending == "expire":
                device.expect(r"授权时长[^\r\n]+> ")
                traces = {role: GrantClockTrace(processes, role, dirs[role]) for role in (target, operator)}
                # The issuing worker starts its relative TTL after this input.
                _, start = guest_clock(target)
                timers = {target: start + EXPIRY_SECONDS * 1000}
            device.send("" if host_args else "24")
            offer = device.expect(r"邀请文件  ([^\r\n]+)\r?\n")[1]
            transfer(target, offer, operator, f"{e}/received.offer")
            offer_json = command(operator, "cat", f"{e}/received.offer")
            # Reuse the lab's pinned SSH host key, under the menu's device-specific alias.
            alias = "peertty-" + hashlib.sha256(base64.b64decode(json.loads(offer_json)["claims"]["issuer"])).hexdigest()
            for name, content in (
                    ("known_hosts", f"{alias} {' '.join(hostkey)}\n"),
                    ("ssh.conf", f"Host *\n BatchMode yes\n StrictHostKeyChecking yes\n UserKnownHostsFile {e}/known_hosts\n")):
                command(operator, "sh", "-c", 'umask 077; cat > "$1"', "lab", f"{e}/{name}", input=content)

            pairing_code = device.expect(r"一次性配对码\s+([A-F0-9]{8}(?:-[A-F0-9]{8}){3})")[1]
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
                control.send(*inputs, pairing_code, "")
            else:
                control.send(*inputs, pairing_code, username, login)
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
            if expected_protocol:
                for role, ticket in ((operator, answer_json), (target, offer_json)):
                    listeners[role] = tcp_listener(role, ticket, not udp_only_peer or role != udp_only_peer[0])
            reply = control.ticket_text("回执文本", answer_json)
            assert_busy(target, programs[target], f"{d}/config/PeerTTY/device.key",
                        ["connect", "-offer", offer, "-answer", f"{d}/blocked.answer"])
            assert_busy(operator, programs[operator], f"{e}/config/PeerTTY/device.key",
                        ["host", "-offer", f"{e}/blocked.offer"])
            if cold and port22(target):
                raise RuntimeError("port 22 opened before local approval")
            if delay:
                time.sleep(delay)
            device.send(reply if cold else f"{d}/received.answer")
            device.expect("回执已核验")
            device.expect("y 批准本次连接")
            if expected_protocol and port22(target, "established"):
                raise RuntimeError("SSH session opened before local approval")
            if cold and port22(target):
                raise RuntimeError("pasting a receipt opened port 22 without local approval")
            if before_connect:
                roam(target, "roam-cut")
            device.send("y")
            device.expect("已批准本次连接")
            if before_connect:
                device.expect("授权期内继续等待可达路径", 76)
                roam(target, "roam-join")
                print("device joined a new subnet after the first minute of an approved grant with no initial route", flush=True)
            if failure:
                count = "0" if outcome == "blocked" else "[1-9][0-9]*"
                device.expect(rf"未建立直连。被控方（[^）]*映射候选 {count}），控制方（[^）]*映射候选 {count}）", 75)
                control.expect(r"(?:操作结束|当前没有有效|本次授权已结束)", 75)
                if port22(target, "established") or (cold and port22(target)):
                    raise RuntimeError("SSH was reached without a direct path")
                for menu in (control, device):
                    menu.send("0")
                    if menu.process.wait(timeout=10):
                        raise RuntimeError("menu failed to exit after the negative test")
                check_tcp_closed(listeners)
                detail = "no STUN mappings" if outcome == "blocked" else "STUN mappings on both sides"
                print(f"{outcome}: {detail}; no direct channel, port 22 remained closed")
                return
            host_route = device.expect(r"被控会话已连接 · ([^\r\n]+)\r?\n", 75)[1]
            route = control.expect(r"控制会话已连接 · ([^\r\n]+)\r?\n", 65)[1]
            if expected_protocol:
                for selected in (route, host_route):
                    if not re.fullmatch(expected_protocol + r" (host|srflx|prflx)/(host|srflx|prflx)", selected):
                        raise RuntimeError(f"expected direct {expected_protocol}, selected {selected}")
                if expected_protocol == "tcp":
                    check_tcp_socket(operator, accepting_role, listeners[accepting_role])
                print(f"selected operator={route}, target={host_route}", flush=True)
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
            device.expect_connected_terminals("被控端", 1)
            other = Menu(processes, operator, e, programs[operator], ["link"])
            other.send("printf 'SECOND_%s\\n' OK")
            other.expect(r"\nSECOND_OK\r?\n", 100)
            device.expect_connected_terminals("被控端", 2)
            key = f"{e}/config/PeerTTY/device.key"
            if verify_identity:
                check_third_identity(operator, target, dirs, programs, STUN[operator] if nat else "none",
                                     username, displayed, pairing_code, json.loads(answer_json)["claims"], device, (control, other))
            if before_connect:
                result = command(operator, programs[operator], "link", "-key", key, "--", "ip -4 -o addr show dev roam0")
                if "10.78.2.2/24" not in result or "换网直连" not in command(operator, programs[operator], "status", "-key", key):
                    raise RuntimeError("first SSH terminal did not use the device's new network")
                print("first connection and two SSH windows reached 10.78.2.2 under the original approved exchange", flush=True)
            elif roam:
                check_roaming(roam, (control, other), dirs, programs, offer, answer)
                return
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
                control.expect("已连接 · 控制端")
            else:
                retained = write_from_both_windows(resources, target, username, (control, other))
                if ending == "expire":
                    wait_near_expiry(expires_ms, timers, other)
                device.expect_connected_terminals("被控端", 2)
            if ending != "expire":
                device.send("/revoke")
                device.expect("本次授权已撤销")
            if ending != "exit":
                # Revocation can close the local status socket while the menu
                # redraws. Confirm actual grant, terminal and socket teardown below.
                control.expect(r"(?:操作结束 · SSH 连接结束|控制会话已结束|当前没有有效的 PeerTTY 授权|"
                               r"read tcp4 127\.0\.0\.1:\d+->127\.0\.0\.1:\d+: (?:read: )?connection reset by peer)")
                if other.process.wait(timeout=20) == 124:
                    raise RuntimeError("the lab timeout, not PeerTTY, closed the second terminal")
                if ending == "expire":
                    offsets = {r: trace.offsets(expires_ms, timers[r]) for r, trace in traces.items()}
                    print(f"guest clocks at disconnect (wall, monotonic, suspend-aware with wall steps; "
                          f"ms from deadline): {offsets}", flush=True)
                    if all(max(pair) < 0 for pair in offsets.values()):
                        raise RuntimeError("the SSH terminals closed before either guest reached its deadline")
            for role in (operator, target):
                until = time.monotonic() + 25
                role_key = f"{dirs[role]}/config/PeerTTY/device.key"
                while "没有有效" not in command(role, programs[role], "status", "-key", role_key):
                    if time.monotonic() >= until:
                        raise RuntimeError(f"{role} retained the ended grant")
                    time.sleep(0.3)
                # The status listener closes before the worker finishes releasing its streams and lease.
                command(role, "sh", "-c", 'exec 9<"$1" && flock -s -w 12 9',
                        "lab", role_key + ".peertty/grant.lock")
            rejected = subprocess.run(endpoint(operator, programs[operator], "link", "-key", key, "--", "id"),
                                      stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=12)
            if rejected.returncode == 0 or "没有有效" not in rejected.stderr:
                raise RuntimeError("new link did not report the ended grant")
            check_tcp_closed(listeners)
            if expected_protocol and port22(target, "established"):
                raise RuntimeError("SSH connection survived the end of the grant")
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
            next_offer = control.expect(r"邀请文件  ([^\r\n]+)\r?\n")[1]
            next_code = control.expect(r"一次性配对码\s+([A-F0-9]{8}(?:-[A-F0-9]{8}){3})")[1]
            new_claims = json.loads(command(operator, "cat", next_offer))["claims"]
            if next_code == pairing_code or new_claims["issuer"] == json.loads(answer_json)["claims"]["issuer"]:
                raise RuntimeError("new grant reused the code or session signer")
            control.send(reply)
            control.expect("回执无效")
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
          int(sys.argv[5]), sys.argv[6] == "fallback", sys.argv[7], "--check-sudo" in sys.argv[8:],
          verify_identity="--check-identity" in sys.argv[8:])
