#!/usr/bin/env python3
"""Build the PeerTTY terminal binaries and native, offline installers."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging"
ARCHES = ("amd64", "arm64")


def run(*args, cwd=None, env=None):
    subprocess.run(args, cwd=cwd, env=env, check=True)


def binaries(work, system, version):
    result = {}
    for arch in ARCHES:
        suffix = ".exe" if system == "windows" else ""
        binary = work / f"peertty-{system}-{arch}{suffix}"
        env = dict(os.environ, GOOS=system, GOARCH=arch, CGO_ENABLED="0")
        run("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
            "-ldflags", f"-s -w -X main.version={version}", "-o", binary, "./cmd/peertty",
            cwd=ROOT, env=env)
        result[arch] = binary
    return result


def macos(work, packages, version, built):
    payload = work / "mac-payload"
    payload.mkdir()
    binary = payload / "peertty"
    run("lipo", "-create", *built.values(), "-output", binary)
    binary.chmod(0o755)
    run("codesign", "--force", "--sign", "-", "--identifier", "io.peertty.cli", binary)
    # /usr/local/bin can be user-managed. Keep the actual program on an
    # administrator-owned path so the local SSH guard can obtain permission.
    launcher = work / "mac-launcher"
    launcher.mkdir()
    entry = launcher / "peertty"
    entry.write_text('#!/bin/sh\nexec /Library/PeerTTY/peertty "$@"\n', encoding="ascii")
    entry.chmod(0o755)
    for folder, location, component in ((payload, "/Library/PeerTTY", "core"), (launcher, "/usr/local/bin", "cli")):
        run("pkgbuild", "--root", folder, "--install-location", location, "--identifier", f"io.peertty.{component}",
            "--version", version, "--ownership", "recommended", work / f"{component}.pkg")
    run("productbuild", "--distribution", PACKAGING / "macos-distribution.xml", "--package-path", work,
        packages / "PeerTTY-macOS.pkg")
    shutil.copyfile(PACKAGING / "install-macos-user.sh", packages / "install-macos-user.sh")


def linux(work, packages, version, built):
    for arch, binary in built.items():
        stage = work / f"linux-{arch}"
        stage.mkdir()
        shutil.copy2(binary, stage / "peertty")
        shutil.copyfile(PACKAGING / "linux.yaml", stage / "nfpm.yaml")
        env = dict(os.environ, PEERTTY_VERSION=version, PEERTTY_ARCH=arch)
        rpm_arch = {"amd64": "x86_64", "arm64": "aarch64"}[arch]
        for fmt, name in (("deb", f"peertty_{arch}.deb"), ("rpm", f"peertty.{rpm_arch}.rpm")):
            run("nfpm", "package", "--packager", fmt, "--target", packages / name,
                cwd=stage, env=env)


def windows(work, packages, version, built):
    for arch, binary in built.items():
        stage = work / f"windows-{arch}"
        stage.mkdir()
        shutil.copy2(binary, stage / "peertty.exe")
        shutil.copyfile(PACKAGING / "windows.wxs", stage / "peertty.wxs")
        label, platform = ("x64", "x64") if arch == "amd64" else ("ARM64", "Arm64")
        msi = packages / f"PeerTTY-Windows-{label}.msi"
        product = uuid.uuid5(uuid.NAMESPACE_URL, f"urn:peertty:product:{arch}:{version}")
        component = uuid.uuid5(uuid.NAMESPACE_URL, f"urn:peertty:component:cli:{arch}")
        run("wixl", "-a", "x64", "-D", f"ProductCode={product}", "-D", f"ComponentCode={component}",
            "-D", f"Version={version}", "-o", msi, "peertty.wxs", cwd=stage)
        # wixl 0.106 emits only x64 64-bit templates and omits the uninstall
        # flag on a non-permanent PATH row. Author both fields explicitly.
        (stage / "Environment.idt").write_bytes(
            b"Environment\tName\tValue\tComponent_\r\ns72\tl64\tL255\ts72\r\n"
            b"Environment\tEnvironment\r\nPeerTTYPath\t=-Path\t[~];[INSTALLDIR]\tCli\r\n")
        run("msibuild", msi, "-i", "Environment.idt", cwd=stage)
        if arch == "arm64":
            run("msibuild", msi, "-s", "PeerTTY", "PeerTTY Project", f"{platform};1033",
                "{" + str(uuid.uuid4()).upper() + "}", cwd=stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("all", "macos", "linux", "windows"), default="all")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--version", default=(ROOT / "VERSION").read_text().strip(),
                        help="release version; defaults to VERSION")
    args = parser.parse_args()
    if not re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", args.version, re.ASCII):
        parser.error("expected a numeric major.minor.patch version")
    if any(int(n) > limit for n, limit in zip(args.version.split("."), (255, 255, 65535))):
        parser.error("version exceeds Windows Installer limits")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    targets = {"macos": ("darwin", macos), "linux": ("linux", linux), "windows": ("windows", windows)}
    with tempfile.TemporaryDirectory(prefix=".peertty-build-", dir=output) as tmp:
        work = Path(tmp)
        packages = work / "packages"
        packages.mkdir()
        all_binaries = []
        for target, (system, package) in targets.items():
            if args.target not in ("all", target):
                continue
            built = binaries(work, system, args.version)
            package(work, packages, args.version, built)
            all_binaries.extend(built.values())
        release = output / "installers" / args.version
        release.mkdir(parents=True, exist_ok=True)
        for binary in all_binaries:
            binary.replace(output / binary.name)
        for artifact in packages.iterdir():
            artifact.replace(release / artifact.name)
        sums = []
        for path in sorted(release.iterdir()):
            installer = path.suffix in (".pkg", ".deb", ".rpm", ".msi") or path.name == "install-macos-user.sh"
            if installer and path.is_file():
                sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
        manifest = work / "SHA256SUMS"
        manifest.write_text("".join(sums), encoding="ascii")
        manifest.replace(release / manifest.name)
    print(release)


if __name__ == "__main__":
    main()
