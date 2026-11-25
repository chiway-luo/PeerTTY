"""Stage CI-built installers for RPM signing and update an existing draft release."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess

RPMS = ("peertty.x86_64.rpm", "peertty.aarch64.rpm")
OTHER = {"PeerTTY-macOS.pkg", "install-macos-user.sh", "peertty_amd64.deb", "peertty_arm64.deb",
         "PeerTTY-Windows-x64.msi", "PeerTTY-Windows-ARM64.msi"}
PUBLIC = Path(__file__).resolve().parent / "keys" / "peertty-rpm.asc"


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def rpm_content(path):
    # The mutable RPM signature header follows the 96-byte lead. The aligned
    # main header and payload must remain identical to the tested package.
    with path.open("rb") as stream:
        if stream.read(4) != b"\xed\xab\xee\xdb":
            raise ValueError(f"Invalid RPM lead in {path.name}")
        stream.seek(96)
        if stream.read(8) != b"\x8e\xad\xe8\x01\0\0\0\0":
            raise ValueError(f"Invalid RPM signature header in {path.name}")
        count, size = struct.unpack(">II", stream.read(8))
        offset = (stream.tell() + count * 16 + size + 7) // 8 * 8
        if offset >= path.stat().st_size:
            raise ValueError(f"Missing RPM payload in {path.name}")
        stream.seek(offset)
        return hashlib.file_digest(stream, "sha256").hexdigest()


def manifest(folder, names):
    return "".join(f"{digest(folder / name)}  {name}\n" for name in sorted(names))


def draft(tag, installers):
    release = json.loads(gh("release", "view", tag, "--json", "databaseId,isDraft,tagName,assets"))
    if release["tagName"] != tag or not release["isDraft"]:
        raise ValueError(f"{tag} must be an existing draft")
    assets = {a["name"]: a.get("digest") for a in release["assets"]}
    if not (OTHER <= assets.keys() <= OTHER.union(RPMS, {"SHA256SUMS", PUBLIC.name})):
        raise ValueError("Unexpected draft asset set")
    for name in OTHER:
        if assets[name] != "sha256:" + digest(installers / name):
            raise ValueError(f"Draft asset differs from the tagged installer build: {name}")
    return release["databaseId"], assets


def prepare(tag, run_id, work):
    if not run_id or not run_id.isdecimal():
        raise ValueError("Expected an installer workflow run ID")
    sha = subprocess.check_output(["git", "rev-parse", f"{tag}^{{commit}}"], text=True).strip()
    subprocess.run(["git", "merge-base", "--is-ancestor", sha, "HEAD"], check=True)
    version = subprocess.check_output(["git", "show", sha + ":VERSION"], text=True).strip()
    run = json.loads(gh("api", f"repos/{os.environ['GH_REPO']}/actions/runs/{run_id}"))
    if (version != tag[1:] or run["head_sha"] != sha or run["head_branch"] != tag or
            run["path"] != ".github/workflows/installers.yml" or run["event"] != "workflow_dispatch"):
        raise ValueError("Installer run does not belong to the requested release tag")
    jobs = json.loads(gh("run", "view", run_id, "--json", "jobs"))["jobs"]
    if not any(j["name"] == "build" and j["conclusion"] == "success" for j in jobs):
        raise ValueError("The installer build job must have succeeded")
    work.mkdir()
    installers = work / "installers"
    gh("run", "download", run_id, "--name", "installers", "--dir", str(installers))
    names = OTHER.union(RPMS)
    if {p.name for p in installers.iterdir()} != names | {"SHA256SUMS"}:
        raise ValueError("Unexpected installer build asset set")
    if (installers / "SHA256SUMS").read_text() != manifest(installers, names):
        raise ValueError("Installer build checksum mismatch")
    release_id, _ = draft(tag, installers)
    record = {"release": release_id, "rpm": {name: rpm_content(installers / name) for name in RPMS}}
    (work / "source.json").write_text(json.dumps(record))


def upload(tag, work):
    installers = work / "installers"
    source = json.loads((work / "source.json").read_text())
    release_id, _ = draft(tag, installers)
    if source["release"] != release_id:
        raise ValueError("The draft was replaced during signing")
    for name in RPMS:
        if rpm_content(installers / name) != source["rpm"][name]:
            raise ValueError(f"Signing changed the tested contents of {name}")
    shutil.copyfile(PUBLIC, installers / PUBLIC.name)
    names = OTHER.union(RPMS, {PUBLIC.name})
    (installers / "SHA256SUMS").write_text(manifest(installers, names))
    gh("release", "upload", tag, *(str(installers / n) for n in (*RPMS, PUBLIC.name, "SHA256SUMS")), "--clobber")
    current_id, remote = draft(tag, installers)
    if current_id != release_id or remote != {n: "sha256:" + digest(installers / n) for n in names | {"SHA256SUMS"}}:
        raise ValueError("Draft asset digest verification failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "upload"))
    parser.add_argument("tag")
    parser.add_argument("work", type=Path)
    parser.add_argument("--run-id")
    args = parser.parse_args()
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", args.tag):
        parser.error("expected a version tag such as v0.6.4")
    if args.action == "prepare":
        prepare(args.tag, args.run_id, args.work)
    else:
        upload(args.tag, args.work)
