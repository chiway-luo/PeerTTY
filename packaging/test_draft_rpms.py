import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import draft_rpms as release


class DraftSigningTests(unittest.TestCase):
    def test_only_the_signature_region_may_change(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "fixture.rpm"
            def write(signature, payload):
                lead = b"\xed\xab\xee\xdb" + bytes(92)
                header = b"\x8e\xad\xe8\x01" + bytes(4) + struct.pack(">II", 0, len(signature))
                path.write_bytes(lead + header + signature + bytes(-len(signature) % 8) + payload)
            write(b"", b"main header and contents")
            original = release.rpm_content(path)
            write(b"new signature", b"main header and contents")
            self.assertEqual(original, release.rpm_content(path))
            write(b"new signature", b"different contents")
            self.assertNotEqual(original, release.rpm_content(path))

    def test_draft_must_still_match_the_build(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            files = []
            for name in release.OTHER:
                path = folder / name
                path.write_bytes(name.encode())
                files.append({"name": name, "digest": "sha256:" + release.digest(path)})
            draft = {"databaseId": 12, "isDraft": True, "tagName": "v1.2.3", "assets": files}
            with patch.object(release, "gh", side_effect=lambda *args: json.dumps(draft)):
                self.assertEqual(release.draft("v1.2.3", folder)[0], 12)
                draft["isDraft"] = False
                with self.assertRaisesRegex(ValueError, "existing draft"):
                    release.draft("v1.2.3", folder)
                draft["isDraft"] = True
                (folder / files[0]["name"]).write_bytes(b"different build")
                with self.assertRaisesRegex(ValueError, "differs"):
                    release.draft("v1.2.3", folder)
