import os
import subprocess
import sys
import tempfile
import unittest

from getipa_cli import cli


class Askpass(unittest.TestCase):
    def test_helper_prints_password_from_env_only(self):
        pw = 'p@ss w0rd!&%^"\'$x'
        tmp = tempfile.mkdtemp()
        env = cli.make_askpass(tmp, "GETIPA_PW", pw)
        helper = env["SSH_ASKPASS"]
        for f in os.listdir(tmp):                       # password never written to disk
            self.assertNotIn(pw, open(os.path.join(tmp, f)).read())
        out = subprocess.run([helper], env=env, capture_output=True, text=True).stdout
        self.assertEqual(out.rstrip("\r\n"), pw)
        self.assertEqual(env["SSH_ASKPASS_REQUIRE"], "force")

    def test_ssh_command_has_no_password(self):
        class A:
            port, key, user, host = 22, None, "root", "192.168.1.9"
        self.assertNotIn("GETIPA_PW", " ".join(cli.ssh_cmd(A)))


if __name__ == "__main__":
    unittest.main()


class VerifyDecrypted(unittest.TestCase):
    @staticmethod
    def macho(cryptid):
        import struct
        lc = struct.pack("<IIIIII", 0x2C, 24, 4096, 4096, cryptid, 0)
        return struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(lc), 0, 0) + lc + b"\0" * 64

    def make_ipa(self, main_cryptid, fw_cryptid):
        import plistlib
        import zipfile
        path = os.path.join(tempfile.mkdtemp(), "t.ipa")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("Payload/A.app/Info.plist", plistlib.dumps({"CFBundleExecutable": "A"}))
            z.writestr("Payload/A.app/A", self.macho(main_cryptid))
            z.writestr("Payload/A.app/Frameworks/F.framework/F", self.macho(fw_cryptid))
        return path

    def test_detects_partial_decryption(self):
        self.assertEqual(cli.encrypted_binaries(self.make_ipa(1, 0)), ["A"])
        self.assertEqual(cli.encrypted_binaries(self.make_ipa(0, 1)), ["Frameworks/F.framework/F"])

    def test_clean_ipa(self):
        self.assertEqual(cli.encrypted_binaries(self.make_ipa(0, 0)), [])

    def test_unreadable_is_none(self):
        bad = os.path.join(tempfile.mkdtemp(), "x.ipa")
        open(bad, "wb").write(b"not a zip")
        self.assertIsNone(cli.encrypted_binaries(bad))


class RepairLayout(unittest.TestCase):
    def test_layout_and_runtime_offset(self):
        import struct
        segs = [struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT", 0x100000000, 0x20000, 0, 0x20000, 5, 5, 0, 0),
                struct.pack("<II16sQQQQiiII", 0x19, 72, b"__DATA", 0x100020000, 0x10000, 0x20000, 0x10000, 3, 3, 0, 0)]
        enc = struct.pack("<IIIIII", 0x2C, 24, 0x8000, 4096, 1, 0)
        lcs = b"".join(segs) + enc
        data = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 3, len(lcs), 0, 0) + lcs + b"\0" * 0x30000
        lay = cli.macho_encryption_layout(data)
        self.assertEqual(len(lay), 1)
        self.assertEqual((lay[0]["cryptoff"], lay[0]["cryptsize"], lay[0]["cryptid"]), (0x8000, 4096, 1))
        self.assertEqual(cli.runtime_offset(lay[0]["segments"], 0x8000), 0x8000)
        self.assertEqual(cli.runtime_offset(lay[0]["segments"], 0x20010), 0x20010)
        self.assertIsNone(cli.runtime_offset(lay[0]["segments"], 0x90000))

    def test_decrypted_has_no_layout(self):
        import struct
        enc = struct.pack("<IIIIII", 0x2C, 24, 0x8000, 4096, 0, 0)
        data = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(enc), 0, 0) + enc
        self.assertEqual(cli.macho_encryption_layout(data), [])
