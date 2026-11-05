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
