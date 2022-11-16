#!/usr/bin/env python2
# Copyright 2017 CoreOS, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import pwd
import shutil
import subprocess
import tempfile
import unittest

script_path = os.path.abspath('%s/../../target/debug/update-ssh-keys' % __file__)

test_keys = {
    'valid1': 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDULTftpWMj4nD+7Ps'
              'B8itam2T6Aqm9Z+ursQG1SRiK4ie5rHGJoteGnbH91Uix/HDE5GC3Hz'
              'ICQVOnQay4hwJUKRfEUEWj1Sncer/BL2igDquABlcXNl2dgOlfJ8a3q'
              '6IZnQpdEe6Vrqg/Ui082UxuZ08pNV94M/5IhR2fx0EbY66PQ97o+ywH'
              'sB7oXDO8p/+mGL+h7cxFY7hILXTa5/3TGBEgcA65Rrmq22eiRt97RGh'
              'DjfzIqTqb8gwuhTSNN7FWDLrEyRwJMbaTgDSoMIZdLtndVrGEqFHUO+'
              'WzinSiEQCs2MDDnTk29bleHAEktu1x68GYhg9S7O/gZq8/swAV '
              'core@valid1',
    'valid2': 'command="echo \\"test\\"" ssh-dss AAAAB3NzaC1kc3MAAACBAJA94Sqw80BSKjVTNZD6570nXIN'
              'hP8R2UhbBuydT+GI6CfA9Dw7O0udJQUfrqARFcRQR/syc72CO6jaKNE'
              '3/A5E+8uVmRZt7s9VtA47s1qxqHswth74m1Nb86n2OTB0HcW63FsXo2'
              'cJF+r+l6F3IcRPi4z/eaEKG7uhAS59TjH2tAAAAFQC0I9kL3oceMT1O'
              '44WPe6NZ8w8CMwAAAIABGm2Yg8nGFZbo/W8njuM79w0W2P1NBVNWzBH'
              'WQqVbr4i1bWTSSc9X+itQUpeF6zAUDsUoprhNise2NLrMYCLFo9JxhE'
              'iYAcEJ/YbKEnjtJzaAmQNpyh3rCWuOcGPTevjAZIkl+zEc+/N7tCW1e'
              'uDYm6IXZ8LEQyTUQUdU4pZ2OgAAAIABk1ZA3+TiCMaoAafNVUZ7zwqk'
              '888yVOgsJ7HGGDGRMo5ytr2SUJB7QWsLX6Un/Zbu32nXsAqtqagxd6F'
              'Ies98TSekMh/hAv9uK92mEsXSINXOeIMKRedqOyPgk5IEOsFpxAUO4T'
              'xpYToeuM8HRemecxw2eIFHnax+mQqCsi7FgQ== core@valid2',
    'valid3': 'sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9w'
              'ZW5zc2guY29tAAAAIEX/dQ0v4127bEo8eeG1EV0ApO2lWbSnN6RWusn'
              '/NjqIAAAABHNzaDo= demos@siril',
    'bad':    'ssh-bad this-not-a-key core@bad',
}

fingerprints = {
    'valid1': 'SHA256:yZ+o48h6quk9c+JVgJ/Zq4S5u4LUk6TSpneHKkmM9KY',
    'valid2': 'SHA256:RP5k1AybZ1kollIAnpUavr1v1nfZ0yloKvI46AMDPkM ',
    'valid3': 'SHA256:U8IKRkIHed6vFMTflwweA3HhIf2DWgZ8EFTm9fgwOUk',
}

class UpdateSshKeysTestCase(unittest.TestCase):

    def setUp(self):
        user_info = pwd.getpwuid(os.getuid())
        self.user = user_info.pw_name
        self.ssh_dir = tempfile.mkdtemp(prefix='test_update_ssh_keys')
        self.env = os.environ.copy()
        self.pub_files = {}

        for name, text in test_keys.iteritems():
            pub_path = '%s/%s.pub' % (self.ssh_dir, name)
            self.pub_files[name] = pub_path
            with open(pub_path, 'w') as pub_fd:
                pub_fd.write('%s\n' % text)

    def tearDown(self):
        shutil.rmtree(self.ssh_dir)

    def assertHasKeys(self, *keys):
        with open('%s/authorized_keys' % self.ssh_dir, 'r') as fd:
            text = fd.read()
        self.assertTrue(text.startswith('# auto-generated'))
        for key in keys:
            self.assertIn(test_keys[key], text)
        for key in test_keys:
            if key in keys:
                continue
            self.assertNotIn(test_keys[key], text)

    def run_script(self, *args, **kwargs):
        cmd = [script_path, '-u', self.user, '--ssh-dir', self.ssh_dir]
        cmd.extend(args)
        return subprocess.Popen(cmd, env=self.env,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                **kwargs)

    def test_usage(self):
        proc = self.run_script('-h')
        out, err = proc.communicate()
        self.assertEquals(proc.returncode, 0)
        self.assertTrue(out.startswith('Usage: '))
        self.assertEquals(err, '')

    def test_no_keys(self):
        proc = self.run_script()
        out, err = proc.communicate()
        self.assertEquals(proc.returncode, 1)
        self.assertEquals(out, '')
        self.assertIn('no keys found', err)
        self.assertTrue(os.path.isdir('%s/authorized_keys.d' % self.ssh_dir))
        self.assertFalse(os.path.exists('%s/authorized_keys' % self.ssh_dir))

    def test_first_run(self):
        with open('%s/authorized_keys' % self.ssh_dir, 'w') as fd:
            fd.write('%s\n' % test_keys['valid1'])
            fd.write('%s\n' % test_keys['valid2'])
            fd.write('%s\n' % test_keys['valid3'])
        proc = self.run_script()
        out, err = proc.communicate()
        self.assertEquals(proc.returncode, 0)
        self.assertTrue(out.startswith('Updated '))
        self.assertEquals(err, '')
        self.assertTrue(os.path.exists(
                '%s/authorized_keys.d/old_authorized_keys' % self.ssh_dir))
        self.assertHasKeys('valid1', 'valid2', 'valid3')

    def test_add_one_file(self):
        proc = self.run_script('-a', 'one', self.pub_files['valid1'])
        out, err = proc.communicate()
        self.assertEquals(proc.returncode, 0)
        self.assertTrue(out.startswith('Adding'))
        self.assertIn(fingerprints['valid1'], out)
        self.assertIn('\nUpdated ', out)
        self.assertEquals(err, '')
        self.assertTrue(os.path.exists(
                '%s/authorized_keys.d/one' % self.ssh_dir))
        self.assertHasKeys('valid1')

    def test_add_one_stdin(self):
        proc = self.run_script('-a', 'one', stdin=subprocess.PIPE)
        out, err = proc.communicate(test_keys['valid1'])
        self.assertEquals(proc.returncode, 0)
        self.assertTrue(out.startswith('Adding'))
        self.assertIn(fingerprints['valid1'], out)
        self.assertIn('\nUpdated ', out)
        self.assertEquals(err, '')
        self.assertTrue(os.path.exists(
                '%s/authorized_keys.d/one' % self.ssh_dir))
        self.assertHasKeys('valid1')

    def test_replace_one(self):
        self.test_add_one_file()
        proc = self.run_script('-a', 'one', self.pub_files['valid2'])
        out, err = proc.communicate()
        self.assertEquals(proc.returncode, 0)
        self.assertIn(fingerprints['valid2'], out)
        self.assertEquals(err, '')
        self.assertHasKeys('valid2')

    def test_no_replace(self):
        self.test_add_one_file()
        proc = self.run_script('-n', '-a', 'one', self.pub_files['valid2'])
        out, err = proc.communicate()
        self.assertTrue(out.startswith('Skipping'))
        self.assertEquals(proc.returncode, 0)
        self.assertEquals(err, '')
        self.assertHasKeys('valid1')

        proc = self.run_script('-n', '-A', 'one', self.pub_files['valid2'])
        out, err = proc.communicate()
        self.assertTrue(out.startswith('Skipping'))
        self.assertEquals(proc.returncode, 0)
        self.assertEquals(err, '')
        self.assertHasKeys('valid1')

    def test_add_two(self):
        self.test_add_one_file()
        proc = self.run_script('-a', 'two', self.pub_files['valid2'])
        out, err = proc.communicate()
        self.assertEquals(proc.returncode, 0)
        self.assertIn(fingerprints['valid2'], out)
        self.assertEquals(err, '')
        self.assertHasKeys('valid1', 'valid2')

    def test_del_one(self):
        self.test_add_one_file()
        proc = self.run_script('-d', 'one')
        out, err = proc.communicate()
        self.assertEquals(proc.returncode, 1)
        self.assertIn(fingerprints['valid1'], out)
        self.assertIn('no keys found', err)
        # Removed from authorized_keys.d but not authorized_keys
        self.assertFalse(os.path.exists(
                '%s/authorized_keys.d/one' % self.ssh_dir))
        self.assertHasKeys('valid1')

    def test_del_two(self):
        self.test_add_two()
        proc = self.run_script('-d', 'two')
        out, err = proc.communicate()
        self.assertEquals(proc.returncode, 0)
        self.assertIn(fingerprints['valid2'], out)
        self.assertEquals(err, '')
        self.assertHasKeys('valid1')

    def test_disable(self):
        self.test_add_two()
        proc = self.run_script('-D', 'two')
        out, err = proc.communicate()
        self.assertEquals(proc.returncode, 0)
        self.assertTrue(out.startswith('Disabling'))
        self.assertIn(fingerprints['valid2'], out)
        self.assertEquals(err, '')
        self.assertHasKeys('valid1')

        proc = self.run_script('-a', 'two', self.pub_files['valid2'])
        out, err = proc.communicate()
        self.assertEquals(proc.returncode, 0)
        self.assertTrue(out.startswith('Skipping'))
        self.assertEquals(err, '')
        self.assertHasKeys('valid1')

    def test_enable(self):
        self.test_disable()
        proc = self.run_script('-A', 'two', self.pub_files['valid2'])
        out, err = proc.communicate()
        self.assertEquals(proc.returncode, 0)
        self.assertTrue(out.startswith('Adding'))
        self.assertEquals(err, '')
        self.assertHasKeys('valid1', 'valid2')

    def test_add_bad(self):
        self.test_add_one_file()
        proc = self.run_script('-a', 'bad', self.pub_files['bad'])
        out, err = proc.communicate()
        self.assertEquals(proc.returncode, 0)
        self.assertIn('warning', out)
        self.assertIn('failed to parse public key', out)
        self.assertHasKeys('valid1')


if __name__ == '__main__':
    unittest.main()
