import os
import time
import signal
import unittest
import subprocess
from dataclasses import dataclass

PINOQ_BIN = os.environ.get('PINOQ_BIN')

@dataclass
class Config:
    disk: str
    mount: str
    aspect: int
    password: str

    def __str__(self):
        return f'''disk = "{self.disk}"
mount = "{self.mount}"

[current]
aspect = {self.aspect}
password = "{self.password}"'''


class Integration(unittest.TestCase):
    def setUp(self):
        self.pid = None
        self.directory = '/tmp/pinoq/'
        self.config_path = '/tmp/pinoq.toml'
        self.disk = '/tmp/volume.pnoq'
        subprocess.run([PINOQ_BIN, '--mkfs', '2', '1024', self.disk, 'password'])

    def test_pinoq_mount_sanity(self):
        config = Config(self.disk, self.directory, 1, 'password')
        with open(self.config_path, 'w') as file:
            file.write(str(config))
        self.run_pinoq()

        self.create_file('test.txt')
        files = os.listdir(self.directory)
        self.assertIn('test.txt', files, 'File does not exist')

    def test_pinoq_multiple_aspects(self):
        # trying the second aspect
        config = Config(self.disk, self.directory, 1, 'password')
        with open(self.config_path, 'w') as file:
            file.write(str(config))
        self.run_pinoq()

        self.create_file('first.txt')
        files = os.listdir(self.directory)
        self.assertIn('first.txt', files, 'File does not exist')

        # trying the first aspect
        config = Config(self.disk, self.directory, 0, 'password')
        with open(self.config_path, 'w') as file:
            file.write(str(config))
        self.run_pinoq()

        files = os.listdir(self.directory)
        self.assertEqual(len(files), 0, 'The aspect is corrupted')
        self.create_file('second.txt')
        files = os.listdir(self.directory)
        self.assertEqual(['second.txt'], files, 'The aspect is corrupted')

        # again trying the second aspect to make sure
        # we don't have access to other aspects' files
        config = Config(self.disk, self.directory, 1, 'password')
        with open(self.config_path, 'w') as file:
            file.write(str(config))
        self.run_pinoq()

        files = os.listdir(self.directory)
        self.assertIn('first.txt', files, 'File does not exist')
        self.assertNotIn('second.txt', files, 'The aspect is corrupted')

    def create_file(self, name):
        subprocess.run(['touch', self.directory + name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def run_pinoq(self):
        if self.pid:
            os.kill(self.pid, signal.SIGTERM)
            time.sleep(2)
        process = subprocess.Popen([PINOQ_BIN, '--mount', self.config_path],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.pid = process.pid
        time.sleep(2)

    def tearDown(self):
        if self.pid:
            os.kill(self.pid, signal.SIGTERM)
        os.remove(self.config_path)
        os.remove(self.disk)

    
if __name__ == '__main__':
    unittest.main()

