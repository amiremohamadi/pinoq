import os
import unittest
import subprocess

class Integration(unittest.TestCase):
    def setUp(self):
        self.directory = '/tmp/pinoq/'

    def test_pinoq_mount_sanity(self):
        subprocess.run(['touch', self.directory + 'test.txt'])
        files = os.listdir(self.directory)
        self.assertIn('test.txt', files, 'File does not exist')
    
if __name__ == '__main__':
    unittest.main()

