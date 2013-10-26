import os
import random
import md5
import shutil
import time
import tempfile
import unittest
from encbup import Reader, Writer, Key


def scandir(directory):
    """
    Walk a directory and build and return a dictionary of {"checksum": "filename"}.
    """
    checksums = {}
    for root, dirs, files in os.walk(directory):
        for filename in files:
            name = os.path.join(root, filename)
            checksum = md5.new(open(name).read()).hexdigest()
            checksums[checksum] = name
    return checksums


class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.source_dir = tempfile.mkdtemp()
        self.backup_dir = tempfile.mkdtemp()
        self.restore_dir = tempfile.mkdtemp()
        self.backup_filename = os.path.join(self.backup_dir, "backup.encbup")
        self.passphrase = "some passphrase"

        self.create_source_files()
        seed = str(time.time())
        print("Seed:", seed)
        random.seed(seed)

    def tearDown(self):
        shutil.rmtree(self.source_dir)
        shutil.rmtree(self.backup_dir)
        shutil.rmtree(self.restore_dir)

    @property
    def is_restore_complete(self):
        """
        Compare the files in the backup dir those in the restore dir, and
        return True if they are identical, False otherwise.
        """
        sd = set(scandir(self.source_dir).keys())
        bd = set(scandir(self.restore_dir).keys())
        return len((sd - bd) | (bd - sd)) == 0

    def full_path(self, path):
        return os.path.join(self.source_dir, path)

    def create_source_files(self):
        """
        Create some files in the source directory.
        """
        os.mkdir(self.full_path("testdir"))
        filenames = [
            "testdir/test1.txt",
            "testdir/test2.txt",
            "test1.txt",
            "test2.txt",
            "test3.txt",
        ]
        for filename in filenames:
            handle = open(self.full_path(filename), "w")
            handle.write("".join([chr(random.randrange(32, 127)) for _ in range(random.randrange(10, 1000))]))
            handle.close()

    def test_idempotence(self):
        print self.backup_filename
        writer = Writer(self.backup_filename)
        key = Key(self.passphrase, rounds=2)
        writer.write_preamble(key)
        writer.write_files(key, [self.source_dir])

        reader = Reader(self.backup_filename, self.restore_dir)
        reader.process_stream(self.passphrase)

        self.assertTrue(self.is_restore_complete)
