"""encbup.

Usage:
  encbup.py [options] --encrypt <outfile> <path> ...
  encbup.py [options] --decrypt <infile> <directory>

Options:
  -h --help                        Show this screen.
  -s --salt=<salt>                 The salt used for the key.
  -p --passphrase=<passphrase>     The encryption passphrase used.
  -r --rounds=<rounds>             The number of rounds used for PBKDF2 [default: 20000].
  -v --verbose                     Say more things.
     --version                     Show version.
"""

import base64
import binascii
import hmac
import hashlib
import json
import logging
import os
import sys

from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from docopt import docopt
from getpass import getpass


PROTOCOL_VERSION = 1
BLOCK_SIZE = 64 * 1024
ENCODING = "utf-8"


def loads(data):
    return json.loads(data.decode(ENCODING))


def dumps(data):
    return json.dumps(data).encode(ENCODING)


class File:
    def __init__(self, key, root, filename):
        self.block_size = BLOCK_SIZE
        self._root = root
        self._filename = filename
        self._key = key

    def read_blocks(self, block_size=None):
        if block_size is None:
            block_size = self.block_size

        infile = open(self.absolute_path, "rb")
        while True:
            block = infile.read(block_size)
            if block:
                yield block
            else:
                break
        infile.close()

    def pad(self, data):
        """
        Pad `data` as per PKCS#7.
        """
        length = 16 - (len(data) % 16)
        return data + (chr(length) * length).encode(ENCODING)

    def hmac(self):
        if getattr(self, "_hmac", None) is None:
            h = hmac.new(self._key.key, digestmod=hashlib.sha512)
            for block in self.read_blocks():
                h.update(block)
            self._hmac = h
        return self._hmac

    def encrypted(self):
        # Set the IV as the first 16 bytes of the file's HMAC, so the same plaintext
        # always encrypts to the same ciphertext for a given key.
        self._cipher = AES.new(self._key.key, AES.MODE_CBC, IV=self.iv)
        infile = open(self.absolute_path)

        yield self.iv
        for block in self.read_blocks():
            if len(block) < self.block_size:
                yield self._cipher.encrypt(self.pad(block))
                break
            else:
                yield self._cipher.encrypt(block)
        else:
            yield self.pad(b"")

        infile.close()

    @property
    def iv(self):
        return self.hmac().digest()[:16]

    @property
    def absolute_path(self):
        return os.path.join(self._root, self._filename)

    @property
    def relative_path(self):
        return self._filename

    @property
    def encrypted_absolute_path(self):
        iv = self.hmac().digest()[-16:]
        cipher = AES.new(self._key.key, AES.MODE_CBC, IV=iv)
        return iv + cipher.encrypt(self.pad(self.absolute_path.encode(ENCODING)))

    @property
    def encrypted_relative_path(self):
        iv = self.hmac().digest()[-16:]
        cipher = AES.new(self._key.key, AES.MODE_CBC, IV=iv)
        return iv + cipher.encrypt(self.pad(self.relative_path))

    @property
    def encrypted_size(self):
        padding_length = 16 - (self.size % 16)
        return 16 + self.size + padding_length

    @property
    def size(self):
        return os.path.getsize(self.absolute_path)

    @property
    def as_dict(self):
        filename = self.encrypted_absolute_path
        h = hmac.new(self._key.key, digestmod=hashlib.sha512)
        h.update(filename)
        filename_hmac = h.hexdigest()
        filename = binascii.hexlify(filename)
        return {
            "plaintext_digest": self.hmac().hexdigest(),
            "size": self.encrypted_size,
            "filename": filename.decode("ascii"),
            "filename_hmac": filename_hmac,
            }


class Key:
    def __init__(self, passphrase, salt=None, rounds=20000):
        if salt is None:
            salt = self.generate_salt()
        self.salt = salt
        self.rounds = rounds
        self.key = PBKDF2(passphrase, salt, count=rounds)

    def generate_salt(self):
        return base64.b64encode(Random.new().read(8))

    @property
    def hexdigest(self):
        return hashlib.sha512(self.key).hexdigest()

    @property
    def as_dict(self):
        return {"filename": ".encbup.json", "size": len(self.contents)}

    @property
    def contents(self):
        return dumps({"digest": self.hexdigest, "salt": self.salt.decode(ENCODING), "rounds": self.rounds})


class Reader:
    def __init__(self, filename, base_dir):
        if filename == "-":
            self.file = sys.stdin
        else:
            self.file = open(filename, "rb")
        self._base_dir = base_dir

    def unpad(self, data):
        """
        Unpad `data` as per PKCS#7.
        """
        try:
            length = ord(data[-1])
        except TypeError:
            length = data[-1]
        return data[:-length]

    def process_stream(self, passphrase):
        version = self.file.readline()
        state = 0

        # Read protocol version.
        if int(version) > PROTOCOL_VERSION:
            sys.exit("Unsupported protocol version.")

        # Read keyfile.
        metadata = loads(self.file.readline())
        keyfile = loads(self.file.read(metadata["size"] + 1))
        key = Key(passphrase, keyfile["salt"].encode(ENCODING), rounds=keyfile["rounds"])
        if key.hexdigest != keyfile["digest"]:
            sys.exit("Wrong passphrase.")

        while True:
            if state == 0:
                # Read metadata.
                metadata = self.file.readline()
                if not metadata:
                    break
                metadata = loads(metadata)

                # Decrypt the filename.
                encrypted_filename = binascii.unhexlify(metadata["filename"])
                if hmac.new(key.key, msg=encrypted_filename, digestmod=hashlib.sha512).hexdigest() != metadata["filename_hmac"]:
                    sys.exit("Invalid filename HMAC, either it is corrupt or someone has tampered with it.")

                cipher = AES.new(key.key, AES.MODE_CBC, IV=encrypted_filename[:16])
                filename = self.unpad(cipher.decrypt(encrypted_filename[16:])).decode(ENCODING)

                # Strip leading slashes.
                # TODO: Protect against ../../ etc.
                if filename.startswith("/"):
                    filename = filename[1:]
                logging.debug("Decrypting {0}...".format(filename))

                pathname = os.path.join(self._base_dir, filename)
                # Create parent directories.
                if not os.path.exists(os.path.dirname(pathname)):
                    os.makedirs(os.path.dirname(pathname))
                outfile = open(pathname, "wb")

                # Read the IV and prepare the cipher.
                cipher = AES.new(key.key, AES.MODE_CBC, IV=self.file.read(16))
                h = hmac.new(key.key, digestmod=hashlib.sha512)
                size = metadata["size"] - 16
                state = 1
            else:
                block_size = min(BLOCK_SIZE, size)
                data = self.file.read(block_size)
                plaintext = cipher.decrypt(data)
                if block_size < BLOCK_SIZE:
                    plaintext = self.unpad(plaintext)
                h.update(plaintext)
                outfile.write(plaintext)
                size -= block_size
                if size == 0:
                    if h.hexdigest() != metadata["plaintext_digest"]:
                        sys.exit("Invalid file HMAC, either it is corrupt or someone has tampered with it.")
                    self.file.read(1)  # Skip the newline.
                    state = 0
                    outfile.close()
        self.file.close()


class Writer:
    """
    A class for writing encrypted data to a file (or stdout).
    """
    def __init__(self, filename):
        if filename == "-":
            self.file = sys.stdout
        else:
            self.file = open(filename, "wb")

    def walk(self, path):
        """
        Recurse down the given `path`, returning filenames relative to it, if it is a directory.
        If not, return path itself.
        """
        if not os.path.isdir(path):
            yield os.path.split(path)
        else:
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    relpath = os.path.relpath(os.path.join(dirpath, filename), path)
                    yield path, relpath

    def write(self, line=b"", terminate=True):
        """
        Write a newline-terminated line to a file.
        """
        self.file.write(line)
        if terminate:
            self.file.write("\n".encode(ENCODING))

    def write_preamble(self, key):
        self.write(str(PROTOCOL_VERSION).encode(ENCODING))
        self.write(dumps(key.as_dict))
        self.write(key.contents)

    def write_files(self, key, paths):
        for path in paths:
            for root, filename in self.walk(path):
                logging.debug("Encrypting {0}...".format(filename))
                infile = File(key, root, filename)
                self.write(dumps(infile.as_dict))
                for block in infile.encrypted():
                    self.write(block, terminate=False)
                # Write a terminating blank line.
                self.write()
        self.file.close()


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    arguments = docopt(__doc__, argv=args, version='encbup 0.1')

    if arguments["--verbose"]:
        logging.basicConfig(level=logging.DEBUG)

    if arguments["--passphrase"] is None:
        passphrase = getpass("Please enter a passphrase: ")
        passphrase_again = getpass("Please confirm the passphrase: ")
        if passphrase != passphrase_again:
            sys.exit("The passphrases don't match.")
    else:
        passphrase = arguments["--passphrase"]

    try:
        rounds = int(arguments["--rounds"])
    except ValueError:
        sys.exit("Please enter an integer for the value of the rounds.")

    if arguments["--encrypt"]:
        key = Key(passphrase, arguments["--salt"], rounds=rounds)
        writer = Writer(arguments["<outfile>"])
        writer.write_preamble(key)
        writer.write_files(key, arguments["<path>"])
    elif arguments["--decrypt"]:
        reader = Reader(arguments["<infile>"], arguments["<directory>"])
        reader.process_stream(passphrase)


if __name__ == '__main__':
    main()
