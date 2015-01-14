# The threat model

The threat model `encbup` is designed to protect against is file backup from a trusted server to untrusted sources
through untrusted connections.

# Requirements

* File contents and filenames are considered sensitive data.
* Other file metadata is potentially not considered sensitive data.
* The number of files is not considered sensitive data.
* Encrypting a file with a given passphrase should always yield the same ciphertext. This is to allow per-file
  deduplication.

# The protocol

When using a passphrase, `encbup` derives a key from it by using PBKDF2-HMAC-SHA1 with a configurable number of rounds
(the goal is for the key derivation to take roughly half a second on a reasonably current machine). The number of
rounds and SHA512 hash of the derived key is stored in the backup set so `encbup` can check if the entered passphrase
is correct (when decrypting).

File encryption under a GPG key will require storing files on the client machine, and is planned for later.

Individual files are encrypted with AES-128 in CBC mode. To ensure that files encrypted with the same key will produce
the same ciphertext, the IV is chosen as the first 16 bytes of the HMAC-SHA512 of the plaintext (using the encryption
key as a MAC key) and stored along with the ciphertext. The MAC is also stored along with the ciphertext, for
authenticating the plaintext after decryption, to ensure that it has not been tampered with.

The filename is encrypted in the same way, using the last 16 bytes of the HMAC-SHA512 of the file's plaintext.
