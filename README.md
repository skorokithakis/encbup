encbup
======
Encrypted backups (without the backups).

Description
-----------
encbup is a companion to [bup](https://github.com/bup/bup), the backup program. encbup adds encryption to bup, while
still allowing per-file deduplication.

encbup can be thought of as an encrypted version of tar. It accepts a list of files and produces an encrypted blob.

Usage
-----
To encrypt:

    encbup.py --encrypt - /my/data/dir/ /some/file

To decrypt:

    encbup.py --decrypt - /my/outdir/

Protocol
--------
The protocol is detailed in `PROTOCOL.md`. If you find any errors, omissions, or have any feedback, please contact me
or open an issue.
