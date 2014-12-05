# gobox - authenticated encryption CLI

Gobox is a trivial CLI wrapper around the excellent
[golang.org/x/crypto/nacl/box](https://godoc.org/golang.org/x/crypto/nacl/box)
library, itself an implementation of the excellent `box` abstraction
from djb et al.'s excellent [NaCl](http://nacl.cr.yp.to/) crypto
library.

NaCl box implements fast, secure and non-surprising authenticated
encryption using a public/private key pair. Using your private key and
a peer's public key, you _seal_ a message to that user from you. That
sealed box can only be _opened_ by that peer, if they provide their
private key and your public key. The API is deliberately devoid of
knobs and settings, allowing only those two operations, seal and open.

Gobox just surfaces those two primitives (plus `keygen` to produce key
pairs) to the commandline.

### CLI

The tool is about as straightforward as the NaCl box API.

```console
$ gobox
usage: gobox <command> [<flags>] [<args> ...]

Flags:
  --help  Show help.

Commands:
  help [<command>]
    Show help for a command.

  genkey <pubkey> <seckey>
    Generate a key pair and write them to the given files.

  encrypt <pubkey> <seckey> <input-file> <output-file>
    Encrypt a file FROM seckey (you) TO pubkey (peer)

  decrypt <pubkey> <seckey> <input-file> <output-file>
    Decrypt a file FROM pubkey (peer) TO seckey (you)
```

### Generate a keypair

```console
$ gobox keygen alice.pub alice.sec
```

### Encrypt a file

```console
$ echo "Eve is listening" >plaintext
$ gobox encrypt bob.pub alice.sec plaintext ciphertext
```

### Decrypt a file

```console
$ gobox decrypt alice.pub bob.sec ciphertext plaintext
$ echo plaintext
Eve is listening
```
