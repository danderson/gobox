# gobox - authenticated encryption CLI

Gobox is a trivial CLI wrapper around the excellent
[golang.org/x/crypto/nacl](https://godoc.org/golang.org/x/crypto/nacl)
library, itself an implementation of djb et al.'s excellent
[NaCl](http://nacl.cr.yp.to/) crypto library.

NaCl implements fast, secure and non-surprising authenticated
encryption using either a symmetric key, or a public/private key
pair.

Using `secretbox`, you _seal_ a message using a symmetric key, and
_open_ it with the same key.

Using `box`, you _seal_ a message to a user (with their public key)
from you (with your private key). That sealed box can only be _opened_
by that user, if they provide their private key and your public key.

The APIs are deliberately devoid of knobs and settings, allowing only
those two operations, seal and open.

Gobox just surfaces two primitives (plus `keygen` to produce key
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

  sym-encrypt <input-file> <output-file>
    Encrypt a file with a passphrase

  sym-decrypt <input-file> <output-file>
    Decrypt a file with a passphrase
```

### Public key crypto (`box`)

#### Generate a keypair

```console
$ gobox keygen alice.pub alice.sec
```

#### Encrypt a file

```console
$ echo "Eve is listening" >plaintext
$ gobox encrypt bob.pub alice.sec plaintext ciphertext
```

#### Decrypt a file

```console
$ gobox decrypt alice.pub bob.sec ciphertext plaintext
$ cat plaintext
Eve is listening
```


### Symmetric crypto (`secretbox`)

#### Encrypt a file

```console
$ echo "Eve is listening" >plaintext
$ gobox sym-encrypt plaintext ciphertext
```

#### Decrypt a file

```console
$ gobox sym-decrypt ciphertext plaintext
$ cat plaintext
Eve is listening
```
