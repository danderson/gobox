package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/nacl/box"

	kingpin "gopkg.in/alecthomas/kingpin.v1"
)

var (
	pubFile        string
	secFile        string
	plaintextFile  string
	ciphertextFile string
)

type keyType byte

func (k keyType) String() string {
	switch k {
	case 'P':
		return "public"
	case 'S':
		return "secret"
	default:
		return "unknown"
	}
}

const (
	keyPub keyType = 'P'
	keySec         = 'S'
)

func readKeyFile(path string, kt keyType) *[32]byte {
	var ret [32]byte
	c, err := ioutil.ReadFile(path)
	kingpin.FatalIfError(err, fmt.Sprintf("Reading key file %q", path))
	if len(c) != 33 {
		kingpin.Fatalf("Invalid key file %q (wrong size)", path)
	}
	at := keyType(c[32])
	if at != kt {
		kingpin.Fatalf("Wrong key type in %q: wanted %q, but got %q (did you switch the public and private key files on the commandline?)", path, kt, at)
	}
	copy(ret[:], c)
	return &ret
}

func main() {
	keys := func(cmd *kingpin.CmdClause) {
		cmd.Arg("pubkey", "Public key file.").Required().StringVar(&pubFile)
		cmd.Arg("seckey", "Secret key file.").Required().StringVar(&secFile)
	}

	cmd := kingpin.Command("genkey", "Generate a key pair and write them to the given files.")
	keys(cmd)

	cmd = kingpin.Command("encrypt", "Encrypt a file FROM seckey (you) TO pubkey (peer)")
	keys(cmd)
	cmd.Arg("input-file", "The file to encrypt.").Required().ExistingFileVar(&plaintextFile)
	cmd.Arg("output-file", "Destination path for the encrypted content.").Required().StringVar(&ciphertextFile)

	cmd = kingpin.Command("decrypt", "Decrypt a file FROM pubkey (peer) TO seckey (you)")
	keys(cmd)
	cmd.Arg("input-file", "The file to decrypt.").Required().ExistingFileVar(&plaintextFile)
	cmd.Arg("output-file", "Destination path for the decrypted content.").Required().StringVar(&ciphertextFile)

	switch kingpin.Parse() {
	case "genkey":
		pub, sec, err := box.GenerateKey(rand.Reader)
		kingpin.FatalIfError(err, "Error generating keypair")
		kingpin.FatalIfError(ioutil.WriteFile(pubFile, append(pub[:], byte(keyPub)), 0644), "Writing public key")
		kingpin.FatalIfError(ioutil.WriteFile(secFile, append(sec[:], byte(keySec)), 0600), "Writing secret key")

	case "encrypt":
		pub := readKeyFile(pubFile, keyPub)
		sec := readKeyFile(secFile, keySec)
		plain, err := ioutil.ReadFile(plaintextFile)
		kingpin.FatalIfError(err, "Reading plaintext file")
		var nonce [24]byte
		_, err = io.ReadFull(rand.Reader, nonce[:])
		kingpin.FatalIfError(err, "Reading randomness")
		cipher := box.Seal(nonce[:], plain, &nonce, pub, sec)
		kingpin.FatalIfError(ioutil.WriteFile(ciphertextFile, cipher, 0644), "Writing ciphertext")

	case "decrypt":
		pub := readKeyFile(pubFile, keyPub)
		sec := readKeyFile(secFile, keySec)
		nonceAndCipher, err := ioutil.ReadFile(ciphertextFile)
		kingpin.FatalIfError(err, "Reading ciphertext file")
		var nonce [24]byte
		copy(nonce[:], nonceAndCipher)
		plain, ok := box.Open(nil, nonceAndCipher[24:], &nonce, pub, sec)
		if !ok {
			kingpin.Fatalf("Decryption of %q failed (wrong keys?)", ciphertextFile)
		}
		kingpin.FatalIfError(ioutil.WriteFile(plaintextFile, plain, 0600), "Writing plaintext")
	}
}
