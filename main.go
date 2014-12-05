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

func readKeyFile(path string) *[32]byte {
	var ret [32]byte
	c, err := ioutil.ReadFile(path)
	kingpin.FatalIfError(err, fmt.Sprintf("Reading key file %q", path))
	if len(c) != 32 {
		kingpin.Fatalf("Invalid key file %q (wrong size)", path)
	}
	copy(ret[:], c)
	return &ret
}

func main() {
	keys := func(cmd *kingpin.CmdClause) {
		cmd.Arg("pubkey", "Public key file").Required().StringVar(&pubFile)
		cmd.Arg("seckey", "Secret key file").Required().StringVar(&secFile)
	}

	cmd := kingpin.Command("genkey", "Generate a key pair")
	keys(cmd)

	cmd = kingpin.Command("encrypt", "Encrypt a file")
	keys(cmd)
	cmd.Arg("plaintext", "Plaintext").Required().ExistingFileVar(&plaintextFile)
	cmd.Arg("ciphertext", "Ciphertext").Required().StringVar(&ciphertextFile)

	cmd = kingpin.Command("decrypt", "Decrypt a file")
	keys(cmd)
	cmd.Arg("ciphertext", "Ciphertext").Required().ExistingFileVar(&plaintextFile)
	cmd.Arg("plaintext", "Plaintext").Required().StringVar(&ciphertextFile)

	switch kingpin.Parse() {
	case "genkey":
		pub, sec, err := box.GenerateKey(rand.Reader)
		kingpin.FatalIfError(err, "Error generating keypair")
		kingpin.FatalIfError(ioutil.WriteFile(pubFile, pub[:], 0644), "Writing public key")
		kingpin.FatalIfError(ioutil.WriteFile(secFile, sec[:], 0600), "Writing secret key")

	case "encrypt":
		pub := readKeyFile(pubFile)
		sec := readKeyFile(secFile)
		plain, err := ioutil.ReadFile(plaintextFile)
		kingpin.FatalIfError(err, "Reading plaintext file")
		var nonce [24]byte
		_, err = io.ReadFull(rand.Reader, nonce[:])
		kingpin.FatalIfError(err, "Reading randomness")
		cipher := box.Seal(nonce[:], plain, &nonce, pub, sec)
		kingpin.FatalIfError(ioutil.WriteFile(ciphertextFile, cipher, 0644), "Writing ciphertext")

	case "decrypt":
		pub := readKeyFile(pubFile)
		sec := readKeyFile(secFile)
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
