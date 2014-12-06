package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"

	kingpin "gopkg.in/alecthomas/kingpin.v1"
)

const privateKeyLen = 24 + 24 + 32 + secretbox.Overhead

var (
	pubFile        string
	privFile       string
	plaintextFile  string
	ciphertextFile string
)

func mkScrypt(passphrase string, salt []byte) (*[32]byte, error) {
	s, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	var ret [32]byte
	copy(ret[:], s)
	return &ret, nil
}

func genKey() ([]byte, []byte, error) {
	passphrase, err := getPassphrase(true)
	if err != nil {
		return nil, nil, err
	}

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privateKey := make([]byte, privateKeyLen)

	if passphrase == "" {
		// Easy one: if no passphrase, just dump the private key in
		// the output.
		copy(privateKey[48:], priv[:])
	} else {
		// If we have a passphrase, derive a key, encrypt, and write
		// the necessaries to the result.
		var salt [24]byte
		if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
			return nil, nil, err
		}

		symmetricKey, err := mkScrypt(passphrase, salt[:])
		if err != nil {
			return nil, nil, err
		}

		var nonce [24]byte
		if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
			return nil, nil, err
		}

		copy(privateKey, salt[:])
		copy(privateKey[24:], nonce[:])
		secretbox.Seal(privateKey[:48], priv[:], &nonce, symmetricKey)
	}

	return []byte(base64.StdEncoding.EncodeToString(pub[:])), []byte(base64.StdEncoding.EncodeToString(privateKey)), nil
}

func readPublicKey(path string) (*[32]byte, error) {
	c, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err = base64.StdEncoding.DecodeString(string(c))
	if err != nil {
		return nil, err
	}

	if len(c) != 32 {
		return nil, fmt.Errorf("Invalid public key %q (wrong size)", path)
	}
	var ret [32]byte
	copy(ret[:], c)
	return &ret, nil
}

func readPrivateKey(path string) (*[32]byte, error) {
	c, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err = base64.StdEncoding.DecodeString(string(c))
	if err != nil {
		return nil, err
	}

	if len(c) != privateKeyLen {
		return nil, fmt.Errorf("Invalid private key %q (wrong size)", path)
	}
	if bytes.Equal(c[:48], bytes.Repeat([]byte{0}, 48)) && bytes.Equal(c[80:96], bytes.Repeat([]byte{0}, 16)) {
		var ret [32]byte
		copy(ret[:], c[48:80])
		return &ret, nil
	}

	passphrase, err := getPassphrase(false)
	if err != nil {
		return nil, err
	}
	symmetricKey, err := mkScrypt(passphrase, c[:24])
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], c[24:48])

	var ret [32]byte
	if _, ok := secretbox.Open(ret[:1], c[48:], &nonce, symmetricKey); !ok {
		return nil, fmt.Errorf("Decryption of private key %q failed (wrong passphrase?)", path)
	}
	return &ret, nil
}

func getPassphrase(repeat bool) (string, error) {
	fd := int(os.Stdin.Fd())
	if terminal.IsTerminal(fd) {
		os.Stderr.WriteString("Passphrase: ")
		passphrase, err := terminal.ReadPassword(fd)
		os.Stderr.WriteString("\n")
		if err != nil {
			return "", err
		}
		if repeat {
			os.Stderr.WriteString("Repeat passphrase: ")
			again, err := terminal.ReadPassword(fd)
			os.Stderr.WriteString("\n")
			if err != nil {
				return "", err
			}
			if !bytes.Equal(passphrase, again) {
				return "", errors.New("Passphrases do not match")
			}
		}
		return string(passphrase), err
	}

	r := bufio.NewReader(os.Stdin)
	passphrase, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if repeat {
		again, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		if passphrase != again {
			return "", errors.New("Passphrases do not match")
		}
	}
	return passphrase, err
}

func main() {
	keys := func(cmd *kingpin.CmdClause) {
		cmd.Arg("pubkey", "Public key file.").Required().StringVar(&pubFile)
		cmd.Arg("privkey", "Private key file.").Required().StringVar(&privFile)
	}

	cmd := kingpin.Command("genkey", "Generate a key pair and write them to the given files.")
	keys(cmd)

	cmd = kingpin.Command("encrypt", "Encrypt a file FROM privkey (you) TO pubkey (peer)")
	keys(cmd)
	cmd.Arg("input-file", "The file to encrypt.").Required().ExistingFileVar(&plaintextFile)
	cmd.Arg("output-file", "Destination path for the encrypted content.").Required().StringVar(&ciphertextFile)

	cmd = kingpin.Command("decrypt", "Decrypt a file FROM pubkey (peer) TO privkey (you)")
	keys(cmd)
	cmd.Arg("input-file", "The file to decrypt.").Required().ExistingFileVar(&ciphertextFile)
	cmd.Arg("output-file", "Destination path for the decrypted content.").Required().StringVar(&plaintextFile)

	switch kingpin.Parse() {
	case "genkey":
		pub, priv, err := genKey()
		kingpin.FatalIfError(err, "Error generating keypair")
		kingpin.FatalIfError(ioutil.WriteFile(pubFile, pub, 0644), "Writing public key")
		kingpin.FatalIfError(ioutil.WriteFile(privFile, priv, 0600), "Writing private key")

	case "encrypt":
		pub, err := readPublicKey(pubFile)
		kingpin.FatalIfError(err, "Reading public key")
		priv, err := readPrivateKey(privFile)
		kingpin.FatalIfError(err, "Reading private key")

		plain, err := ioutil.ReadFile(plaintextFile)
		kingpin.FatalIfError(err, "Reading plaintext file")
		var nonce [24]byte
		_, err = io.ReadFull(rand.Reader, nonce[:])
		kingpin.FatalIfError(err, "Reading randomness")
		cipher := box.Seal(nonce[:], plain, &nonce, pub, priv)
		kingpin.FatalIfError(ioutil.WriteFile(ciphertextFile, cipher, 0644), "Writing ciphertext")

	case "decrypt":
		pub, err := readPublicKey(pubFile)
		kingpin.FatalIfError(err, "Reading public key")
		priv, err := readPrivateKey(privFile)
		kingpin.FatalIfError(err, "Reading private key")

		nonceAndCipher, err := ioutil.ReadFile(ciphertextFile)
		kingpin.FatalIfError(err, "Reading ciphertext file")
		var nonce [24]byte
		copy(nonce[:], nonceAndCipher)
		plain, ok := box.Open(nil, nonceAndCipher[24:], &nonce, pub, priv)
		if !ok {
			kingpin.Fatalf("Decryption of %q failed (wrong keys?)", ciphertextFile)
		}
		kingpin.FatalIfError(ioutil.WriteFile(plaintextFile, plain, 0600), "Writing plaintext")
	}
}
