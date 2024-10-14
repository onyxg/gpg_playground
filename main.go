package main

import (
	"bytes"
	"flag"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	_ "golang.org/x/crypto/openpgp/packet"
	"golang.org/x/term"
	"io/ioutil"
	"log"
	"os"
)

var (
	publicKeyFile  = flag.String("public-key", "", "Public key file")
	privateKeyFile = flag.String("private-key", "", "Private key file")
)

func main() {
	flag.Parse()

	// Load public and private keys
	publicKey, err := readKey(*publicKeyFile)
	if err != nil {
		log.Fatal("Error loading public key:", err)
	}

	privateKey, err := readKey(*privateKeyFile)
	if err != nil {
		log.Fatal("Error loading private key:", err)
	}

	// Prompt for passphrase
	fmt.Print("Enter passphrase: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal("Error reading passphrase:", err)
	}
	fmt.Println()

	// Decrypt the private key
	err = decryptPrivateKey(privateKey, passphrase)
	if err != nil {
		log.Fatal("Error decrypting private key:", err)
	}

	// Example message
	message := "Hello, this is a secret message."

	// Encrypt the message
	encryptedMessage, err := encrypt(publicKey, message)
	if err != nil {
		log.Fatal("Error encrypting message:", err)
	}
	log.Println("Encrypted Message:", string(encryptedMessage))

	// Decrypt the message
	decryptedMessage, err := decrypt(privateKey, encryptedMessage)
	if err != nil {
		log.Fatal("Error decrypting message:", err)
	}
	log.Println("Decrypted Message:", decryptedMessage)
}

// Helper function to read PGP key
func readKey(file string) (entity *openpgp.Entity, err error) {
	keyFile, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	entityList, err := openpgp.ReadArmoredKeyRing(keyFile)
	if err != nil {
		return nil, err
	}

	return entityList[0], nil
}

// Function to encrypt message
func encrypt(publicKey *openpgp.Entity, message string) ([]byte, error) {
	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	plaintext, err := openpgp.Encrypt(w, []*openpgp.Entity{publicKey}, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	_, err = plaintext.Write([]byte(message))
	if err != nil {
		return nil, err
	}
	plaintext.Close()
	w.Close()

	return buf.Bytes(), nil
}

// Function to decrypt message
func decrypt(privateKey *openpgp.Entity, encryptedMessage []byte) (string, error) {
	block, err := armor.Decode(bytes.NewReader(encryptedMessage))
	if err != nil {
		return "", err
	}

	md, err := openpgp.ReadMessage(block.Body, openpgp.EntityList{privateKey}, nil, nil)
	if err != nil {
		return "", err
	}

	message, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}

	return string(message), nil
}

// Function to decrypt private key
func decryptPrivateKey(privateKey *openpgp.Entity, passphrase []byte) error {
	if privateKey.PrivateKey.Encrypted {
		err := privateKey.PrivateKey.Decrypt(passphrase)
		if err != nil {
			return err
		}
	}
	for _, subkey := range privateKey.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			err := subkey.PrivateKey.Decrypt(passphrase)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
