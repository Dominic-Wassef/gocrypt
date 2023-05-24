package gocrypt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"io"
	"os"
)

type EncryptedObject struct {
	kdfSalt    [8]byte
	encrNonce  [24]byte
	cipherText []byte
}

func (e EncryptedObject) String() string {
	return fmt.Sprintf("salt: %v, nonce: %v \nciphertext: %v\n",
		e.kdfSalt, e.encrNonce, base64.StdEncoding.EncodeToString(e.cipherText))

}

func (e *EncryptedObject) CipherText() []byte {
	return e.cipherText
}

func NewEncryptedObject() *EncryptedObject {
	// Generate random salt for KDF
	var salt [8]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		panic(err)
	}
	// Random nonce
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	return &EncryptedObject{kdfSalt: salt, encrNonce: nonce}
}

// encrypts byte slice with a pass
func (e *EncryptedObject) Encrypt(plainText []byte, pass string) error {

	// Derive key with scrypt
	var salt [8]byte
	copy(salt[:], e.kdfSalt[:])
	secretKeyBytes, err := scrypt.Key([]byte(pass), salt[:], 1<<15, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)
	encrypted := secretbox.Seal(nil, plainText, &e.encrNonce, &secretKey)
	// Add the salt at the beginning of the message:
	//	encrypted = append(e.kdfSalt, encrypted...)
	e.cipherText = encrypted
	return nil
}

// This function puts the KDF salt, encryption nonce and ciphertext all together
func (e *EncryptedObject) PackMessage() []byte {
	packedMsg := append(e.kdfSalt[:], e.encrNonce[:]...)
	packedMsg = append(packedMsg, e.cipherText...)
	return packedMsg
}

// Unpack a byte slice into an encrypted Object.
// TODO add delimiters between
func UnpackMessage(packed []byte) (*EncryptedObject, error) {
	// The packed object is not long enough
	if len(packed) < 8+24 {
		return nil, errors.New("packed object is not long enough")
	}
	obj := &EncryptedObject{}

	kdfSalt := packed[:8]
	encrNonce := packed[8:(8 + 24)]
	copy(obj.kdfSalt[:], kdfSalt)
	copy(obj.encrNonce[:], encrNonce)
	obj.cipherText = packed[(8 + 24):]
	return obj, nil
}

func (e *EncryptedObject) WriteToFile(path string) error {
	if path == "" {
		panic("Cannot write to an empty path")
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	encoded := base64.StdEncoding.EncodeToString(e.cipherText)
	f.WriteString(encoded)
	return nil

}

// Constructor that reads a file, parse
func NewEncryptedObjectFromFile() {
}

// Decrypts an EncryptedObject
func (e *EncryptedObject) Decrypt(pass string) ([]byte, error) {
	// First 8 bytes of cyphertext is salt
	secretKeyBytes, err := scrypt.Key([]byte(pass), e.kdfSalt[:], 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)
	decrypted, ok := secretbox.Open(nil, e.cipherText, &e.encrNonce, &secretKey)
	if !ok {
		return nil, errors.New("decryption error")
	}
	fmt.Println(string(decrypted))
	return decrypted, nil
}
