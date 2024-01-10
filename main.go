// Read and write asynchronously to encrypted files.
package rwcipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"os"
)

// Returns a password string
type PasswordReader interface {
	ReadPassword() ([]byte, error)
}

type StdInPasswordReader struct {
}

func (spr StdInPasswordReader) ReadPassword() ([]byte, error) {
	pwd, error := terminal.ReadPassword(int(os.Stdin.Fd()))
	return pwd, error
}

// Read an encrypted file
// enc is the encrypted file path
// dst is the decrypted file path destination
// pr is only used for testing, and should be nil
func Decrypt(enc string, dst string, pr PasswordReader) (err error) {

	if pr == nil {
		pr = StdInPasswordReader{}
	}

	pw, err := getPassword(enc, pr)
	if err != nil {
		return
	}

	// Read from src
	ciphertext, err := ioutil.ReadFile(enc)
	if err != nil {
		return errors.New(fmt.Sprintf("Error Reading Ciphertext: %v", err))
	}

	plaintext, err := decBytes(ciphertext, pw)
	if err != nil {
		return
	}

	// Write to dst
	err = ioutil.WriteFile(dst, plaintext, 0644)
	if err != nil {
		return errors.New(fmt.Sprintf("Error writing decrypted file to disk: %v", err))
	}

	return nil
}

// Encrypt a plaintext file with a password from stdin
// plain is the plaintext file path
// dst is the destination filepath for the encrypted file
// pr is only used for testing, and should be nil
func Encrypt(plain string, dst string, pr PasswordReader) (err error) {

	if pr == nil {
		pr = StdInPasswordReader{}
	}

	pw, err := getPassword(plain, pr)
	if err != nil {
		return
	}

	plaintext, err := ioutil.ReadFile(plain)
	if err != nil {
		return errors.New(fmt.Sprintf("Error Reading File to Encrypt: %v", err))
	}

	ciphertext, err := encBytes(plaintext, pw)
	if err != nil {
		return
	}

	// Write out
	err = ioutil.WriteFile(dst, ciphertext, 0444)
	if err != nil {
		return errors.New(fmt.Sprintf("Error writing encrypted file to disk: %v", err))
	}

	return nil
}

func encBytes(plaintext []byte, pw []byte) (ciphertext []byte, err error) {

	//Choose a random nonce
	nonce := make([]byte, 12)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	//Choose a random salt
	//This hack reduces the security of the password hash,
	salt := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	key := (stretchPasswordToAES256Key(pw, salt))
	keyptr := (([32]byte)(key))

	ciphertext, err = encryptGCM(plaintext, &keyptr, nonce)
	if err != nil {
		ciphertext = nil
		return
	}

	// Save the salt for decryption
	ciphertext = append(ciphertext, salt...)

	return
}

func decBytes(ciphertext []byte, pw []byte) (plaintext []byte, err error) {

	// Recover salt from end of file
	salt := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	key := (stretchPasswordToAES256Key(pw, salt))
	keyptr := (([32]byte)(key))

	plaintext, err = decryptGCM(ciphertext, &keyptr)
	if err != nil {
		return []byte(""), errors.New(fmt.Sprintf("Decryption Failed: %v", err))
	}

	return
}

func stretchPasswordToAES256Key(pw []byte, salt []byte) []byte {
	return argon2.IDKey(pw, salt, 1, 64*1024, 4, 32)
}

// Get password bytes from user
func getPassword(filename string, pr PasswordReader) (pwd []byte, err error) {

	fmt.Println("Enter password for " + filename)

	pwd, err = pr.ReadPassword()

	if err != nil {
		return []byte(""), err
	}

	return pwd, nil
}

// The following is from https://github.com/gtank/cryptopasta/blob/master/encrypt.go
// It is in the public domain

// Encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func encryptGCM(plaintext []byte, key *[32]byte, nonce []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func decryptGCM(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}
