package rwcipher

import "testing"
import "os"
import "io/ioutil"
import "bytes"
import "errors"

type stubPasswordReader struct {
	Password    []byte
	ReturnError error
}

func (pr stubPasswordReader) ReadPassword() ([]byte, error) {
	if pr.ReturnError != nil {
		return []byte(""), pr.ReturnError
	}
	return pr.Password, nil
}

func TestEncryptDecrypt(t *testing.T) {

	spr := stubPasswordReader{Password: []byte("ThisPasswordISSUPERSECURE"), ReturnError: nil}

	Encrypt("./test/test.txt", "./test/test1.enc", spr)
	Decrypt("./test/test1.enc", "./test/test1.txt", spr)

	defer os.Remove("./test/test1.txt")
	defer os.Remove("./test/test1.enc")

	ciphertext, err := ioutil.ReadFile("./test/test1.enc")
	if err != nil {
		t.Fatal("Error reading file1 in test")
	}
	plaintext, err := ioutil.ReadFile("./test/test1.txt")
	if err != nil {
		t.Fatal("Error reading file2 in test")
	}

	ciphertext_exp, err := ioutil.ReadFile("./test/test1.enc")
	if err != nil {
		t.Fatal("Error reading file3 in test")
	}
	plaintext_exp, err := ioutil.ReadFile("./test/test1.txt")
	if err != nil {
		t.Fatal("Error reading file4 in test")
	}

	if bytes.Compare(plaintext, plaintext_exp) != 0 {
		t.Fatal("Encryption and Decryption were not inverses!")
	}
	if bytes.Compare(ciphertext, ciphertext_exp) != 0 {
		t.Fatal("Encryption and Decryption were not inverses!")
	}
}

// Thanks to https://petersouter.xyz/testing-and-mocking-stdin-in-golang/
// for the pattern for unit tests when password input is used
func TestGetPassword(t *testing.T) {
	tt := []struct {
		description string
		password    stubPasswordReader
	}{
		{"Normal Input", stubPasswordReader{Password: []byte("NormalPassword"), ReturnError: nil}},
		{"Error Condition", stubPasswordReader{Password: []byte("Iamfuzzing"), ReturnError: errors.New("wrong ioctl for device, yo")}},
	}

	test_filename := "./test/test.enc"

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {

			pw, err := getPassword(test_filename, tc.password)

			if tc.password.ReturnError == nil {
				if err != nil {
					t.Errorf("Error getting password: %v", err)
				}
				if bytes.Compare(tc.password.Password, pw) != 0 {
					t.Errorf("Got <<%s>>, expected <<%s>>", pw, tc.password.Password)
				}
			} else {
				if err == nil {
					t.Errorf("Error was not surfaced!")
				}
				if !errors.Is(err, tc.password.ReturnError) {
					t.Errorf("Wrong error surfaced: <<%v>>, expected <<%v>>", pw, tc.password.Password)
				}
			}
		})
	}
}

func TestPasswordStretchEncDec(t *testing.T) {
	pw := []byte("Thisisan awwesomepassword nobody will guess for sure yep.1!")
	msg := []byte("Super Secret Message")
	ciphertext, err := encBytes(msg, pw)
	if err != nil {
		t.Errorf("Error Encrypting: %v", err)
	}
	plaintext, err := decBytes(ciphertext, pw)
	if err != nil {
		t.Errorf("Error Decrypting: %v", err)
	}
	if bytes.Compare(msg, plaintext) != 0 {
		t.Errorf("Encryption and Decryption should be inverse functions!")
	}
}
