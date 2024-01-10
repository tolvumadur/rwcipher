package main

import (
	"flag"
	"github.com/tolvumadur/rwcipher"
	"fmt"
	"os"
	"strings"
)

func init() {
	
}


func main() {

	// Collect command line input
	var dst = flag.String("o", "../test/test1.tmp", "output file")
	var src = flag.String("i", "../test/test.txt", "input file")
	var dec = flag.Bool("d", false, "set this flag for decrypting")
	var enc = flag.Bool("e", false, "set this flag for encrypting")
	var silent = flag.Bool("s", false, "set this flag to silence stdout")

	flag.Parse()

	// Validate boolean inputs
	if (*enc && *dec) || (!*enc && !*dec) {
		os.Stderr.WriteString("Must specify -d xor -e for decryption or encryption\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Report actions unless silent
	if !*silent {
		if *enc {
			fmt.Printf("Encrypting %s to outfile %s\n", *src, *dst)
		} else if *dec {
			fmt.Printf("Encrypting %s to outfile %s\n", *src, *dst)
		}
	}

	// Decrypt or Encrypt using rwcipher, report any error
	if *dec {
		err := rwcipher.Decrypt(*src, *dst, nil)
		if err != nil {
			if strings.Contains(err.Error(), "message authentication failed") {
				os.Stderr.WriteString("Decryption failed either due to a wrong password or altered ciphertext/nonce/salt in the encrypted file.\n")
			} else {
				os.Stderr.WriteString(fmt.Sprintf("Decryption Failed: %v\n", err))
			}
			os.Exit(4)
		}
	} else if *enc {
		err := rwcipher.Encrypt(*src, *dst, nil)
		if err != nil {
			fmt.Printf("Encryption Failed: %v\n", err)
			os.Exit(3)
		}
	} else {
		os.Stderr.WriteString("Unknown operation requested\n")
		flag.PrintDefaults()
		os.Exit(2)
	}
	 
	if !*silent {
		fmt.Println("Operation Successful.\n")
	}
	
	os.Exit(0)
}

