package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"
)

// The default password length, if run without any options.
var defaultCodeSize int = 12
var codeSize int
var secretCode, shortCode, secureID, hexCode, encodedSecureID string
var secretSha256Sum [32]byte
var secretCodeSeed [90]string = [90]string{
	"w", "l", "f",
	"`", "~", "#",
	"j", "k", "p",
	")", "%", "&",
	"g", "h", "e",
	"m", "d", "o",
	"*", "^", "!",
	"i", "q", "v",
	"s", "y", "u",
	"r", "c", "x",
	";", ":", "\\",
	"a", "z", "Z",
	"Y", "U", "W",
	"|", "]", "}",
	"V", "X", "T",
	"O", "R", "Q",
	"[", "{", "+",
	"P", "L", "N",
	"$", "@", "(",
	"M", "S", "D",
	"J", "F", "H",
	"?", ".", ">",
	"G", "K", "E",
	",", "<", "-",
	"I", "A", "B",
	"C", "9", "8",
	"7", "6", "1",
	"5", "2", "3",
	"4", "0", "/",
	"t", "b", "n"}

func main() {
	if codeSize < defaultCodeSize {
		codeSize = defaultCodeSize
	}
	secretCode = SecretCode(codeSize)
	secretSha256Sum = sha256.Sum256([]byte(secretCode[:codeSize]))
	encodedSecureID = string(hex.EncodeToString(secretSha256Sum[:]))
	shortCode = string(encodedSecureID[:8])
	hexCode = string(encodedSecureID[:])
	secureID = string(encodedSecureID[:8]) + "-" +
		string(encodedSecureID[8:12]) + "-" +
		string(encodedSecureID[12:16]) + "-" +
		string(encodedSecureID[16:20]) + "-" +
		string(encodedSecureID[20:32])

	if len(os.Args[1:]) > 0 {
		if len(os.Args[2:]) > 0 && os.Args[2] == "-base64" {
			var err error
			codeSize, err = strconv.Atoi(os.Args[1])
			if err != nil {
				fmt.Println("Usage: passworder (<number> [-base64]) [-sha256] [-uuid] [-short]")
				return
			} else {
				if codeSize < 4097 {
					secretCode = SecretCode(codeSize)
					secretBase64 := base64.StdEncoding.EncodeToString([]byte(secretCode[:codeSize]))
					fmt.Println(secretBase64)
				} else {
					fmt.Printf("%v exceeds maximum allowed length of 4096.\n", codeSize)
				}
			}
		}
		if len(os.Args[2:]) > 0 && os.Args[2] != "-base64" {
			fmt.Println("Usage: passworder (<number> [-base64]) [-sha256] [-uuid] [-short]")
			return
		}
		if len(os.Args[1:]) > 0 && len(os.Args[2:]) == 0 {
			options(os.Args[1])
		}
	} else {

		secretCode = SecretCode(codeSize)
		secretBase64 := base64.StdEncoding.EncodeToString([]byte(secretCode[:codeSize]))
		fmt.Printf("Secret: %s\n", secretCode)
		fmt.Printf("Secret Base64: %s\n", secretBase64)
		fmt.Printf("UUID: %s\n", secureID)
		fmt.Printf("Short Code: %s\n", shortCode)
		fmt.Printf("Secret SHA256: %s\n", encodedSecureID)
	}
}

func options(op string) {
	switch {
	case op == "-base64":
		secretBase64 := base64.StdEncoding.EncodeToString([]byte(secretCode[:codeSize]))
		fmt.Println(secretBase64)
		break
	case op == "-sha256":
		fmt.Println(encodedSecureID)
		break
	case op == "-short":
		fmt.Println(shortCode)
		break
	case op == "-uuid":
		fmt.Println(secureID)
		break
	default:
		var err error
		codeSize, err = strconv.Atoi(op)
		if err != nil {
			fmt.Println("Usage: passworder (<number> [-base64]) [-sha256] [-uuid] [-short]")
			return
		} else {
			if codeSize < 4097 {
				secretCode = SecretCode(codeSize)
				secretBase64 := base64.StdEncoding.EncodeToString([]byte(secretCode[:codeSize]))
				fmt.Printf("Secret: %s\n", secretCode)
				fmt.Printf("Secret Base64: %s\n", secretBase64)
			} else {
				fmt.Printf("%v exceeds maximum allowed length of 4096.\n", codeSize)
			}
		}
	}
}

func SecretCode(rotations int) string {
	var s string
	v := make([]int, rotations)
	// Populate array "v" with "n" number of random
	// characters selected from []string "secretCodeSeed".
	for n := 0; n < rotations; n++ {
		rand.Seed(time.Now().UnixNano())
		for _, value := range rand.Perm(len(secretCodeSeed)) {
			v[n] = value
		}
	}
	// Generate "x" amount of random characters
	// according to int specified with "rotations".
	for x := 0; x < rotations; x++ {
		s = s + secretCodeSeed[v[x]]
	}
	return s
}
