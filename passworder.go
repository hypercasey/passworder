package main

import (
	"crypto/sha256"
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
var secretCode, shortCode, secureID, encodedSecureID string
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
	if codeSize < defaultCodeSize || codeSize > 4096 {
		codeSize = defaultCodeSize
	}
	secretCode = SecretCode(codeSize)
	secretSha256Sum = sha256.Sum256([]byte(secretCode[:]))
	encodedSecureID = string(hex.EncodeToString(secretSha256Sum[:]))
	shortCode = string(encodedSecureID[:8])
	secureID = string(encodedSecureID[:8]) + "-" +
		string(encodedSecureID[8:12]) + "-" +
		string(encodedSecureID[12:16]) + "-" +
		string(encodedSecureID[16:20]) + "-" +
		string(encodedSecureID[20:32])

	if len(os.Args[1:]) > 0 && len(os.Args[1:]) < 8 {
		options(os.Args[1])
	} else {
		fmt.Printf("UUID: %s\n", secureID)
		fmt.Printf("Short Code: %s\n", shortCode)
		fmt.Printf("Secret: %s\n", secretCode)
		fmt.Printf("Secret SHA256: %s\n", encodedSecureID)
	}
}

func options(op string) {
	switch {
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
			fmt.Println("Usage: passworder [length] [-sha256] [-uuid] [-short]")
			return
		} else {
			if codeSize < 4097 {
				secretCode = SecretCode(codeSize)
				fmt.Println(secretCode)
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
