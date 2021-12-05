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

var codeSize int

func main() {

	if len(os.Args[1:]) > 0 {
		if os.Args[1] != "help" &&
			os.Args[1] != "-help" &&
			os.Args[1] != "--help" &&
			os.Args[1] != "-sha256" &&
			os.Args[1] != "-uuid" &&
			os.Args[1] != "-short" {
			var err error
			codeSize, err = strconv.Atoi(os.Args[1])
			if err != nil {
				fmt.Println("Usage: passworder [length] [-sha256] [-uuid] [-short]")
				return
			} else {
				if codeSize < 12 || codeSize > 4096 {
					codeSize = 12
				}
			}
		}
	} else {
		codeSize = 12
	}

	var secretCode string = SecretCode(codeSize)
	secretSha256Sum := sha256.Sum256([]byte(secretCode[:]))
	encodedSecureID := string(hex.EncodeToString(secretSha256Sum[:]))
	var shortCode string = string(encodedSecureID[:8])
	var secureID string = string(encodedSecureID[:8]) + "-" +
		string(encodedSecureID[8:12]) + "-" +
		string(encodedSecureID[12:16]) + "-" +
		string(encodedSecureID[16:20]) + "-" +
		string(encodedSecureID[20:32])

	if len(os.Args[1:]) > 0 {
		if os.Args[1] == "help" ||
			os.Args[1] == "-help" ||
			os.Args[1] == "--help" {
			fmt.Println("Usage: passworder [length] [-sha256] [-uuid] [-short]")
			return
		}
		if os.Args[1] == "-uuid" {
			fmt.Println(secureID)
			return
		}
		if os.Args[1] == "-short" {
			fmt.Println(shortCode)
			return
		}
		if os.Args[1] == "-sha256" {
			fmt.Println(encodedSecureID)
			return
		}
	}

	if len(secretCode) > 0 && codeSize == 12 {
		fmt.Printf("UUID: %s\n", secureID)
		fmt.Printf("Short Code: %s\n", shortCode)
		fmt.Printf("Secret: %s\n", secretCode)
		fmt.Printf("Secret SHA256: %s\n", encodedSecureID)
		return
	}
	if len(secretCode) > 0 && codeSize > 12 {
		fmt.Println(secretCode)
		return
	}
	if len(secretCode) == 0 || codeSize == 0 {
		fmt.Println("Usage: passworder [length] [-sha256] [-uuid] [-short]")
		return
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
