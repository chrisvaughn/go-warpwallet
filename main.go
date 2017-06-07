package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/chrisvaughn/go-warpwallet/warp"
)

var src = rand.NewSource(time.Now().UnixNano())

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func main() {
	salt := flag.String("S", "", "salt used for generating the warpwallet")
	address := flag.String("A", "", "Address to match")
	concurrency := flag.Int("C", 5, "# of concurrent attempts")
	flag.Parse()

	if *address == "" {
		flag.Usage()
		os.Exit(1)
	}
	sem := make(chan bool, *concurrency)
	fmt.Printf("Using address \"%s\" and salt \"%s\"\n", *address, *salt)

	tries := 0
	start := time.Now()

	for {
		sem <- true
		go func() {
			defer func() { <-sem }()
			passphrase := randString(8)
			generatedAddress, generatePrivate := warp.Generate(passphrase, *salt)
			if generatedAddress == *address {
				fmt.Printf("Found! Passphrase %s, private key %s\n", passphrase, generatePrivate)
				os.Exit(0)
			} else {
				tries++
				if (tries % *concurrency) == 0 {
					fmt.Printf("\rTried %d passphrases in %s [last passphrase: %s]", tries, time.Since(start), passphrase)
				}
			}
		}()
	}
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}
}

func randString(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
