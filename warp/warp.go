package warp

import (
	"crypto/sha256"
	"fmt"

	"github.com/vsergeev/btckeygenie/btckey"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

func blockXOR(dst, src []byte, n int) {
	for i, v := range src[:n] {
		dst[i] ^= v
	}
}

func createScryptSeed(key string, salt string, c chan []byte) {
	dk, err := scrypt.Key([]byte(key+"\u0001"), []byte(salt+"\u0001"), 262144, 8, 1, 32)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
	}
	c <- dk
}

func createPbkdf2Seed(key string, salt string, c chan []byte) {
	dk := pbkdf2.Key([]byte(key+"\u0002"), []byte(salt+"\u0002"), 65536, 32, sha256.New)
	c <- dk
}

func createSeeds(passphrase string, salt string) []byte {
	scryptChannel := make(chan []byte)
	pbkdf2Channel := make(chan []byte)

	go createScryptSeed(passphrase, salt, scryptChannel)
	go createPbkdf2Seed(passphrase, salt, pbkdf2Channel)

	scryptKey := <-scryptChannel
	pbkdf2Key := <-pbkdf2Channel
	finalKey := make([]byte, 32)
	copy(finalKey, scryptKey)
	blockXOR(finalKey, pbkdf2Key, 32)

	return finalKey
}

func createBitcoinAddress(secret []byte) (string, string) {
	var priv btckey.PrivateKey

	err := priv.FromBytes(secret)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
	}
	return priv.ToAddressUncompressed(), priv.ToWIF()
}

// Generate a address & private key from passphrase & salt using the WarpWallet algorithm
func Generate(passphrase string, salt string) (string, string) {
	finalKey := createSeeds(passphrase, salt)
	return createBitcoinAddress(finalKey)
}
