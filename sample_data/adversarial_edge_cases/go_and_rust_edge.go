package main

import (
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// Go Cryptographic Edge Cases
func ExecuteCryptoOperations() {
	// Case 1: Insecure 3DES cipher in Go
	tripleDesKey := []byte("example key 123456789012")
	_, err := des.NewTripleDESCipher(tripleDesKey)
	if err != nil {
		fmt.Println("3DES Init Error:", err)
	}

	// Case 2: Shor's vulnerable RSA-2048 in Go
	privRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	fmt.Printf("Generated RSA Key: %v\n", privRSA.PublicKey.N)

	// Case 3: Shor's vulnerable P-224 curve in Go
	privECDSA, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	fmt.Printf("Generated ECDSA Key on P-224: %v\n", privECDSA.PublicKey.X)
}
