//go:build ignore

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile("../config/keys/jwt_private.pem", privPEM, 0600); err != nil {
		panic(err)
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1})
	if err := os.WriteFile("../config/keys/jwt_public.pem", pubPEM, 0644); err != nil {
		panic(err)
	}

	fmt.Println("Keys generated successfully in ../config/keys/")
}
