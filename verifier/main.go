package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"encoding/base64"
	"errors"
)

const blockTypePublicKey = "PUBLIC KEY"

func main()  {
	challenge := "mahmoud"
	signatureString := "Bob/ff0HDEfJUUsA1pzTkdL4CrbCgOemuYXpfTqHO14fJZLmeDURSUftDU2R17+uo63b4SvelzfP334FYWRFpAgAm5DDUFr5Up02QzzxV6rbon6q5ce4UWvCXq7qimC996StVirgiLmzhruVzNWUhsRHLTTViMyzRqYUavLTxcwix3hNNknbS+Dfa8cQwJvQ0AcQfZf+Lb0ijaQ/804fL7AbNB0VN7UuHEZhbsjuL4OZXPZ9qUWjrRX0E3H6WPsTfx8KOYX+V1qIjDxCnwH/udnAy4Gtt6VWbbj3AIy5WqW/uZjxyIbOswvHxUxVFmbdZj0CX1viuxn2ggaALHFQmw=="
	publicKeyPem := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg1eh1y7wpH5czddAQ196
refwEsuU4C4QglNnAYBNGIOp1owjrUC+FRItWcW3o18gfRofrR+zYmf8VmLqPYW5
gEvK27s8JsFCodPACSf2embLYC48uC/O/fGs86kd39/0PRASSqGNw8C7X2Jd1AS6
QHquO+EeSVhi5HjDKFhuqYF8Gy7xSjHKDeWd7KJRPYBxqha+3hXGAEvmjaeY23Fg
gmaELBf3T5gv7xrm//+XOdqGSEpbpCPurhvaF+RuHyIlnZDmO0i2zRNPYaoPgO+N
hwB6RcwfrdxkEGYY2JtvejWNgzbUVR4x66dr73Bhuat5awtV5lG9eUCnVNTJjWFy
fwIDAQAB
-----END PUBLIC KEY-----`
	
	pubKey, err := parsePublicKey(publicKeyPem)
	if err != nil {
		panic(err)
	}

	challengeDigest := sha256.Sum256([]byte(challenge))

	signatureDecoded, err := base64.StdEncoding.DecodeString(signatureString)
	if err != nil {
		panic(err)
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, challengeDigest[:], signatureDecoded)
	if err != nil {
		panic(err)
	}
}

func parsePublicKey(key string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil || block.Type != blockTypePublicKey {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("error parsing public key as rsa public key")
	}

	return publicKey, nil
}
