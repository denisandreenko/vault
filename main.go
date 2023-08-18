package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards/eddsa"
	"github.com/denisandreenko/vault/vault"
	"github.com/ecadlabs/signatory/pkg/crypt"

	"gopkg.in/yaml.v2"
)

type Key struct {
	ID     string
	PubKey *eddsa.PublicKey
}

func main() {
	configYaml, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}

	var cfg vault.Config
	if err := yaml.Unmarshal(configYaml, &cfg); err != nil {
		log.Fatalf("Error unmarshaling YAML: %v", err)
	}

	v, err := vault.New(&cfg)
	if err != nil {
		log.Fatalf("Vault initialization error: %v", err)
	}

	keys, err := v.Transit().ListKeys()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(keys)

	wrappingKeyString, err := v.Transit().GetKey(keys[0])
	if err != nil {
		log.Fatal(err)
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(wrappingKeyString)
	if err != nil {
		log.Fatal(err)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		log.Fatal("invalid public key length")
	}

	// Convert the bytes to an Ed25519 public key
	eddsaPublicKey := ed25519.PublicKey(pubKeyBytes)

	cryptPubKey, err := crypt.NewPublicKeyFrom(eddsaPublicKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(cryptPubKey)
}
