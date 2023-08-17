package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards/eddsa"
	"github.com/denisandreenko/vault/vault"

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

	keyBlock, _ := pem.Decode([]byte(wrappingKeyString))
	if keyBlock == nil {
		log.Fatal("failed to decode PEM block")
	}
	pubKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		log.Fatalf("failed to parse public key: %v", err)
	}
	pkKey := &Key{PubKey: pubKey.(*eddsa.PublicKey)}

	fmt.Println("Pub Key: ", pkKey.ID)
}
