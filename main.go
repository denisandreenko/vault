package main

import (
	"fmt"
	"log"
	"os"

	"github.com/denisandreenko/vault/vault"

	"gopkg.in/yaml.v2"
)

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

	fmt.Println(v)
}
