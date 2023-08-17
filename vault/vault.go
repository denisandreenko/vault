package vault

import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

// Config contains Hashcorp Vault backend configuration
type Config struct {
	Address        string `yaml:"address"`
	RoleID         string `yaml:"roleID"`
	SecretID       string `yaml:"secretID"`
	TLSCaCert      string `yaml:"tlsCaCert"`
	TLSClientCert  string `yaml:"tlsClientCert"`
	TLSClientKey   string `yaml:"tlsClientKey"`
	*TransitConfig `yaml:"transitConfig"`
	*SecretsConfig `yaml:"secretsConfig"`
}

type Vault struct {
	client     *api.Client
	RoleID     string
	SecretID   string
	transitCfg *TransitConfig
	secretsCfg *SecretsConfig
}

type SecretsConfig struct {
	MountPoint string `yaml:"mountPoint"`
}

// New creates new Hashicorp Vault backend
func New(cfg *Config) (*Vault, error) {
	vaultConfig := &api.Config{
		Address: cfg.Address,
	}

	// verify if address is https
	parsedurl, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("unable to parse vault address: %w", err)
	}
	if parsedurl.Scheme == "https" {
		tlsCfg := api.TLSConfig{
			CACert:     cfg.TLSCaCert,
			ClientCert: cfg.TLSClientCert,
			ClientKey:  cfg.TLSClientKey,
		}
		if err := vaultConfig.ConfigureTLS(&tlsCfg); err != nil {
			return nil, fmt.Errorf("unable to configure TLS: %w", err)
		}
	}

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}

	vault := &Vault{
		client:     client,
		RoleID:     cfg.RoleID,
		SecretID:   cfg.SecretID,
		transitCfg: cfg.TransitConfig,
		secretsCfg: cfg.SecretsConfig,
	}

	if err = vault.login(); err != nil {
		return nil, err
	}

	return vault, nil
}

func (v *Vault) login() error {
	appRoleAuth, err := auth.NewAppRoleAuth(v.RoleID, &auth.SecretID{FromString: v.SecretID})
	if err != nil {
		return fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := v.client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return fmt.Errorf("no auth info was returned after login")
	}

	return nil
}
