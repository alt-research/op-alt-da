package signer

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Mode constants for signer backends.
const (
	ModeLocal     = "local"
	ModePOPSigner = "popsigner"
	ModeAWSKMS    = "aws_kms"
	ModeGCPKMS    = "gcp_kms"
	ModeVault     = "vault"
)

// Config holds the complete signer configuration.
// Only one backend should be configured based on the Mode field.
type Config struct {
	// Mode specifies which signer backend to use.
	// Valid values: "local", "popsigner", "aws_kms", "gcp_kms", "vault"
	Mode string `toml:"mode"`

	// Local contains configuration for filesystem-based keyring.
	Local LocalConfig `toml:"local"`

	// POPSigner contains configuration for POPSigner remote signing.
	POPSigner POPSignerConfig `toml:"popsigner"`

	// AWSKMS contains configuration for AWS KMS signing.
	AWSKMS AWSKMSConfig `toml:"aws_kms"`

	// GCPKMS contains configuration for GCP Cloud KMS signing.
	GCPKMS GCPKMSConfig `toml:"gcp_kms"`

	// Vault contains configuration for HashiCorp Vault Transit signing (future).
	Vault VaultConfig `toml:"vault"`
}

// LocalConfig holds configuration for the local filesystem keyring.
type LocalConfig struct {
	// BackendName is the cosmos-sdk keyring backend name.
	// Example values: "test", "file", "os", "memory"
	BackendName string `toml:"backend"`

	// KeyringPath is the path to the keyring directory.
	// Example: "~/.celestia-light-mocha-4/keys"
	KeyringPath string `toml:"keyring_path"`

	// KeyName is the name of the key to use from the keyring.
	KeyName string `toml:"key_name"`
}

// POPSignerConfig holds configuration for POPSigner remote signing.
type POPSignerConfig struct {
	// APIKey is the POPSigner API key.
	// Can also be set via POPSIGNER_API_KEY environment variable.
	APIKey string `toml:"api_key"`

	// KeyID is the UUID of the key to use for signing.
	KeyID string `toml:"key_id"`

	// BaseURL is an optional custom API endpoint.
	// If empty, the default POPSigner API URL is used.
	BaseURL string `toml:"base_url"`
}

// AWSKMSConfig holds configuration for AWS KMS signing.
type AWSKMSConfig struct {
	// Region is the AWS region where the KMS key is located.
	Region string `toml:"region"`

	// Endpoint is an optional custom KMS endpoint.
	Endpoint string `toml:"endpoint"`

	// KeyID is the ARN or alias of the KMS key.
	KeyID string `toml:"key_id"`

	// AccessKeyID is the AWS access key ID (optional, can use IAM role).
	AccessKeyID string `toml:"access_key_id"`

	// SecretAccessKey is the AWS secret access key (optional).
	SecretAccessKey string `toml:"secret_access_key"`
}

// GCPKMSConfig holds configuration for GCP Cloud KMS signing.
type GCPKMSConfig struct {
	// Project is the GCP project ID.
	Project string `toml:"project"`

	// Location is the GCP location (e.g., "us-east1").
	Location string `toml:"location"`

	// KeyRing is the name of the key ring.
	KeyRing string `toml:"key_ring"`

	// Key is the name of the crypto key.
	Key string `toml:"key"`

	// KeyVersion is the numeric CryptoKeyVersion. It is required because each
	// asymmetric key version has a different public key and Celestia address.
	KeyVersion string `toml:"key_version"`

	// CredentialsFile is the path to the service account JSON file (optional).
	CredentialsFile string `toml:"credentials_file"`
}

// VaultConfig holds configuration for HashiCorp Vault Transit signing (future implementation).
type VaultConfig struct {
	// Address is the Vault server address.
	Address string `toml:"address"`

	// Token is the Vault authentication token.
	// Can also be set via VAULT_TOKEN environment variable.
	Token string `toml:"token"`

	// TransitPath is the path to the Transit secrets engine.
	// Default: "transit"
	TransitPath string `toml:"transit_path"`

	// KeyName is the name of the key in the Transit engine.
	KeyName string `toml:"key_name"`

	// Namespace is the Vault namespace (enterprise only).
	Namespace string `toml:"namespace"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Mode: ModeLocal,
		Local: LocalConfig{
			BackendName: "test",
			KeyName:     "my_celes_key",
		},
		Vault: VaultConfig{
			TransitPath: "transit",
		},
	}
}

// Validate checks the configuration for errors based on the selected mode.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeLocal:
		if c.Local.KeyringPath == "" {
			return fmt.Errorf("signer.local.keyring_path is required when mode is '%s'", ModeLocal)
		}
		if c.Local.KeyName == "" {
			return fmt.Errorf("signer.local.key_name is required when mode is '%s'", ModeLocal)
		}

	case ModePOPSigner:
		if c.POPSigner.KeyID == "" {
			return fmt.Errorf("signer.popsigner.key_id is required when mode is '%s'", ModePOPSigner)
		}
		// API key can come from environment variable
		if c.POPSigner.APIKey == "" && os.Getenv("POPSIGNER_API_KEY") == "" {
			return fmt.Errorf("signer.popsigner.api_key is required when mode is '%s' (or set POPSIGNER_API_KEY env var)", ModePOPSigner)
		}

	case ModeAWSKMS:
		if c.AWSKMS.Region == "" {
			return fmt.Errorf("signer.aws_kms.region is required when mode is '%s'", ModeAWSKMS)
		}
		if c.AWSKMS.KeyID == "" && c.Local.KeyName == "" {
			return fmt.Errorf("signer.aws_kms.key_id is required when mode is '%s'", ModeAWSKMS)
		}

	case ModeGCPKMS:
		if err := c.GCPKMS.Validate(); err != nil {
			return fmt.Errorf("signer.gcp_kms: %w", err)
		}

	case ModeVault:
		return fmt.Errorf("signer mode '%s' is not yet implemented", ModeVault)

	case "":
		// Empty mode defaults to local, which needs validation
		if c.Local.KeyringPath == "" {
			return fmt.Errorf("signer.local.keyring_path is required when mode is '%s' (default)", ModeLocal)
		}

	default:
		return fmt.Errorf("unknown signer mode: %s (valid: %s, %s, %s, %s, %s)",
			c.Mode, ModeLocal, ModePOPSigner, ModeAWSKMS, ModeGCPKMS, ModeVault)
	}

	return nil
}

// Validate checks that the GCP KMS resource is explicit and stable. In
// particular, key_version must never float to a new primary version because
// that would silently change the Celestia account address.
func (c *GCPKMSConfig) Validate() error {
	fields := []struct {
		name  string
		value string
	}{
		{name: "project", value: c.Project},
		{name: "location", value: c.Location},
		{name: "key_ring", value: c.KeyRing},
		{name: "key", value: c.Key},
		{name: "key_version", value: c.KeyVersion},
	}

	for _, field := range fields {
		if field.value == "" {
			return fmt.Errorf("%s is required", field.name)
		}
		if strings.Contains(field.value, "/") {
			return fmt.Errorf("%s must be an ID, not a resource path", field.name)
		}
	}

	version, err := strconv.ParseUint(c.KeyVersion, 10, 64)
	if err != nil || version == 0 {
		return fmt.Errorf("key_version must be a positive integer")
	}

	return nil
}

// ResolveAPIKey returns the POPSigner API key, checking environment variable as fallback.
func (c *POPSignerConfig) ResolveAPIKey() string {
	if c.APIKey != "" {
		return c.APIKey
	}
	return os.Getenv("POPSIGNER_API_KEY")
}

// ResolveToken returns the Vault token, checking environment variable as fallback.
func (c *VaultConfig) ResolveToken() string {
	if c.Token != "" {
		return c.Token
	}
	return os.Getenv("VAULT_TOKEN")
}
