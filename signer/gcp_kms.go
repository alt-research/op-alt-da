package signer

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	secp256k1x509 "github.com/MetaMask/go-did-it/crypto/secp256k1"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	errUnsupportedGCPKMSOp = errors.New("gcp kms keyring: operation not supported")
	crc32cTable            = crc32.MakeTable(crc32.Castagnoli)
)

type gcpKMSClient interface {
	GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error)
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

type gcpKMSKeyring struct {
	ctx context.Context

	client       gcpKMSClient
	resourceName string
	record       *keyring.Record
	pubKey       cryptotypes.PubKey
	address      string
}

// NewGCPKMSKeyring creates a single-key Cosmos SDK keyring backed by one
// explicitly pinned GCP Cloud KMS CryptoKeyVersion. ADC is used by default;
// CredentialsFile is intended only for development or controlled migration.
func NewGCPKMSKeyring(cfg GCPKMSConfig) (keyring.Keyring, string, error) {
	if err := cfg.Validate(); err != nil {
		return nil, "", fmt.Errorf("invalid gcp_kms config: %w", err)
	}

	ctx := context.Background()
	var opts []option.ClientOption
	if cfg.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(cfg.CredentialsFile))
	}

	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("create gcp kms client: %w", err)
	}

	kr, err := newGCPKMSKeyring(ctx, cfg, client)
	if err != nil {
		_ = client.Close()
		return nil, "", err
	}

	// The client connection intentionally lives for the DA server process
	// lifetime. keyring.Keyring has no Close method and the signer is constructed
	// once during startup.
	return kr, kr.resourceName, nil
}

func newGCPKMSKeyring(ctx context.Context, cfg GCPKMSConfig, client gcpKMSClient) (*gcpKMSKeyring, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid gcp_kms config: %w", err)
	}
	if client == nil {
		return nil, errors.New("gcp kms client is nil")
	}

	kr := &gcpKMSKeyring{
		ctx:          ctx,
		client:       client,
		resourceName: gcpKMSKeyVersionResourceName(cfg),
	}
	if err := kr.loadKey(); err != nil {
		return nil, err
	}
	return kr, nil
}

func gcpKMSKeyVersionResourceName(cfg GCPKMSConfig) string {
	return fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
		cfg.Project,
		cfg.Location,
		cfg.KeyRing,
		cfg.Key,
		cfg.KeyVersion,
	)
}

func (k *gcpKMSKeyring) loadKey() error {
	response, err := k.client.GetPublicKey(k.ctx, &kmspb.GetPublicKeyRequest{Name: k.resourceName})
	if err != nil {
		return fmt.Errorf("get gcp kms public key: %w", err)
	}
	if response.GetName() != k.resourceName {
		return fmt.Errorf("gcp kms public key resource mismatch: got %q, want %q", response.GetName(), k.resourceName)
	}
	if response.GetAlgorithm() != kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256 {
		return fmt.Errorf("gcp kms key algorithm must be EC_SIGN_SECP256K1_SHA256, got %s", response.GetAlgorithm())
	}
	if !isGCPHSMProtectionLevel(response.GetProtectionLevel()) {
		return fmt.Errorf("gcp kms secp256k1 key must use HSM protection, got %s", response.GetProtectionLevel())
	}
	if response.GetPem() == "" {
		return errors.New("gcp kms returned an empty public key")
	}
	if err := verifyCRC32C([]byte(response.GetPem()), response.GetPemCrc32C(), "public key PEM"); err != nil {
		return err
	}

	pubKey, err := gcpKMSPEMToCosmos(response.GetPem())
	if err != nil {
		return err
	}
	anyPub, err := types.NewAnyWithValue(pubKey)
	if err != nil {
		return fmt.Errorf("pack gcp kms public key: %w", err)
	}

	k.pubKey = pubKey
	k.address = sdk.AccAddress(pubKey.Address()).String()
	k.record = &keyring.Record{
		Name:   k.resourceName,
		PubKey: anyPub,
		Item:   &keyring.Record_Offline_{Offline: &keyring.Record_Offline{}},
	}
	return nil
}

func gcpKMSPEMToCosmos(publicKeyPEM string) (cryptotypes.PubKey, error) {
	block, rest := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("decode gcp kms public key PEM")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected gcp kms PEM block type %q", block.Type)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("gcp kms public key PEM contains trailing data")
	}

	publicKey, err := secp256k1x509.PublicKeyFromX509DER(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse gcp kms secp256k1 public key: %w", err)
	}
	return &secp256k1.PubKey{Key: publicKey.ToBytes()}, nil
}

func isGCPHSMProtectionLevel(level kmspb.ProtectionLevel) bool {
	return level == kmspb.ProtectionLevel_HSM || level == kmspb.ProtectionLevel_HSM_SINGLE_TENANT
}

func crc32c(data []byte) int64 {
	return int64(crc32.Checksum(data, crc32cTable))
}

func verifyCRC32C(data []byte, expected *wrapperspb.Int64Value, field string) error {
	if expected == nil {
		return fmt.Errorf("gcp kms did not return CRC32C for %s", field)
	}
	actual := crc32c(data)
	if expected.GetValue() != actual {
		return fmt.Errorf("gcp kms %s CRC32C mismatch: got %d, want %d", field, expected.GetValue(), actual)
	}
	return nil
}

func (k *gcpKMSKeyring) Backend() string { return ModeGCPKMS }

func (k *gcpKMSKeyring) List() ([]*keyring.Record, error) {
	return []*keyring.Record{k.record}, nil
}

func (k *gcpKMSKeyring) SupportedAlgorithms() (keyring.SigningAlgoList, keyring.SigningAlgoList) {
	algorithms := keyring.SigningAlgoList{hd.Secp256k1}
	return algorithms, algorithms
}

func (k *gcpKMSKeyring) Key(uid string) (*keyring.Record, error) {
	if uid != k.resourceName {
		return nil, sdkerrors.ErrKeyNotFound
	}
	return k.record, nil
}

func (k *gcpKMSKeyring) KeyByAddress(address sdk.Address) (*keyring.Record, error) {
	if address.String() != k.address {
		return nil, sdkerrors.ErrKeyNotFound
	}
	return k.record, nil
}

func (k *gcpKMSKeyring) Sign(uid string, message []byte, _ signing.SignMode) ([]byte, cryptotypes.PubKey, error) {
	if uid != k.resourceName {
		return nil, nil, sdkerrors.ErrKeyNotFound
	}

	digest := sha256.Sum256(message)
	response, err := k.client.AsymmetricSign(k.ctx, &kmspb.AsymmetricSignRequest{
		Name: k.resourceName,
		Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{
			Sha256: digest[:],
		}},
		DigestCrc32C: wrapperspb.Int64(crc32c(digest[:])),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("gcp kms sign: %w", err)
	}
	if response.GetName() != k.resourceName {
		return nil, nil, fmt.Errorf("gcp kms signing resource mismatch: got %q, want %q", response.GetName(), k.resourceName)
	}
	if !isGCPHSMProtectionLevel(response.GetProtectionLevel()) {
		return nil, nil, fmt.Errorf("gcp kms signing response is not HSM protected: %s", response.GetProtectionLevel())
	}
	if !response.GetVerifiedDigestCrc32C() {
		return nil, nil, errors.New("gcp kms did not verify the digest CRC32C")
	}
	if err := verifyCRC32C(response.GetSignature(), response.GetSignatureCrc32C(), "signature"); err != nil {
		return nil, nil, err
	}

	signature, err := gcpKMSDERSignatureToCosmos(response.GetSignature())
	if err != nil {
		return nil, nil, err
	}
	return signature, k.pubKey, nil
}

func (k *gcpKMSKeyring) SignByAddress(address sdk.Address, message []byte, signMode signing.SignMode) ([]byte, cryptotypes.PubKey, error) {
	if address.String() != k.address {
		return nil, nil, sdkerrors.ErrKeyNotFound
	}
	return k.Sign(k.resourceName, message, signMode)
}

func gcpKMSDERSignatureToCosmos(der []byte) ([]byte, error) {
	signature, err := secp256k1ecdsa.ParseDERSignature(der)
	if err != nil {
		return nil, fmt.Errorf("parse gcp kms DER signature: %w", err)
	}

	r := signature.R()
	s := signature.S()
	if s.IsOverHalfOrder() {
		s = *new(dcrsecp256k1.ModNScalar).NegateVal(&s)
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	result := make([]byte, 64)
	copy(result[:32], rBytes[:])
	copy(result[32:], sBytes[:])
	return result, nil
}

// GCP Cloud KMS owns key lifecycle. This keyring intentionally implements
// signing and lookup only.
func (k *gcpKMSKeyring) Delete(string) error               { return errUnsupportedGCPKMSOp }
func (k *gcpKMSKeyring) DeleteByAddress(sdk.Address) error { return errUnsupportedGCPKMSOp }
func (k *gcpKMSKeyring) Rename(string, string) error       { return errUnsupportedGCPKMSOp }
func (k *gcpKMSKeyring) NewMnemonic(string, keyring.Language, string, string, keyring.SignatureAlgo) (*keyring.Record, string, error) {
	return nil, "", errUnsupportedGCPKMSOp
}
func (k *gcpKMSKeyring) NewAccount(string, string, string, string, keyring.SignatureAlgo) (*keyring.Record, error) {
	return nil, errUnsupportedGCPKMSOp
}
func (k *gcpKMSKeyring) SaveLedgerKey(string, keyring.SignatureAlgo, string, uint32, uint32, uint32) (*keyring.Record, error) {
	return nil, errUnsupportedGCPKMSOp
}
func (k *gcpKMSKeyring) SaveOfflineKey(string, cryptotypes.PubKey) (*keyring.Record, error) {
	return nil, errUnsupportedGCPKMSOp
}
func (k *gcpKMSKeyring) SaveMultisig(string, cryptotypes.PubKey) (*keyring.Record, error) {
	return nil, errUnsupportedGCPKMSOp
}
func (k *gcpKMSKeyring) ImportPrivKey(string, string, string) error {
	return errUnsupportedGCPKMSOp
}
func (k *gcpKMSKeyring) ImportPrivKeyHex(string, string, string) error {
	return errUnsupportedGCPKMSOp
}
func (k *gcpKMSKeyring) ImportPubKey(string, string) error { return errUnsupportedGCPKMSOp }
func (k *gcpKMSKeyring) ExportPubKeyArmor(string) (string, error) {
	return "", errUnsupportedGCPKMSOp
}
func (k *gcpKMSKeyring) ExportPubKeyArmorByAddress(sdk.Address) (string, error) {
	return "", errUnsupportedGCPKMSOp
}
func (k *gcpKMSKeyring) ExportPrivKeyArmor(string, string) (string, error) {
	return "", errUnsupportedGCPKMSOp
}
func (k *gcpKMSKeyring) ExportPrivKeyArmorByAddress(sdk.Address, string) (string, error) {
	return "", errUnsupportedGCPKMSOp
}
func (k *gcpKMSKeyring) MigrateAll() ([]*keyring.Record, error) {
	return nil, errUnsupportedGCPKMSOp
}
