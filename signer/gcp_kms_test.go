package signer

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	secp256k1x509 "github.com/MetaMask/go-did-it/crypto/secp256k1"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func validGCPKMSConfig() GCPKMSConfig {
	return GCPKMSConfig{
		Project:    "example-project",
		Location:   "us-east1",
		KeyRing:    "celestia",
		Key:        "op-alt-da",
		KeyVersion: "1",
	}
}

type mockGCPKMSClient struct {
	privateKey *dcrsecp256k1.PrivateKey
	publicKey  *kmspb.PublicKey

	getPublicKeyErr error
	signErr         error
	mutateSignature func(*kmspb.AsymmetricSignResponse)
	lastSignRequest *kmspb.AsymmetricSignRequest
}

func newMockGCPKMSClient(t *testing.T, cfg GCPKMSConfig) *mockGCPKMSClient {
	t.Helper()

	privateKey, err := dcrsecp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	publicKey := privateKey.PubKey()
	wrappedPublicKey, err := secp256k1x509.PublicKeyFromXY(publicKey.X().Bytes()[:], publicKey.Y().Bytes()[:])
	require.NoError(t, err)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wrappedPublicKey.ToX509DER()})
	resourceName := gcpKMSKeyVersionResourceName(cfg)

	return &mockGCPKMSClient{
		privateKey: privateKey,
		publicKey: &kmspb.PublicKey{
			Pem:             string(publicKeyPEM),
			PemCrc32C:       wrapperspb.Int64(crc32c(publicKeyPEM)),
			Name:            resourceName,
			Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
		},
	}
}

func (m *mockGCPKMSClient) GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error) {
	if m.getPublicKeyErr != nil {
		return nil, m.getPublicKeyErr
	}
	return m.publicKey, nil
}

func (m *mockGCPKMSClient) AsymmetricSign(_ context.Context, request *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	m.lastSignRequest = request
	if m.signErr != nil {
		return nil, m.signErr
	}

	digest := request.GetDigest().GetSha256()
	signature := secp256k1ecdsa.Sign(m.privateKey, digest).Serialize()
	response := &kmspb.AsymmetricSignResponse{
		Signature:            signature,
		SignatureCrc32C:      wrapperspb.Int64(crc32c(signature)),
		VerifiedDigestCrc32C: request.GetDigestCrc32C().GetValue() == crc32c(digest),
		Name:                 request.GetName(),
		ProtectionLevel:      kmspb.ProtectionLevel_HSM,
	}
	if m.mutateSignature != nil {
		m.mutateSignature(response)
	}
	return response, nil
}

func newTestGCPKMSKeyring(t *testing.T) (*gcpKMSKeyring, *mockGCPKMSClient) {
	t.Helper()
	cfg := validGCPKMSConfig()
	client := newMockGCPKMSClient(t, cfg)
	keyring, err := newGCPKMSKeyring(context.Background(), cfg, client)
	require.NoError(t, err)
	return keyring, client
}

func TestGCPKMSConfigValidate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cfg := validGCPKMSConfig()
		require.NoError(t, cfg.Validate())
		signerCfg := Config{Mode: ModeGCPKMS, GCPKMS: cfg}
		require.NoError(t, signerCfg.Validate())
	})

	tests := []struct {
		name   string
		mutate func(*GCPKMSConfig)
	}{
		{name: "missing project", mutate: func(c *GCPKMSConfig) { c.Project = "" }},
		{name: "missing location", mutate: func(c *GCPKMSConfig) { c.Location = "" }},
		{name: "missing key ring", mutate: func(c *GCPKMSConfig) { c.KeyRing = "" }},
		{name: "missing key", mutate: func(c *GCPKMSConfig) { c.Key = "" }},
		{name: "missing key version", mutate: func(c *GCPKMSConfig) { c.KeyVersion = "" }},
		{name: "floating key version", mutate: func(c *GCPKMSConfig) { c.KeyVersion = "primary" }},
		{name: "zero key version", mutate: func(c *GCPKMSConfig) { c.KeyVersion = "0" }},
		{name: "resource path instead of id", mutate: func(c *GCPKMSConfig) { c.Key = "cryptoKeys/key" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validGCPKMSConfig()
			test.mutate(&cfg)
			require.Error(t, cfg.Validate())
		})
	}
}

func TestGCPKMSKeyringLookupAndSign(t *testing.T) {
	kr, client := newTestGCPKMSKeyring(t)
	require.Equal(t, ModeGCPKMS, kr.Backend())

	records, err := kr.List()
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, kr.resourceName, records[0].Name)

	record, err := kr.Key(kr.resourceName)
	require.NoError(t, err)
	address, err := record.GetAddress()
	require.NoError(t, err)
	require.Equal(t, kr.address, address.String())

	recordByAddress, err := kr.KeyByAddress(address)
	require.NoError(t, err)
	require.Equal(t, record.Name, recordByAddress.Name)

	message := []byte("celestia transaction sign bytes")
	signature, publicKey, err := kr.Sign(kr.resourceName, message, signing.SignMode_SIGN_MODE_DIRECT)
	require.NoError(t, err)
	require.Len(t, signature, 64)
	require.True(t, publicKey.VerifySignature(message, signature))

	digest := sha256.Sum256(message)
	require.Equal(t, digest[:], client.lastSignRequest.GetDigest().GetSha256())
	require.Equal(t, crc32c(digest[:]), client.lastSignRequest.GetDigestCrc32C().GetValue())
	require.Equal(t, kr.resourceName, client.lastSignRequest.GetName())

	byAddressSignature, _, err := kr.SignByAddress(address, message, signing.SignMode_SIGN_MODE_DIRECT)
	require.NoError(t, err)
	require.Equal(t, signature, byAddressSignature)

	_, err = kr.Key("wrong-key")
	require.ErrorIs(t, err, sdkerrors.ErrKeyNotFound)
	_, err = kr.KeyByAddress(sdk.AccAddress([]byte("wrong-address")))
	require.ErrorIs(t, err, sdkerrors.ErrKeyNotFound)
	_, _, err = kr.Sign("wrong-key", message, signing.SignMode_SIGN_MODE_DIRECT)
	require.ErrorIs(t, err, sdkerrors.ErrKeyNotFound)
}

func TestGCPKMSPublicKeyValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*kmspb.PublicKey)
	}{
		{name: "wrong resource", mutate: func(p *kmspb.PublicKey) { p.Name = "wrong" }},
		{name: "wrong algorithm", mutate: func(p *kmspb.PublicKey) { p.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 }},
		{name: "software protection", mutate: func(p *kmspb.PublicKey) { p.ProtectionLevel = kmspb.ProtectionLevel_SOFTWARE }},
		{name: "missing PEM", mutate: func(p *kmspb.PublicKey) { p.Pem = ""; p.PemCrc32C = wrapperspb.Int64(0) }},
		{name: "missing PEM CRC", mutate: func(p *kmspb.PublicKey) { p.PemCrc32C = nil }},
		{name: "bad PEM CRC", mutate: func(p *kmspb.PublicKey) { p.PemCrc32C = wrapperspb.Int64(1) }},
		{name: "invalid PEM", mutate: func(p *kmspb.PublicKey) { p.Pem = "invalid"; p.PemCrc32C = wrapperspb.Int64(crc32c([]byte("invalid"))) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validGCPKMSConfig()
			client := newMockGCPKMSClient(t, cfg)
			test.mutate(client.publicKey)
			_, err := newGCPKMSKeyring(context.Background(), cfg, client)
			require.Error(t, err)
		})
	}

	t.Run("client error", func(t *testing.T) {
		cfg := validGCPKMSConfig()
		client := newMockGCPKMSClient(t, cfg)
		client.getPublicKeyErr = errors.New("unavailable")
		_, err := newGCPKMSKeyring(context.Background(), cfg, client)
		require.ErrorContains(t, err, "get gcp kms public key")
	})
}

func TestGCPKMSSignatureResponseValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*kmspb.AsymmetricSignResponse)
	}{
		{name: "wrong resource", mutate: func(r *kmspb.AsymmetricSignResponse) { r.Name = "wrong" }},
		{name: "software protection", mutate: func(r *kmspb.AsymmetricSignResponse) { r.ProtectionLevel = kmspb.ProtectionLevel_SOFTWARE }},
		{name: "digest CRC not verified", mutate: func(r *kmspb.AsymmetricSignResponse) { r.VerifiedDigestCrc32C = false }},
		{name: "missing signature CRC", mutate: func(r *kmspb.AsymmetricSignResponse) { r.SignatureCrc32C = nil }},
		{name: "bad signature CRC", mutate: func(r *kmspb.AsymmetricSignResponse) { r.SignatureCrc32C = wrapperspb.Int64(1) }},
		{name: "invalid DER", mutate: func(r *kmspb.AsymmetricSignResponse) {
			r.Signature = []byte("invalid")
			r.SignatureCrc32C = wrapperspb.Int64(crc32c(r.Signature))
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kr, client := newTestGCPKMSKeyring(t)
			client.mutateSignature = test.mutate
			_, _, err := kr.Sign(kr.resourceName, []byte("message"), signing.SignMode_SIGN_MODE_DIRECT)
			require.Error(t, err)
		})
	}

	t.Run("client error", func(t *testing.T) {
		kr, client := newTestGCPKMSKeyring(t)
		client.signErr = errors.New("permission denied")
		_, _, err := kr.Sign(kr.resourceName, []byte("message"), signing.SignMode_SIGN_MODE_DIRECT)
		require.ErrorContains(t, err, "gcp kms sign")
	})
}

func TestGCPKMSUnsupportedOperations(t *testing.T) {
	kr, _ := newTestGCPKMSKeyring(t)
	require.ErrorIs(t, kr.Delete(kr.resourceName), errUnsupportedGCPKMSOp)
	require.ErrorIs(t, kr.DeleteByAddress(sdk.AccAddress(kr.pubKey.Address())), errUnsupportedGCPKMSOp)
	require.ErrorIs(t, kr.Rename("old", "new"), errUnsupportedGCPKMSOp)
	_, _, err := kr.NewMnemonic("key", keyring.English, "", "", nil)
	require.ErrorIs(t, err, errUnsupportedGCPKMSOp)
	_, err = kr.NewAccount("key", "", "", "", nil)
	require.ErrorIs(t, err, errUnsupportedGCPKMSOp)
	_, err = kr.ExportPubKeyArmor(kr.resourceName)
	require.ErrorIs(t, err, errUnsupportedGCPKMSOp)
}
