package main

import (
	"encoding/json"
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/celestiaorg/op-alt-da/signer"
)

const (
	signerAddressCommandName = "signer-address"
	signerAddressOutputFlag  = "output"
)

type signerAddressResult struct {
	Address    string `json:"address"`
	SignerMode string `json:"signer_mode"`
	KeyName    string `json:"key_name"`
}

type signerAddressResolver func(signer.Config) (signerAddressResult, error)

func newSignerAddressCommand(resolve signerAddressResolver) *cli.Command {
	return &cli.Command{
		Name:  signerAddressCommandName,
		Usage: "derive the configured Celestia signer address without signing or submitting a transaction",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     ConfigFileFlagName,
				Usage:    "Path to TOML configuration file",
				EnvVars:  prefixEnvVars("CONFIG"),
				Required: true,
			},
			&cli.StringFlag{
				Name:    signerAddressOutputFlag,
				Aliases: []string{"o"},
				Usage:   "Output format: text or json",
				Value:   "text",
			},
		},
		Action: func(cliCtx *cli.Context) error {
			return runSignerAddress(cliCtx, resolve)
		},
	}
}

func runSignerAddress(cliCtx *cli.Context, resolve signerAddressResolver) error {
	cfg, err := LoadConfigFromFile(cliCtx.String(ConfigFileFlagName))
	if err != nil {
		return fmt.Errorf("load signer config: %w", err)
	}

	signerCfg := cfg.buildSignerConfig()
	result, err := resolve(signerCfg)
	if err != nil {
		return err
	}

	switch cliCtx.String(signerAddressOutputFlag) {
	case "text":
		_, err = fmt.Fprintln(cliCtx.App.Writer, result.Address)
		return err
	case "json":
		encoder := json.NewEncoder(cliCtx.App.Writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(result)
	default:
		return fmt.Errorf("unsupported output format %q: use text or json", cliCtx.String(signerAddressOutputFlag))
	}
}

func resolveSignerAddress(cfg signer.Config) (signerAddressResult, error) {
	if err := cfg.Validate(); err != nil {
		return signerAddressResult{}, fmt.Errorf("invalid signer config: %w", err)
	}
	mode := cfg.Mode
	if mode == "" {
		mode = signer.ModeLocal
	}

	keyring, keyName, err := signer.NewKeyring(cfg)
	if err != nil {
		return signerAddressResult{}, fmt.Errorf("create signer keyring: %w", err)
	}
	record, err := keyring.Key(keyName)
	if err != nil {
		return signerAddressResult{}, fmt.Errorf("load signer public key: %w", err)
	}
	address, err := record.GetAddress()
	if err != nil {
		return signerAddressResult{}, fmt.Errorf("derive signer address: %w", err)
	}

	return signerAddressResult{
		Address:    address.String(),
		SignerMode: mode,
		KeyName:    keyName,
	}, nil
}
