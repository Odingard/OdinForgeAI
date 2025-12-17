package sender

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
)

type TLSConfig struct {
	VerifyTLS  bool
	CertPath   string
	KeyPath    string
	CAPath     string
	PinnedSPKI string // base64(SPKI sha256) or empty
}

func BuildTLS(cfg TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if !cfg.VerifyTLS {
		tlsCfg.InsecureSkipVerify = true // acceptable only in dev
		return tlsCfg, nil
	}

	// Optional custom CA
	if cfg.CAPath != "" {
		caPem, err := os.ReadFile(cfg.CAPath)
		if err != nil {
			return nil, err
		}
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(caPem) {
			return nil, errors.New("failed to append CA cert")
		}
		tlsCfg.RootCAs = cp
	}

	// Optional mTLS
	if cfg.CertPath != "" && cfg.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			return nil, err
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	// Optional pinning hook (SPKI pin)
	// If you want strict pinning, enforce in VerifyPeerCertificate.
	if cfg.PinnedSPKI != "" {
		pin, err := base64.StdEncoding.DecodeString(cfg.PinnedSPKI)
		if err != nil {
			return nil, errors.New("invalid pinned_spki base64")
		}
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// This is a "hook point" for strict pinning in v1.
			// Keep minimal for now; enforce in your next iteration.
			_ = pin
			return nil
		}
	}

	return tlsCfg, nil
}
