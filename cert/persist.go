package cert

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

const (
	caCertFile = "tlsmask-ca.crt"
	caKeyFile  = "tlsmask-ca.key"
)

func DefaultDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "tlsmask")
	}
	return ".tlsmask"
}

func LoadOrCreateCA(dir string) (*CA, bool, error) {
	if dir == "" {
		ca, err := NewCA()
		return ca, false, err
	}

	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	ca, err := loadCA(certPath, keyPath)
	switch {
	case err == nil:
		return ca, false, nil
	case !os.IsNotExist(err):
		return nil, false, fmt.Errorf("load CA from %s: %w", dir, err)
	}

	ca, err = NewCA()
	if err != nil {
		return nil, false, err
	}
	if err := saveCA(ca, dir, certPath, keyPath); err != nil {
		return nil, false, err
	}
	return ca, true, nil
}

func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s does not contain a PEM certificate", certPath)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("%s does not contain a PEM private key", keyPath)
	}

	parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	parsedKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	return newCAFrom(parsedCert, parsedKey, certBlock.Bytes)
}

func RegenerateCA(dir string) (*CA, error) {
	ca, err := NewCA()
	if err != nil {
		return nil, err
	}
	if dir == "" {
		return ca, nil
	}
	if err := saveCA(ca, dir, filepath.Join(dir, caCertFile), filepath.Join(dir, caKeyFile)); err != nil {
		return nil, err
	}
	return ca, nil
}

func saveCA(ca *CA, dir, certPath, keyPath string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create CA directory %s: %w", dir, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.tlsCert.Certificate[0]})
	keyDER, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(keyPath+".tmp", keyPEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", keyPath, err)
	}
	if err := os.WriteFile(certPath+".tmp", certPEM, 0o644); err != nil {
		os.Remove(keyPath + ".tmp")
		return fmt.Errorf("write %s: %w", certPath, err)
	}
	if err := os.Rename(keyPath+".tmp", keyPath); err != nil {
		return fmt.Errorf("replace %s: %w", keyPath, err)
	}
	if err := os.Rename(certPath+".tmp", certPath); err != nil {
		return fmt.Errorf("replace %s: %w", certPath, err)
	}
	return nil
}

func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.tlsCert.Certificate[0]})
}

func (ca *CA) Fingerprint() string {
	sum := sha256Sum(ca.tlsCert.Certificate[0])
	out := make([]byte, 0, len(sum)*3)
	const hexDigits = "0123456789ABCDEF"
	for i, b := range sum {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out)
}

func (ca *CA) NotAfter() string {
	return ca.cert.NotAfter.UTC().Format("2006-01-02")
}

func CertPath(dir string) string {
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, caCertFile)
}

var _ = ecdsa.PublicKey{}
