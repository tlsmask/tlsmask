package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	tlsCert tls.Certificate

	baseConfig *tls.Config

	leafCache sync.Map
}

func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "TLSMask Proxy CA",
			Organization: []string{"TLSMask"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	return newCAFrom(cert, key, certDER)
}

func newCAFrom(cert *x509.Certificate, key *ecdsa.PrivateKey, certDER []byte) (*CA, error) {
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}

	base := &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}

	var ticketKey [32]byte
	if _, err := rand.Read(ticketKey[:]); err != nil {
		return nil, fmt.Errorf("generate session ticket key: %w", err)
	}
	base.SetSessionTicketKeys([][32]byte{ticketKey})

	return &CA{cert: cert, key: key, tlsCert: tlsCert, baseConfig: base}, nil
}

func (ca *CA) TLSConfigForHost(host string) *tls.Config {
	cfg := ca.baseConfig.Clone()
	cfg.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := info.ServerName
		if name == "" {
			name = host
		}
		return ca.leafCert(name)
	}
	return cfg
}

func (ca *CA) leafCert(hostname string) (*tls.Certificate, error) {
	if cached, ok := ca.leafCache.Load(hostname); ok {
		return cached.(*tls.Certificate), nil
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert for %s: %w", hostname, err)
	}

	leaf := &tls.Certificate{
		Certificate: [][]byte{leafDER, ca.tlsCert.Certificate[0]},
		PrivateKey:  leafKey,
	}

	actual, _ := ca.leafCache.LoadOrStore(hostname, leaf)
	return actual.(*tls.Certificate), nil
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
