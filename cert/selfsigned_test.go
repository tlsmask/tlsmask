package cert

import (
	"crypto/x509"
	"testing"
)

func TestLeafVerifiesForItsHost(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA(): %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	for _, host := range []string{"example.com", "127.0.0.1", "::1", "2001:db8::7"} {
		t.Run(host, func(t *testing.T) {
			leaf, err := ca.leafCert(host)
			if err != nil {
				t.Fatalf("leafCert(%q): %v", host, err)
			}
			parsed, err := x509.ParseCertificate(leaf.Certificate[0])
			if err != nil {
				t.Fatalf("parse leaf: %v", err)
			}
			if _, err := parsed.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
				t.Errorf("a client connecting to %s would reject this certificate: %v", host, err)
			}
		})
	}
}

func TestRegenerateCAReplacesWhatIsStored(t *testing.T) {
	dir := t.TempDir()

	first, created, err := LoadOrCreateCA(dir)
	if err != nil || !created {
		t.Fatalf("LoadOrCreateCA() = created %v, err %v", created, err)
	}
	second, err := RegenerateCA(dir)
	if err != nil {
		t.Fatalf("RegenerateCA(): %v", err)
	}
	if second.Fingerprint() == first.Fingerprint() {
		t.Fatal("regenerating produced the same CA")
	}

	loaded, created, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("loading after a regeneration: %v", err)
	}
	if created {
		t.Error("the regenerated CA was not found on disk, so a new one was made instead")
	}
	if loaded.Fingerprint() != second.Fingerprint() {
		t.Error("the CA on disk is not the regenerated one")
	}
}
