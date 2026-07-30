package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateReloaderObservesRotationAndRetainsLastGoodPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	firstCert, firstKey := certificatePair(t, 1)
	secondCert, secondKey := certificatePair(t, 2)
	writePair(t, certFile, keyFile, firstCert, firstKey)

	reloader, err := newCertificateReloader(
		certFile,
		keyFile,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := certificateSerial(t, reloader.GetCertificate); got != 1 {
		t.Fatalf("initial certificate serial = %d, want 1", got)
	}

	// Projected Secret updates are atomic, but tolerate a transient mismatch
	// so a malformed or partially observed rotation cannot take HTTPS down.
	if err := os.WriteFile(certFile, secondCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := certificateSerial(t, reloader.GetCertificate); got != 1 {
		t.Fatalf("certificate during malformed rotation = %d, want last good serial 1", got)
	}

	if err := os.WriteFile(keyFile, secondKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := certificateSerial(t, reloader.GetCertificate); got != 2 {
		t.Fatalf("certificate after rotation = %d, want 2", got)
	}
}

func TestCertificateReloaderRequiresAValidInitialPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newCertificateReloader(
		certFile,
		keyFile,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	); err == nil {
		t.Fatal("expected invalid initial certificate error")
	}
}

func certificateSerial(
	t *testing.T,
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
) int64 {
	t.Helper()
	certificate, err := getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.SerialNumber.Int64()
}

func certificatePair(t *testing.T, serial int64) ([]byte, []byte) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "groupbridge.test"},
		DNSNames:     []string{"groupbridge.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	return certPEM, keyPEM
}

func writePair(t *testing.T, certFile, keyFile string, cert, key []byte) {
	t.Helper()
	if err := os.WriteFile(certFile, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
}
