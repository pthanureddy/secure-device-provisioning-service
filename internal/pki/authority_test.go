package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestAuthoritySignsBoundDeviceCertificate(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	authority, err := NewAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, csrPEM, err := NewDeviceCSR("camera-001")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, cert, err := authority.SignDeviceCSR(csrPEM, "camera-001", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "camera-001" || len(cert.URIs) != 1 {
		t.Fatalf("unexpected device identity: %+v", cert.Subject)
	}
	if _, err := DeviceTLSCertificate(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	parsed, _ := x509.ParseCertificate(block.Bytes)
	if _, err := parsed.Verify(x509.VerifyOptions{
		Roots: authority.CertPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("device certificate did not verify: %v", err)
	}
}

func TestAuthorityRejectsMismatchedCSRAndExcessValidity(t *testing.T) {
	now := time.Now().UTC()
	authority, _ := NewAuthority(now)
	_, csrPEM, _ := NewDeviceCSR("camera-001")
	if _, _, err := authority.SignDeviceCSR(csrPEM, "camera-002", now, time.Hour); err == nil {
		t.Fatal("expected identity mismatch")
	}
	if _, _, err := authority.SignDeviceCSR(csrPEM, "camera-001", now, 31*24*time.Hour); err == nil {
		t.Fatal("expected validity rejection")
	}
}

func TestServerCertificateContainsConfiguredHosts(t *testing.T) {
	now := time.Now().UTC()
	authority, _ := NewAuthority(now)
	certificate, err := authority.ServerCertificate(
		[]string{"localhost", "127.0.0.1"}, now, 24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
}
