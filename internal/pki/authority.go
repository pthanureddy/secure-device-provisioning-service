package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

const deviceURIPrefix = "spiffe://device-fleet/devices/"

type Authority struct {
	certificate *x509.Certificate
	signer      crypto.Signer
	certPEM     []byte
}

func NewAuthority(now time.Time) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Device Fleet Development CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return &Authority{
		certificate: cert,
		signer:      key,
		certPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

func (a *Authority) CertificatePEM() []byte {
	return append([]byte(nil), a.certPEM...)
}

func (a *Authority) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.certificate)
	return pool
}

func (a *Authority) SignDeviceCSR(
	csrPEM []byte,
	deviceID string,
	now time.Time,
	validFor time.Duration,
) ([]byte, *x509.Certificate, error) {
	if validFor <= 0 || validFor > 30*24*time.Hour {
		return nil, nil, errors.New("device certificate validity must be between 1ns and 30 days")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("CSR must be PEM encoded")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("invalid CSR signature: %w", err)
	}
	if csr.Subject.CommonName != deviceID {
		return nil, nil, errors.New("CSR common name must match device ID")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	deviceURI, err := url.Parse(deviceURIPrefix + deviceID)
	if err != nil {
		return nil, nil, fmt.Errorf("build device URI: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: deviceID, Organization: []string{"Synthetic Device Fleet"}},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{deviceURI},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, csr.PublicKey, a.signer)
	if err != nil {
		return nil, nil, fmt.Errorf("sign device certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse device certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, nil
}

func (a *Authority) ServerCertificate(
	hosts []string,
	now time.Time,
	validFor time.Duration,
) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "device-fleet-mqtt"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, &key.PublicKey, a.signer)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sign server certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal server key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load server key pair: %w", err)
	}
	return certificate, nil
}

func NewDeviceCSR(deviceID string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate device key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: deviceID}},
		key,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal device key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func DeviceTLSCertificate(certPEM, keyPEM []byte) (tls.Certificate, error) {
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load device key pair: %w", err)
	}
	return certificate, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return serial, nil
}
