package provisioning

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/pthanureddy/secure-device-provisioning-service/internal/pki"
)

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)

var (
	ErrInvalidIdentifier = errors.New("device and hardware IDs must use lowercase letters, digits, and hyphens")
	ErrTokenInvalid      = errors.New("bootstrap token is invalid")
	ErrTokenExpired      = errors.New("bootstrap token has expired")
	ErrTokenUsed         = errors.New("bootstrap token has already been used")
	ErrHardwareMismatch  = errors.New("hardware ID does not match bootstrap record")
	ErrDeviceNotFound    = errors.New("device not found")
	ErrDeviceRevoked     = errors.New("device is revoked")
)

type DeviceStatus string

const (
	StatusActive  DeviceStatus = "active"
	StatusRevoked DeviceStatus = "revoked"
)

type Device struct {
	ID                string       `json:"id"`
	HardwareID        string       `json:"hardwareId"`
	Status            DeviceStatus `json:"status"`
	CertificateSerial string       `json:"certificateSerial"`
	EnrolledAt        time.Time    `json:"enrolledAt"`
	CertificateExpiry time.Time    `json:"certificateExpiry"`
}

type Bootstrap struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type Enrollment struct {
	Device         Device `json:"device"`
	CertificatePEM string `json:"certificatePem"`
	CACertificate  string `json:"caCertificatePem"`
	MQTTEndpoint   string `json:"mqttEndpoint"`
	PublishTopic   string `json:"publishTopic"`
	DesiredTopic   string `json:"desiredTopic"`
}

type tokenRecord struct {
	deviceID   string
	hardwareID string
	digest     [32]byte
	expiresAt  time.Time
	used       bool
}

type Service struct {
	mu               sync.RWMutex
	authority        *pki.Authority
	now              func() time.Time
	mqttEndpoint     string
	tokens           map[string]*tokenRecord
	devices          map[string]Device
	certificateHours time.Duration
}

func NewService(authority *pki.Authority, now func() time.Time, mqttEndpoint string) *Service {
	return &Service{
		authority:        authority,
		now:              now,
		mqttEndpoint:     mqttEndpoint,
		tokens:           make(map[string]*tokenRecord),
		devices:          make(map[string]Device),
		certificateHours: 24 * time.Hour,
	}
}

func (s *Service) SetMQTTEndpoint(endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mqttEndpoint = endpoint
}

func (s *Service) IssueBootstrap(deviceID, hardwareID string, ttl time.Duration) (Bootstrap, error) {
	if !identifierPattern.MatchString(deviceID) || !identifierPattern.MatchString(hardwareID) {
		return Bootstrap{}, ErrInvalidIdentifier
	}
	if ttl <= 0 || ttl > time.Hour {
		return Bootstrap{}, errors.New("bootstrap token TTL must be between 1ns and one hour")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Bootstrap{}, fmt.Errorf("generate bootstrap token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	expiresAt := s.now().Add(ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[deviceID] = &tokenRecord{
		deviceID: deviceID, hardwareID: hardwareID, digest: digest, expiresAt: expiresAt,
	}
	return Bootstrap{Token: token, ExpiresAt: expiresAt}, nil
}

func (s *Service) Enroll(deviceID, hardwareID, token string, csrPEM []byte) (Enrollment, error) {
	if !identifierPattern.MatchString(deviceID) || !identifierPattern.MatchString(hardwareID) {
		return Enrollment{}, ErrInvalidIdentifier
	}
	digest := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.tokens[deviceID]
	if !ok || subtle.ConstantTimeCompare(digest[:], record.digest[:]) != 1 {
		return Enrollment{}, ErrTokenInvalid
	}
	if record.used {
		return Enrollment{}, ErrTokenUsed
	}
	if !s.now().Before(record.expiresAt) {
		return Enrollment{}, ErrTokenExpired
	}
	if record.hardwareID != hardwareID {
		return Enrollment{}, ErrHardwareMismatch
	}
	certificatePEM, certificate, err := s.authority.SignDeviceCSR(
		csrPEM, deviceID, s.now(), s.certificateHours,
	)
	if err != nil {
		return Enrollment{}, err
	}
	record.used = true
	device := Device{
		ID:                deviceID,
		HardwareID:        hardwareID,
		Status:            StatusActive,
		CertificateSerial: certificate.SerialNumber.Text(16),
		EnrolledAt:        s.now(),
		CertificateExpiry: certificate.NotAfter,
	}
	s.devices[deviceID] = device
	return Enrollment{
		Device:         device,
		CertificatePEM: string(certificatePEM),
		CACertificate:  string(s.authority.CertificatePEM()),
		MQTTEndpoint:   s.mqttEndpoint,
		PublishTopic:   "devices/" + deviceID + "/telemetry",
		DesiredTopic:   "devices/" + deviceID + "/desired",
	}, nil
}

func (s *Service) Device(deviceID string) (Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	device, ok := s.devices[deviceID]
	if !ok {
		return Device{}, ErrDeviceNotFound
	}
	return device, nil
}

func (s *Service) Revoke(deviceID string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[deviceID]
	if !ok {
		return Device{}, ErrDeviceNotFound
	}
	device.Status = StatusRevoked
	s.devices[deviceID] = device
	return device, nil
}

func (s *Service) AuthorizeCertificate(certificate *x509.Certificate) (string, bool) {
	if certificate == nil {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	device, ok := s.devices[certificate.Subject.CommonName]
	if !ok || device.Status != StatusActive {
		return "", false
	}
	return device.ID, subtle.ConstantTimeCompare(
		[]byte(device.CertificateSerial),
		[]byte(certificate.SerialNumber.Text(16)),
	) == 1
}
