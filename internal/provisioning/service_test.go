package provisioning

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/pthanureddy/secure-device-provisioning-service/internal/pki"
)

func fixture(t *testing.T) (*Service, *time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	authority, err := pki.NewAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(authority, func() time.Time { return now }, "localhost:8883")
	return service, &now
}

func enroll(t *testing.T, service *Service, deviceID, hardwareID string) Enrollment {
	t.Helper()
	bootstrap, err := service.IssueBootstrap(deviceID, hardwareID, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, csr, err := pki.NewDeviceCSR(deviceID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Enroll(deviceID, hardwareID, bootstrap.Token, csr)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestEnrollmentConsumesHardwareBoundToken(t *testing.T) {
	service, _ := fixture(t)
	bootstrap, _ := service.IssueBootstrap("camera-001", "hardware-001", 10*time.Minute)
	_, csr, _ := pki.NewDeviceCSR("camera-001")
	if _, err := service.Enroll("camera-001", "hardware-999", bootstrap.Token, csr); !errors.Is(err, ErrHardwareMismatch) {
		t.Fatalf("expected hardware mismatch, got %v", err)
	}
	result, err := service.Enroll("camera-001", "hardware-001", bootstrap.Token, csr)
	if err != nil {
		t.Fatal(err)
	}
	if result.Device.Status != StatusActive || result.PublishTopic != "devices/camera-001/telemetry" {
		t.Fatalf("unexpected enrollment: %+v", result)
	}
	if _, err := service.Enroll("camera-001", "hardware-001", bootstrap.Token, csr); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("expected used token, got %v", err)
	}
}

func TestExpiredAndUnknownTokensAreRejected(t *testing.T) {
	service, clock := fixture(t)
	bootstrap, _ := service.IssueBootstrap("camera-001", "hardware-001", time.Minute)
	*clock = clock.Add(2 * time.Minute)
	_, csr, _ := pki.NewDeviceCSR("camera-001")
	if _, err := service.Enroll("camera-001", "hardware-001", bootstrap.Token, csr); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected expired token, got %v", err)
	}
	if _, err := service.Enroll("camera-001", "hardware-001", "unknown", csr); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected invalid token, got %v", err)
	}
}

func TestRevocationRemovesCertificateAuthorization(t *testing.T) {
	service, _ := fixture(t)
	bootstrap, _ := service.IssueBootstrap("camera-001", "hardware-001", time.Minute)
	_, csr, _ := pki.NewDeviceCSR("camera-001")
	result, err := service.Enroll("camera-001", "hardware-001", bootstrap.Token, csr)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(result.CertificatePEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	if _, ok := service.AuthorizeCertificate(cert); !ok {
		t.Fatal("expected enrolled certificate to be authorized")
	}
	device, err := service.Revoke("camera-001")
	if err != nil || device.Status != StatusRevoked {
		t.Fatalf("unexpected revocation: %+v %v", device, err)
	}
	if _, err := service.Device("missing"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
	if _, ok := service.AuthorizeCertificate(cert); ok {
		t.Fatal("expected revoked certificate to be rejected")
	}
}

func TestIdentifierAndTTLValidation(t *testing.T) {
	service, _ := fixture(t)
	if _, err := service.IssueBootstrap("BAD", "hardware-001", time.Minute); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("expected invalid identifier, got %v", err)
	}
	if _, err := service.IssueBootstrap("camera-001", "hardware-001", 2*time.Hour); err == nil {
		t.Fatal("expected TTL rejection")
	}
}
