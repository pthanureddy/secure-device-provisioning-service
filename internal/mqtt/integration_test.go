package mqtt

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/pthanureddy/secure-device-provisioning-service/internal/pki"
	"github.com/pthanureddy/secure-device-provisioning-service/internal/provisioning"
)

type mqttFixture struct {
	authority *pki.Authority
	service   *provisioning.Service
	broker    *Broker
	address   string
}

func newMQTTFixture(t *testing.T) mqttFixture {
	t.Helper()
	now := time.Now().UTC()
	authority, _ := pki.NewAuthority(now)
	service := provisioning.NewService(authority, func() time.Time { return time.Now().UTC() }, "")
	serverCertificate, _ := authority.ServerCertificate(
		[]string{"localhost", "127.0.0.1"}, now, 24*time.Hour,
	)
	broker := NewBroker(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: authority.CertPool(),
	}, service)
	address, err := broker.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	service.SetMQTTEndpoint(address)
	return mqttFixture{authority: authority, service: service, broker: broker, address: address}
}

func enrollTLS(t *testing.T, fixture mqttFixture, deviceID string) *tls.Config {
	t.Helper()
	bootstrap, _ := fixture.service.IssueBootstrap(deviceID, "hardware-001", time.Minute)
	key, csr, _ := pki.NewDeviceCSR(deviceID)
	enrollment, err := fixture.service.Enroll(deviceID, "hardware-001", bootstrap.Token, csr)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := pki.DeviceTLSCertificate([]byte(enrollment.CertificatePEM), key)
	return &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: "localhost",
		RootCAs: fixture.authority.CertPool(), Certificates: []tls.Certificate{certificate},
	}
}

func TestMutualTLSMQTTPublishAndDesiredConfig(t *testing.T) {
	fixture := newMQTTFixture(t)
	tlsConfig := enrollTLS(t, fixture, "camera-001")
	fixture.broker.SetDesired("camera-001", []byte(`{"firmware":"2.0.0"}`))
	client, err := Dial(fixture.address, "camera-001", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.PublishQoS1("devices/camera-001/telemetry", []byte(`{"temperatureC":42}`)); err != nil {
		t.Fatal(err)
	}
	desired, err := client.SubscribeDesired("devices/camera-001/desired")
	if err != nil || string(desired) != `{"firmware":"2.0.0"}` {
		t.Fatalf("unexpected desired config: %s %v", desired, err)
	}
	if err := client.Ping(); err != nil {
		t.Fatal(err)
	}
	receipts := fixture.broker.Receipts()
	if len(receipts) != 1 || receipts[0].QoS != 1 || receipts[0].DeviceID != "camera-001" {
		t.Fatalf("unexpected receipts: %+v", receipts)
	}
}

func TestTopicScopeAndClientIdentityAreEnforced(t *testing.T) {
	fixture := newMQTTFixture(t)
	tlsConfig := enrollTLS(t, fixture, "camera-001")
	if _, err := Dial(fixture.address, "camera-002", tlsConfig); err == nil {
		t.Fatal("expected client ID rejection")
	}
	client, err := Dial(fixture.address, "camera-001", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.PublishQoS1("devices/camera-002/telemetry", []byte("{}")); err == nil {
		t.Fatal("expected cross-device topic rejection")
	}
}

func TestUntrustedAndRevokedCertificatesAreRejected(t *testing.T) {
	fixture := newMQTTFixture(t)
	validConfig := enrollTLS(t, fixture, "camera-001")
	_, _ = fixture.service.Revoke("camera-001")
	if _, err := Dial(fixture.address, "camera-001", validConfig); err == nil {
		t.Fatal("expected revoked certificate rejection")
	}

	rogueAuthority, _ := pki.NewAuthority(time.Now().UTC())
	rogueService := provisioning.NewService(rogueAuthority, time.Now, fixture.address)
	bootstrap, _ := rogueService.IssueBootstrap("camera-rogue", "hardware-001", time.Minute)
	key, csr, _ := pki.NewDeviceCSR("camera-rogue")
	enrollment, _ := rogueService.Enroll("camera-rogue", "hardware-001", bootstrap.Token, csr)
	certificate, _ := pki.DeviceTLSCertificate([]byte(enrollment.CertificatePEM), key)
	rogueConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: "localhost",
		RootCAs: fixture.authority.CertPool(), Certificates: []tls.Certificate{certificate},
	}
	if _, err := Dial(fixture.address, "camera-rogue", rogueConfig); err == nil {
		t.Fatal("expected untrusted certificate rejection")
	}
}

func TestRunUntilCancelledClosesBroker(t *testing.T) {
	fixture := newMQTTFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RunUntilCancelled(ctx, fixture.broker); err != nil {
		t.Fatal(err)
	}
	fixture.broker.listener = nil
}
