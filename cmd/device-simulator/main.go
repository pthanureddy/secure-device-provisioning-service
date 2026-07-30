package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pthanureddy/secure-device-provisioning-service/internal/mqtt"
	"github.com/pthanureddy/secure-device-provisioning-service/internal/pki"
	"github.com/pthanureddy/secure-device-provisioning-service/internal/provisioning"
)

func main() {
	deviceID := required("DEVICE_ID")
	hardwareID := required("HARDWARE_ID")
	token := required("BOOTSTRAP_TOKEN")
	apiURL := environment("CONTROL_PLANE_URL", "http://127.0.0.1:8080")

	keyPEM, csrPEM, err := pki.NewDeviceCSR(deviceID)
	fatalIf(err)
	requestBody, _ := json.Marshal(map[string]string{
		"deviceId": deviceID, "hardwareId": hardwareID,
		"bootstrapToken": token, "csrPem": string(csrPEM),
	})
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Post(apiURL+"/v1/enroll", "application/json", bytes.NewReader(requestBody))
	fatalIf(err)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(response.Body)
		fatalIf(fmt.Errorf("enrollment failed: %s: %s", response.Status, body))
	}
	var enrollment provisioning.Enrollment
	fatalIf(json.NewDecoder(response.Body).Decode(&enrollment))

	certificate, err := pki.DeviceTLSCertificate([]byte(enrollment.CertificatePEM), keyPEM)
	fatalIf(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(enrollment.CACertificate)) {
		fatalIf(fmt.Errorf("CA certificate could not be loaded"))
	}
	serverName, _, err := net.SplitHostPort(enrollment.MQTTEndpoint)
	fatalIf(err)
	mqttClient, err := mqtt.Dial(enrollment.MQTTEndpoint, deviceID, &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: serverName,
		RootCAs: roots, Certificates: []tls.Certificate{certificate},
	})
	fatalIf(err)
	defer mqttClient.Close()
	telemetry, _ := json.Marshal(map[string]any{
		"deviceId": deviceID, "firmware": "1.0.0-synthetic",
		"temperatureC": 42.5, "timestamp": time.Now().UTC(),
	})
	fatalIf(mqttClient.PublishQoS1(enrollment.PublishTopic, telemetry))
	fmt.Printf("enrolled %s and published one QoS 1 telemetry message\n", deviceID)
}

func required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		fatalIf(fmt.Errorf("%s is required", name))
	}
	return value
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
