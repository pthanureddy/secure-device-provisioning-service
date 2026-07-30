package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pthanureddy/secure-device-provisioning-service/internal/pki"
	"github.com/pthanureddy/secure-device-provisioning-service/internal/provisioning"
)

func newAPI(t *testing.T) (*httptest.Server, *provisioning.Service) {
	t.Helper()
	authority, err := pki.NewAuthority(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	service := provisioning.NewService(authority, time.Now, "localhost:8883")
	server := httptest.NewServer(NewHandler(service, "test-admin-key"))
	t.Cleanup(server.Close)
	return server, service
}

func requestJSON(t *testing.T, method, url string, body any, admin bool) *http.Response {
	t.Helper()
	data, _ := json.Marshal(body)
	request, _ := http.NewRequest(method, url, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	if admin {
		request.Header.Set("X-Admin-Key", "test-admin-key")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestCompleteBootstrapEnrollmentAndRevocationAPI(t *testing.T) {
	server, _ := newAPI(t)
	bootstrapResponse := requestJSON(t, http.MethodPost, server.URL+"/v1/bootstrap-tokens", map[string]any{
		"deviceId": "camera-001", "hardwareId": "hardware-001", "ttlSeconds": 60,
	}, true)
	defer bootstrapResponse.Body.Close()
	if bootstrapResponse.StatusCode != http.StatusCreated {
		t.Fatalf("bootstrap status: %d", bootstrapResponse.StatusCode)
	}
	var bootstrap provisioning.Bootstrap
	_ = json.NewDecoder(bootstrapResponse.Body).Decode(&bootstrap)
	_, csr, _ := pki.NewDeviceCSR("camera-001")
	enrollmentResponse := requestJSON(t, http.MethodPost, server.URL+"/v1/enroll", map[string]any{
		"deviceId": "camera-001", "hardwareId": "hardware-001",
		"bootstrapToken": bootstrap.Token, "csrPem": string(csr),
	}, false)
	defer enrollmentResponse.Body.Close()
	if enrollmentResponse.StatusCode != http.StatusCreated {
		t.Fatalf("enrollment status: %d", enrollmentResponse.StatusCode)
	}
	getResponse := requestJSON(t, http.MethodGet, server.URL+"/v1/devices/camera-001", nil, true)
	defer getResponse.Body.Close()
	if getResponse.StatusCode != http.StatusOK {
		t.Fatalf("device status: %d", getResponse.StatusCode)
	}
	revokeResponse := requestJSON(t, http.MethodPost, server.URL+"/v1/devices/camera-001/revoke", nil, true)
	defer revokeResponse.Body.Close()
	if revokeResponse.StatusCode != http.StatusOK {
		t.Fatalf("revoke status: %d", revokeResponse.StatusCode)
	}
}

func TestAdminAndStrictJSONValidation(t *testing.T) {
	server, _ := newAPI(t)
	unauthorized := requestJSON(t, http.MethodPost, server.URL+"/v1/bootstrap-tokens", map[string]string{
		"deviceId": "camera-001", "hardwareId": "hardware-001",
	}, false)
	defer unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", unauthorized.StatusCode)
	}
	invalid := requestJSON(t, http.MethodPost, server.URL+"/v1/bootstrap-tokens", map[string]any{
		"deviceId": "camera-001", "hardwareId": "hardware-001", "unexpected": true,
	}, true)
	defer invalid.Body.Close()
	if invalid.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected strict JSON rejection, got %d", invalid.StatusCode)
	}
}

func TestHealthAndNotFound(t *testing.T) {
	server, _ := newAPI(t)
	response, err := http.Get(server.URL + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status: %d", response.StatusCode)
	}
	missing := requestJSON(t, http.MethodGet, server.URL+"/v1/devices/missing", nil, true)
	defer missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status: %d", missing.StatusCode)
	}
}
