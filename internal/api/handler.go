package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pthanureddy/secure-device-provisioning-service/internal/provisioning"
)

type Handler struct {
	service  *provisioning.Service
	adminKey string
	mux      *http.ServeMux
}

func NewHandler(service *provisioning.Service, adminKey string) *Handler {
	handler := &Handler{service: service, adminKey: adminKey, mux: http.NewServeMux()}
	handler.routes()
	return handler
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(writer, request)
}

func (h *Handler) routes() {
	h.mux.HandleFunc("GET /health/live", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	})
	h.mux.HandleFunc("GET /health/ready", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
	})
	h.mux.HandleFunc("POST /v1/bootstrap-tokens", h.admin(h.issueBootstrap))
	h.mux.HandleFunc("POST /v1/enroll", h.enroll)
	h.mux.HandleFunc("GET /v1/devices/{deviceID}", h.admin(h.getDevice))
	h.mux.HandleFunc("POST /v1/devices/{deviceID}/revoke", h.admin(h.revokeDevice))
}

func (h *Handler) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		expected := sha256.Sum256([]byte(h.adminKey))
		supplied := sha256.Sum256([]byte(request.Header.Get("X-Admin-Key")))
		if h.adminKey == "" || subtle.ConstantTimeCompare(expected[:], supplied[:]) != 1 {
			writeError(writer, http.StatusUnauthorized, "admin authentication failed")
			return
		}
		next(writer, request)
	}
}

func (h *Handler) issueBootstrap(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		DeviceID   string `json:"deviceId"`
		HardwareID string `json:"hardwareId"`
		TTlSeconds int    `json:"ttlSeconds"`
	}
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if input.TTlSeconds == 0 {
		input.TTlSeconds = 600
	}
	result, err := h.service.IssueBootstrap(
		input.DeviceID, input.HardwareID, time.Duration(input.TTlSeconds)*time.Second,
	)
	if err != nil {
		writeServiceError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, result)
}

func (h *Handler) enroll(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		DeviceID       string `json:"deviceId"`
		HardwareID     string `json:"hardwareId"`
		BootstrapToken string `json:"bootstrapToken"`
		CSRPEM         string `json:"csrPem"`
	}
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	result, err := h.service.Enroll(
		input.DeviceID, input.HardwareID, input.BootstrapToken, []byte(input.CSRPEM),
	)
	if err != nil {
		writeServiceError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, result)
}

func (h *Handler) getDevice(writer http.ResponseWriter, request *http.Request) {
	result, err := h.service.Device(request.PathValue("deviceID"))
	if err != nil {
		writeServiceError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (h *Handler) revokeDevice(writer http.ResponseWriter, request *http.Request) {
	result, err := h.service.Revoke(request.PathValue("deviceID"))
	if err != nil {
		writeServiceError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, 1<<20)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeServiceError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, provisioning.ErrDeviceNotFound):
		writeError(writer, http.StatusNotFound, err.Error())
	case errors.Is(err, provisioning.ErrTokenInvalid),
		errors.Is(err, provisioning.ErrTokenExpired),
		errors.Is(err, provisioning.ErrTokenUsed),
		errors.Is(err, provisioning.ErrHardwareMismatch),
		errors.Is(err, provisioning.ErrDeviceRevoked):
		writeError(writer, http.StatusForbidden, err.Error())
	default:
		writeError(writer, http.StatusBadRequest, err.Error())
	}
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{
		"error": strings.TrimSpace(message),
	})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
