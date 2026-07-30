package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pthanureddy/secure-device-provisioning-service/internal/api"
	"github.com/pthanureddy/secure-device-provisioning-service/internal/mqtt"
	"github.com/pthanureddy/secure-device-provisioning-service/internal/pki"
	"github.com/pthanureddy/secure-device-provisioning-service/internal/provisioning"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	now := time.Now().UTC()
	authority, err := pki.NewAuthority(now)
	if err != nil {
		logger.Error("create development CA", "error", err)
		os.Exit(1)
	}
	service := provisioning.NewService(authority, func() time.Time { return time.Now().UTC() }, "")
	serverCertificate, err := authority.ServerCertificate(
		[]string{"localhost", "127.0.0.1", "secure-device-provisioning"},
		now,
		30*24*time.Hour,
	)
	if err != nil {
		logger.Error("create MQTT server certificate", "error", err)
		os.Exit(1)
	}
	broker := mqtt.NewBroker(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    authority.CertPool(),
	}, service)
	mqttAddress, err := broker.Start(environment("MQTT_ADDRESS", ":8883"))
	if err != nil {
		logger.Error("start MQTT endpoint", "error", err)
		os.Exit(1)
	}
	service.SetMQTTEndpoint(environment("MQTT_PUBLIC_ENDPOINT", "localhost:8883"))

	adminKey := environment("ADMIN_KEY", "local-admin-key-change-me")
	httpAddress := environment("HTTP_ADDRESS", ":8080")
	server := &http.Server{
		Addr:              httpAddress,
		Handler:           api.NewHandler(service, adminKey),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		logger.Info("control plane started", "httpAddress", httpAddress, "mqttAddress", mqttAddress)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server stopped", "error", err)
			os.Exit(1)
		}
	}()

	shutdown, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-shutdown.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	_ = broker.Close()
	logger.Info("control plane stopped")
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
