package mqtt

import (
	"bufio"
	"bytes"
	"testing"
)

func TestRemainingLengthRoundTrip(t *testing.T) {
	for _, value := range []int{0, 1, 127, 128, 16384, maxRemainingBytes} {
		reader := bufio.NewReader(bytes.NewReader(encodeRemainingLength(value)))
		actual, err := decodeRemainingLength(reader)
		if err != nil || actual != value {
			t.Fatalf("round trip %d: %d %v", value, actual, err)
		}
	}
}

func TestConnectRoundTripAndRejectsCredentials(t *testing.T) {
	body, err := connectBody("camera-001")
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := parseConnect(body)
	if err != nil || clientID != "camera-001" {
		t.Fatalf("unexpected CONNECT parse: %q %v", clientID, err)
	}
	body[7] = 0x82
	if _, err := parseConnect(body); err == nil {
		t.Fatal("expected credential flag rejection")
	}
}

func TestPublishAndSubscribeRoundTrips(t *testing.T) {
	body, _ := publishBody("devices/camera-001/telemetry", 42, []byte(`{"online":true}`), 1)
	topic, packetID, payload, err := parsePublish(0x32, body)
	if err != nil || topic != "devices/camera-001/telemetry" || packetID != 42 {
		t.Fatalf("unexpected publish parse: %s %d %v", topic, packetID, err)
	}
	if string(payload) != `{"online":true}` {
		t.Fatalf("unexpected payload: %s", payload)
	}
	subscribe, _ := subscribeBody(7, "devices/camera-001/desired")
	id, subscription, err := parseSubscribe(subscribe)
	if err != nil || id != 7 || subscription != "devices/camera-001/desired" {
		t.Fatalf("unexpected subscribe parse: %d %s %v", id, subscription, err)
	}
}

func TestPacketLimitAndMalformedLength(t *testing.T) {
	if err := writePacket(&bytes.Buffer{}, 0x30, make([]byte, maxRemainingBytes+1)); err == nil {
		t.Fatal("expected packet limit")
	}
	reader := bufio.NewReader(bytes.NewReader([]byte{0x80, 0x80, 0x80, 0x80}))
	if _, err := decodeRemainingLength(reader); err == nil {
		t.Fatal("expected malformed remaining length")
	}
}
