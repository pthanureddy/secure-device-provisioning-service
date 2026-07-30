package mqtt

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

type CertificateAuthorizer interface {
	AuthorizeCertificate(certificate *x509.Certificate) (string, bool)
}

type Receipt struct {
	DeviceID string    `json:"deviceId"`
	Topic    string    `json:"topic"`
	Payload  []byte    `json:"payload"`
	Received time.Time `json:"receivedAt"`
	PacketID uint16    `json:"packetId"`
	QoS      byte      `json:"qos"`
	RemoteIP string    `json:"remoteIp"`
}

type Broker struct {
	tlsConfig   *tls.Config
	authorizer  CertificateAuthorizer
	listener    net.Listener
	mu          sync.RWMutex
	receipts    []Receipt
	desired     map[string][]byte
	connections map[net.Conn]struct{}
	wg          sync.WaitGroup
}

func NewBroker(config *tls.Config, authorizer CertificateAuthorizer) *Broker {
	return &Broker{
		tlsConfig: config, authorizer: authorizer, desired: make(map[string][]byte),
		connections: make(map[net.Conn]struct{}),
	}
}

func (b *Broker) Start(address string) (string, error) {
	listener, err := tls.Listen("tcp", address, b.tlsConfig)
	if err != nil {
		return "", err
	}
	b.listener = listener
	b.wg.Add(1)
	go b.accept()
	return listener.Addr().String(), nil
}

func (b *Broker) Close() error {
	if b.listener == nil {
		return nil
	}
	err := b.listener.Close()
	b.mu.Lock()
	for connection := range b.connections {
		_ = connection.Close()
	}
	b.mu.Unlock()
	b.wg.Wait()
	return err
}

func (b *Broker) SetDesired(deviceID string, payload []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.desired[deviceID] = append([]byte(nil), payload...)
}

func (b *Broker) Receipts() []Receipt {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]Receipt, len(b.receipts))
	copy(result, b.receipts)
	return result
}

func (b *Broker) accept() {
	defer b.wg.Done()
	for {
		connection, err := b.listener.Accept()
		if err != nil {
			return
		}
		b.mu.Lock()
		b.connections[connection] = struct{}{}
		b.mu.Unlock()
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer func() {
				b.mu.Lock()
				delete(b.connections, connection)
				b.mu.Unlock()
			}()
			defer connection.Close()
			_ = b.handle(connection)
		}()
	}
}

func (b *Broker) handle(connection net.Conn) error {
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return errors.New("MQTT connection must use TLS")
	}
	_ = tlsConnection.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConnection.Handshake(); err != nil {
		return err
	}
	state := tlsConnection.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("client certificate is required")
	}
	authorizedID, ok := b.authorizer.AuthorizeCertificate(state.PeerCertificates[0])
	if !ok {
		return errors.New("device certificate is not active")
	}
	reader := bufio.NewReader(tlsConnection)
	first, err := readPacket(reader)
	if err != nil {
		return err
	}
	if err := requirePacket(first, packetConnect); err != nil {
		return err
	}
	clientID, err := parseConnect(first.body)
	if err != nil {
		return err
	}
	if clientID != authorizedID {
		_ = writePacket(tlsConnection, packetConnAck<<4, []byte{0, 5})
		return errors.New("MQTT client ID must match certificate identity")
	}
	if err := writePacket(tlsConnection, packetConnAck<<4, []byte{0, 0}); err != nil {
		return err
	}
	for {
		incoming, err := readPacket(reader)
		if err != nil {
			return err
		}
		switch packetType(incoming.header) {
		case packetPublish:
			if err := b.handlePublish(tlsConnection, clientID, incoming); err != nil {
				return err
			}
		case packetSubscribe:
			if err := b.handleSubscribe(tlsConnection, clientID, incoming); err != nil {
				return err
			}
		case packetPingReq:
			if len(incoming.body) != 0 {
				return errors.New("PINGREQ must not contain a body")
			}
			if err := writePacket(tlsConnection, packetPingResp<<4, nil); err != nil {
				return err
			}
		case packetDisconnect:
			if len(incoming.body) != 0 {
				return errors.New("DISCONNECT must not contain a body")
			}
			return nil
		default:
			return errors.New("unsupported MQTT packet")
		}
	}
}

func (b *Broker) handlePublish(connection net.Conn, deviceID string, incoming packet) error {
	topic, packetID, payload, err := parsePublish(incoming.header, incoming.body)
	if err != nil {
		return err
	}
	if topic != "devices/"+deviceID+"/telemetry" && topic != "devices/"+deviceID+"/status" {
		return errors.New("publish topic is outside device scope")
	}
	qos := (incoming.header >> 1) & 3
	remoteHost, _, _ := net.SplitHostPort(connection.RemoteAddr().String())
	b.mu.Lock()
	b.receipts = append(b.receipts, Receipt{
		DeviceID: deviceID, Topic: topic, Payload: payload, Received: time.Now().UTC(),
		PacketID: packetID, QoS: qos, RemoteIP: remoteHost,
	})
	b.mu.Unlock()
	if qos == 1 {
		body := make([]byte, 2)
		binary.BigEndian.PutUint16(body, packetID)
		return writePacket(connection, packetPubAck<<4, body)
	}
	return nil
}

func (b *Broker) handleSubscribe(connection net.Conn, deviceID string, incoming packet) error {
	if incoming.header&0x0F != 2 {
		return errors.New("SUBSCRIBE flags must be 0x02")
	}
	packetID, topic, err := parseSubscribe(incoming.body)
	if err != nil {
		return err
	}
	if topic != "devices/"+deviceID+"/desired" {
		return errors.New("subscription topic is outside device scope")
	}
	body := []byte{byte(packetID >> 8), byte(packetID), 0}
	if err := writePacket(connection, packetSubAck<<4, body); err != nil {
		return err
	}
	b.mu.RLock()
	desired := append([]byte(nil), b.desired[deviceID]...)
	b.mu.RUnlock()
	if len(desired) == 0 {
		return nil
	}
	publish, err := publishBody(topic, 0, desired, 0)
	if err != nil {
		return err
	}
	return writePacket(connection, packetPublish<<4, publish)
}

func RunUntilCancelled(ctx context.Context, broker *Broker) error {
	<-ctx.Done()
	err := broker.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
