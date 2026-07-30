package mqtt

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

type Client struct {
	connection net.Conn
	reader     *bufio.Reader
	packetID   uint16
}

func Dial(address, clientID string, config *tls.Config) (*Client, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("dial MQTT TLS endpoint: %w", err)
	}
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	body, err := connectBody(clientID)
	if err != nil {
		connection.Close()
		return nil, err
	}
	if err := writePacket(connection, packetConnect<<4, body); err != nil {
		connection.Close()
		return nil, err
	}
	reader := bufio.NewReader(connection)
	response, err := readPacket(reader)
	if err != nil {
		connection.Close()
		return nil, err
	}
	if err := requirePacket(response, packetConnAck); err != nil {
		connection.Close()
		return nil, err
	}
	if len(response.body) != 2 || response.body[1] != 0 {
		connection.Close()
		return nil, errors.New("MQTT broker rejected connection")
	}
	return &Client{connection: connection, reader: reader}, nil
}

func (c *Client) PublishQoS1(topic string, payload []byte) error {
	packetID := c.nextPacketID()
	body, err := publishBody(topic, packetID, payload, 1)
	if err != nil {
		return err
	}
	if err := writePacket(c.connection, (packetPublish<<4)|2, body); err != nil {
		return err
	}
	response, err := readPacket(c.reader)
	if err != nil {
		return err
	}
	if err := requirePacket(response, packetPubAck); err != nil {
		return err
	}
	if len(response.body) != 2 || binary.BigEndian.Uint16(response.body) != packetID {
		return errors.New("PUBACK packet ID does not match")
	}
	return nil
}

func (c *Client) SubscribeDesired(topic string) ([]byte, error) {
	packetID := c.nextPacketID()
	body, err := subscribeBody(packetID, topic)
	if err != nil {
		return nil, err
	}
	if err := writePacket(c.connection, (packetSubscribe<<4)|2, body); err != nil {
		return nil, err
	}
	ack, err := readPacket(c.reader)
	if err != nil {
		return nil, err
	}
	if err := requirePacket(ack, packetSubAck); err != nil {
		return nil, err
	}
	if len(ack.body) != 3 || binary.BigEndian.Uint16(ack.body[:2]) != packetID || ack.body[2] != 0 {
		return nil, errors.New("invalid SUBACK")
	}
	message, err := readPacket(c.reader)
	if err != nil {
		return nil, err
	}
	if err := requirePacket(message, packetPublish); err != nil {
		return nil, err
	}
	actualTopic, _, payload, err := parsePublish(message.header, message.body)
	if err != nil {
		return nil, err
	}
	if actualTopic != topic {
		return nil, errors.New("desired configuration topic does not match subscription")
	}
	return payload, nil
}

func (c *Client) Ping() error {
	if err := writePacket(c.connection, packetPingReq<<4, nil); err != nil {
		return err
	}
	response, err := readPacket(c.reader)
	if err != nil {
		return err
	}
	return requirePacket(response, packetPingResp)
}

func (c *Client) Close() error {
	_ = writePacket(c.connection, packetDisconnect<<4, nil)
	return c.connection.Close()
}

func (c *Client) nextPacketID() uint16 {
	c.packetID++
	if c.packetID == 0 {
		c.packetID = 1
	}
	return c.packetID
}
