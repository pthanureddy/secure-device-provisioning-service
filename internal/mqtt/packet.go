package mqtt

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	packetConnect     = 1
	packetConnAck     = 2
	packetPublish     = 3
	packetPubAck      = 4
	packetSubscribe   = 8
	packetSubAck      = 9
	packetPingReq     = 12
	packetPingResp    = 13
	packetDisconnect  = 14
	maxRemainingBytes = 1 << 20
)

type packet struct {
	header byte
	body   []byte
}

func writePacket(writer io.Writer, header byte, body []byte) error {
	if len(body) > maxRemainingBytes {
		return errors.New("MQTT packet exceeds configured limit")
	}
	remaining := encodeRemainingLength(len(body))
	data := append([]byte{header}, remaining...)
	data = append(data, body...)
	_, err := writer.Write(data)
	return err
}

func readPacket(reader *bufio.Reader) (packet, error) {
	header, err := reader.ReadByte()
	if err != nil {
		return packet{}, err
	}
	remaining, err := decodeRemainingLength(reader)
	if err != nil {
		return packet{}, err
	}
	if remaining > maxRemainingBytes {
		return packet{}, errors.New("MQTT packet exceeds configured limit")
	}
	body := make([]byte, remaining)
	if _, err := io.ReadFull(reader, body); err != nil {
		return packet{}, err
	}
	return packet{header: header, body: body}, nil
}

func encodeRemainingLength(value int) []byte {
	var encoded []byte
	for {
		digit := byte(value % 128)
		value /= 128
		if value > 0 {
			digit |= 0x80
		}
		encoded = append(encoded, digit)
		if value == 0 {
			return encoded
		}
	}
}

func decodeRemainingLength(reader *bufio.Reader) (int, error) {
	multiplier := 1
	value := 0
	for count := 0; count < 4; count++ {
		digit, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		value += int(digit&127) * multiplier
		if digit&128 == 0 {
			return value, nil
		}
		multiplier *= 128
	}
	return 0, errors.New("malformed MQTT remaining length")
}

func encodeString(value string) ([]byte, error) {
	if len(value) == 0 || len(value) > 65535 {
		return nil, errors.New("MQTT string length must be between 1 and 65535 bytes")
	}
	result := make([]byte, 2+len(value))
	binary.BigEndian.PutUint16(result[:2], uint16(len(value)))
	copy(result[2:], value)
	return result, nil
}

func readString(data []byte, offset *int) (string, error) {
	if *offset+2 > len(data) {
		return "", io.ErrUnexpectedEOF
	}
	length := int(binary.BigEndian.Uint16(data[*offset : *offset+2]))
	*offset += 2
	if length == 0 || *offset+length > len(data) {
		return "", errors.New("invalid MQTT string")
	}
	value := string(data[*offset : *offset+length])
	*offset += length
	return value, nil
}

func connectBody(clientID string) ([]byte, error) {
	protocol, _ := encodeString("MQTT")
	client, err := encodeString(clientID)
	if err != nil {
		return nil, err
	}
	body := append(protocol, 4, 2, 0, 30)
	return append(body, client...), nil
}

func parseConnect(body []byte) (string, error) {
	offset := 0
	protocol, err := readString(body, &offset)
	if err != nil || protocol != "MQTT" {
		return "", errors.New("invalid MQTT protocol name")
	}
	if offset+4 > len(body) || body[offset] != 4 {
		return "", errors.New("only MQTT 3.1.1 is supported")
	}
	flags := body[offset+1]
	if flags&2 == 0 || flags&0xFC != 0 {
		return "", errors.New("only clean sessions without credentials are supported")
	}
	offset += 4
	clientID, err := readString(body, &offset)
	if err != nil {
		return "", err
	}
	if offset != len(body) {
		return "", errors.New("unexpected CONNECT payload")
	}
	return clientID, nil
}

func publishBody(topic string, packetID uint16, payload []byte, qos byte) ([]byte, error) {
	topicBytes, err := encodeString(topic)
	if err != nil {
		return nil, err
	}
	body := topicBytes
	if qos == 1 {
		if packetID == 0 {
			return nil, errors.New("QoS 1 packet ID must not be zero")
		}
		id := make([]byte, 2)
		binary.BigEndian.PutUint16(id, packetID)
		body = append(body, id...)
	}
	return append(body, payload...), nil
}

func parsePublish(header byte, body []byte) (string, uint16, []byte, error) {
	qos := (header >> 1) & 3
	if qos > 1 {
		return "", 0, nil, errors.New("only MQTT QoS 0 and 1 are supported")
	}
	offset := 0
	topic, err := readString(body, &offset)
	if err != nil {
		return "", 0, nil, err
	}
	var packetID uint16
	if qos == 1 {
		if offset+2 > len(body) {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		packetID = binary.BigEndian.Uint16(body[offset : offset+2])
		offset += 2
		if packetID == 0 {
			return "", 0, nil, errors.New("QoS 1 packet ID must not be zero")
		}
	}
	return topic, packetID, append([]byte(nil), body[offset:]...), nil
}

func subscribeBody(packetID uint16, topic string) ([]byte, error) {
	if packetID == 0 {
		return nil, errors.New("SUBSCRIBE packet ID must not be zero")
	}
	topicBytes, err := encodeString(topic)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, packetID)
	body = append(body, topicBytes...)
	return append(body, 0), nil
}

func parseSubscribe(body []byte) (uint16, string, error) {
	if len(body) < 5 {
		return 0, "", io.ErrUnexpectedEOF
	}
	packetID := binary.BigEndian.Uint16(body[:2])
	offset := 2
	topic, err := readString(body, &offset)
	if err != nil {
		return 0, "", err
	}
	if packetID == 0 || offset+1 != len(body) || body[offset] != 0 {
		return 0, "", errors.New("only one QoS 0 subscription is supported")
	}
	return packetID, topic, nil
}

func packetType(header byte) byte {
	return header >> 4
}

func requirePacket(actual packet, expected byte) error {
	if packetType(actual.header) != expected {
		return fmt.Errorf("expected MQTT packet type %d, got %d", expected, packetType(actual.header))
	}
	return nil
}
