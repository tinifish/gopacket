package tls

import (
	"golang.org/x/crypto/cryptobyte"
)

type ServerHelloInfo struct {
	Version           ProtocolVersion   `json:"version"`
	Random            []byte            `json:"random"`
	SessionID         []byte            `json:"session_id"`
	CipherSuite       CipherSuite       `json:"cipher_suite"`
	CompressionMethod CompressionMethod `json:"compression_method"`
	Extensions        []Extension       `json:"extensions"`

	Info struct {
		ServerName *string  `json:"server_name"`
		SCTs       bool     `json:"scts"`
		Protocols  []string `json:"protocols"`
	} `json:"info"`
}

func UnmarshalServerHello(msg cryptobyte.String) *ServerHelloInfo {
	info := &ServerHelloInfo{}

	if !msg.ReadUint16((*uint16)(&info.Version)) {
		return nil
	}

	if !msg.ReadBytes(&info.Random, 32) {
		return nil
	}

	if !msg.ReadUint8LengthPrefixed((*cryptobyte.String)(&info.SessionID)) {
		return nil
	}

	var suite uint16
	if !msg.ReadUint16(&suite) {
		return nil
	}
	info.CipherSuite = MakeCipherSuite(suite)

	var method uint8
	if !msg.ReadUint8(&method) {
		return nil
	}
	info.CompressionMethod = CompressionMethod(method)

	info.Extensions = []Extension{}

	if msg.Empty() {
		return info
	}
	var extensions cryptobyte.String
	if !msg.ReadUint16LengthPrefixed(&extensions) {
		return nil
	}
	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			return nil
		}

		parseData := extensionParsers[extType]
		if parseData == nil {
			parseData = ParseUnknownExtensionData
		}
		data := parseData(extData)

		info.Extensions = append(info.Extensions, Extension{
			Type:    extType,
			Name:    Extensions[extType].Name,
			Grease:  Extensions[extType].Grease,
			Private: Extensions[extType].Private,
			Data:    data,
		})

		switch extType {
		case 0:
			info.Info.ServerName = &data.(*ServerNameData).HostName
		case 16:
			info.Info.Protocols = data.(*ALPNData).Protocols
		case 18:
			info.Info.SCTs = true
		}

	}

	if !msg.Empty() {
		return nil
	}

	return info
}
