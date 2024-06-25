// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers/tls"
	"golang.org/x/crypto/cryptobyte"
)

type TLSHandshakeType uint8

const (
	TLSHandshakeClientHello        TLSHandshakeType = 1
	TLSHandshakeServerHello        TLSHandshakeType = 2
	TLSHandshakeCertificate        TLSHandshakeType = 11
	TLSHandshakeServerKeyExchange  TLSHandshakeType = 12
	TLSHandshakeCertificateRequest TLSHandshakeType = 13
	TLSHandshakeServerHelloDone    TLSHandshakeType = 14
	TLSHandshakeCertificateVerify  TLSHandshakeType = 15
	TLSHandshakeClientKeyExchange  TLSHandshakeType = 16
	TLSHandshakeUnknown            TLSHandshakeType = 255
)

// TLSHandshakeRecord defines the structure of a Handshare Record
type TLSHandshakeRecord struct {
	TLSRecordHeader
	HandshakeType TLSHandshakeType
	ClientHello   *tls.ClientHelloInfo `json:"client_hello,omitempty"`
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.TLSRecordHeader = h

	if len(data) < 4 {
		df.SetTruncated()
		return errors.New("TLS Change Cipher Spec record incorrect length")
	}

	t.HandshakeType = TLSHandshakeType(data[0])
	str := cryptobyte.String(data[1:])
	var hs_len uint32
	str.ReadUint24(&hs_len)
	if hs_len+4 != uint32(t.Length) {
		df.SetTruncated()
		return errors.New("TLS handshake length mismatch")
	}
	switch t.HandshakeType {
	case TLSHandshakeClientHello:
		t.ClientHello = tls.UnmarshalClientHello(str)
	case TLSHandshakeServerHello:
	case TLSHandshakeCertificate:
	case TLSHandshakeServerKeyExchange:
	case TLSHandshakeCertificateRequest:
	case TLSHandshakeServerHelloDone:
	case TLSHandshakeCertificateVerify:
	case TLSHandshakeClientKeyExchange:
	}
	return nil
}
