package tls

import (
	"golang.org/x/crypto/cryptobyte"
)

type CertificateInfo struct {
	Certificates [][]byte `json:"certificates"`
}

func UnmarshalCertificate(msg cryptobyte.String) *CertificateInfo {
	info := &CertificateInfo{}
	var certs cryptobyte.String
	if !msg.ReadUint24LengthPrefixed(&certs) {
		return nil
	}
	info.Certificates = [][]byte{}
	for !certs.Empty() {
		var cert cryptobyte.String
		if !certs.ReadUint24LengthPrefixed(&cert) {
			return nil
		}

		info.Certificates = append(info.Certificates, cert)
	}

	if !msg.Empty() {
		return nil
	}

	return info
}

type IBCCertificateInfo struct {
	ID        []byte `json:"id"`
	Parameter []byte `json:"parameter"`
}

func UnmarshalIBCCertificate(msg cryptobyte.String) *IBCCertificateInfo {
	info := &IBCCertificateInfo{}
	if !msg.ReadUint16LengthPrefixed((*cryptobyte.String)(&info.ID)) {
		return nil
	}
	if !msg.ReadUint24LengthPrefixed((*cryptobyte.String)(&info.Parameter)) {
		return nil
	}

	if !msg.Empty() {
		return nil
	}

	return info
}

type CertificateRequestInfo struct {
	CertificateTypes       []byte `json:"certificate_types"`
	CertificateAuthorities []byte `json:"certificate_authorities"`
}

func UnmarshalCertificateRequest(msg cryptobyte.String) *CertificateRequestInfo {
	info := &CertificateRequestInfo{}
	if !msg.ReadUint8LengthPrefixed((*cryptobyte.String)(&info.CertificateTypes)) {
		return nil
	}
	if !msg.ReadUint16LengthPrefixed((*cryptobyte.String)(&info.CertificateAuthorities)) {
		return nil
	}

	if !msg.Empty() {
		return nil
	}
	return info
}
