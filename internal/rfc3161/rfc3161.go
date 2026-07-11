// Package rfc3161 implements a minimal RFC 3161 Time-Stamp Protocol client
// using only the Go standard library, in keeping with the project's
// zero-dependency constraint. It builds DER-encoded TimeStampReq messages,
// and parses TimeStampResp answers far enough to validate that the returned
// token attests the submitted hash.
package rfc3161

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	oidSHA256         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSignedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// PKIStatus values accepted as success (RFC 3161 section 2.4.2).
const (
	statusGranted         = 0
	statusGrantedWithMods = 1
)

// messageImprint binds the request/token to the hashed data (RFC 3161 2.4.1).
type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// timeStampReq is the DER structure POSTed to the TSA (RFC 3161 2.4.1).
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional"`
}

// pkiStatusInfo carries the TSA verdict (RFC 3161 2.4.2).
type pkiStatusInfo struct {
	Status       int
	StatusString []asn1.RawValue `asn1:"optional"`
	FailInfo     asn1.BitString  `asn1:"optional"`
}

// timeStampResp is the DER structure returned by the TSA (RFC 3161 2.4.2).
type timeStampResp struct {
	Status pkiStatusInfo
	Token  asn1.RawValue `asn1:"optional"`
}

// contentInfo is the outer CMS wrapper of a TimeStampToken (RFC 5652 3).
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// encapsulatedContentInfo holds the DER-encoded TSTInfo (RFC 5652 5.2).
type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

// signedData is parsed only deep enough to reach the TSTInfo; signature
// fields are kept raw (RFC 5652 5.1).
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

// accuracy bounds the TSA clock precision (RFC 3161 2.4.2).
type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// tstInfo is the timestamped statement inside the token (RFC 3161 2.4.2).
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

// TokenInfo summarizes the attestation extracted from a timestamp token.
type TokenInfo struct {
	GenTime      time.Time
	SerialNumber *big.Int
	Policy       string
}

// newRequest builds a DER-encoded TimeStampReq for the given SHA-256 digest.
// certReq is set so the TSA embeds its signing certificate, allowing the
// token to be verified offline later.
func newRequest(digest []byte, nonce *big.Int) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("rfc3161: digest must be %d bytes, got %d", sha256.Size, len(digest))
	}
	req := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			HashedMessage: digest,
		},
		Nonce:   nonce,
		CertReq: true,
	}
	return asn1.Marshal(req)
}

// parseResponse validates a DER TimeStampResp: the TSA must have granted the
// request and the token must attest the submitted digest and echo our nonce.
// It returns the raw token bytes (to be saved to disk) and their summary.
func parseResponse(der, digest []byte, nonce *big.Int) ([]byte, *TokenInfo, error) {
	var resp timeStampResp
	if _, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, nil, fmt.Errorf("rfc3161: invalid TimeStampResp: %w", err)
	}

	if resp.Status.Status != statusGranted && resp.Status.Status != statusGrantedWithMods {
		msg := fmt.Sprintf("rfc3161: TSA rejected the request (status %d)", resp.Status.Status)
		if text := resp.Status.text(); text != "" {
			msg += ": " + text
		}
		return nil, nil, errors.New(msg)
	}

	if len(resp.Token.FullBytes) == 0 {
		return nil, nil, errors.New("rfc3161: TSA granted the request but returned no token")
	}

	info, err := parseToken(resp.Token.FullBytes, digest, nonce)
	if err != nil {
		return nil, nil, err
	}
	return resp.Token.FullBytes, info, nil
}

// parseToken descends through the CMS layers of a TimeStampToken down to the
// TSTInfo, and checks it matches the digest and nonce we submitted.
func parseToken(tokenDER, digest []byte, nonce *big.Int) (*TokenInfo, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(tokenDER, &ci); err != nil {
		return nil, fmt.Errorf("rfc3161: invalid token ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("rfc3161: unexpected token content type %s", ci.ContentType)
	}

	// encoding/asn1 does not unwrap the explicit [0] tag when the target is a
	// RawValue: Content captures the whole [0] element and its Bytes field
	// holds the SignedData SEQUENCE.
	sdDER := ci.Content.FullBytes
	if ci.Content.Class == asn1.ClassContextSpecific {
		sdDER = ci.Content.Bytes
	}

	var sd signedData
	if _, err := asn1.Unmarshal(sdDER, &sd); err != nil {
		return nil, fmt.Errorf("rfc3161: invalid token SignedData: %w", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidContentTSTInfo) {
		return nil, fmt.Errorf("rfc3161: unexpected encapsulated content type %s", sd.EncapContentInfo.EContentType)
	}

	var tst tstInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &tst); err != nil {
		return nil, fmt.Errorf("rfc3161: invalid TSTInfo: %w", err)
	}

	if !bytes.Equal(tst.MessageImprint.HashedMessage, digest) {
		return nil, errors.New("rfc3161: token does not attest the submitted hash")
	}
	if nonce != nil && (tst.Nonce == nil || tst.Nonce.Cmp(nonce) != 0) {
		return nil, errors.New("rfc3161: token nonce does not match the request nonce")
	}

	return &TokenInfo{
		GenTime:      tst.GenTime,
		SerialNumber: tst.SerialNumber,
		Policy:       tst.Policy.String(),
	}, nil
}

// text joins the optional PKIFreeText strings of a status into one message.
func (st pkiStatusInfo) text() string {
	if len(st.StatusString) == 0 {
		return ""
	}
	parts := make([]string, 0, len(st.StatusString))
	for _, rv := range st.StatusString {
		parts = append(parts, string(rv.Bytes))
	}
	return strings.Join(parts, "; ")
}
