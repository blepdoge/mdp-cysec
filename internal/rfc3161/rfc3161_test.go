package rfc3161

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var testGenTime = time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)

// mustMarshal marshals v with asn1 or fails the test.
func mustMarshal(t *testing.T, v interface{}, params string) []byte {
	t.Helper()
	der, err := asn1.MarshalWithParams(v, params)
	if err != nil {
		t.Fatalf("asn1 marshal failed: %v", err)
	}
	return der
}

// buildTestToken assembles a syntactically valid TimeStampToken (ContentInfo
// -> SignedData -> TSTInfo) around the given digest and nonce.
func buildTestToken(t *testing.T, digest []byte, nonce *big.Int) []byte {
	t.Helper()

	tst := tstInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			HashedMessage: digest,
		},
		SerialNumber: big.NewInt(42),
		GenTime:      testGenTime,
		Nonce:        nonce,
	}
	tstDER := mustMarshal(t, tst, "")

	algsDER := mustMarshal(t, []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}}, "set")
	signersDER := mustMarshal(t, []asn1.RawValue{}, "set")

	sd := signedData{
		Version:          3,
		DigestAlgorithms: asn1.RawValue{FullBytes: algsDER},
		EncapContentInfo: encapsulatedContentInfo{
			EContentType: oidContentTSTInfo,
			EContent:     tstDER,
		},
		SignerInfos: asn1.RawValue{FullBytes: signersDER},
	}
	sdDER := mustMarshal(t, sd, "")

	ci := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER},
	}
	return mustMarshal(t, ci, "")
}

// buildTestResponse wraps a token (or no token) in a TimeStampResp.
func buildTestResponse(t *testing.T, status int, tokenDER []byte) []byte {
	t.Helper()
	resp := timeStampResp{Status: pkiStatusInfo{Status: status}}
	if tokenDER != nil {
		resp.Token = asn1.RawValue{FullBytes: tokenDER}
	}
	return mustMarshal(t, resp, "")
}

func TestNewRequestRoundTrip(t *testing.T) {
	digest := sha256.Sum256([]byte("merkle-root"))
	nonce := big.NewInt(123456789)

	der, err := newRequest(digest[:], nonce)
	if err != nil {
		t.Fatalf("newRequest returned error: %v", err)
	}

	var req timeStampReq
	if _, err := asn1.Unmarshal(der, &req); err != nil {
		t.Fatalf("request does not round-trip: %v", err)
	}
	if req.Version != 1 {
		t.Errorf("version = %d, want 1", req.Version)
	}
	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		t.Errorf("hash algorithm = %s, want SHA-256", req.MessageImprint.HashAlgorithm.Algorithm)
	}
	if !bytes.Equal(req.MessageImprint.HashedMessage, digest[:]) {
		t.Error("hashed message does not match digest")
	}
	if req.Nonce == nil || req.Nonce.Cmp(nonce) != 0 {
		t.Error("nonce not preserved")
	}
	if !req.CertReq {
		t.Error("certReq should be true")
	}
}

func TestNewRequestRejectsBadDigest(t *testing.T) {
	if _, err := newRequest([]byte("too-short"), big.NewInt(1)); err == nil {
		t.Error("expected error for non-SHA256-sized digest, got nil")
	}
}

func TestParseResponseGranted(t *testing.T) {
	digest := sha256.Sum256([]byte("merkle-root"))
	nonce := big.NewInt(777)
	tokenDER := buildTestToken(t, digest[:], nonce)
	respDER := buildTestResponse(t, statusGranted, tokenDER)

	token, info, err := parseResponse(respDER, digest[:], nonce)
	if err != nil {
		t.Fatalf("parseResponse returned error: %v", err)
	}
	if !bytes.Equal(token, tokenDER) {
		t.Error("returned token differs from the one in the response")
	}
	if !info.GenTime.Equal(testGenTime) {
		t.Errorf("genTime = %v, want %v", info.GenTime, testGenTime)
	}
	if info.SerialNumber.Int64() != 42 {
		t.Errorf("serial = %v, want 42", info.SerialNumber)
	}
}

func TestParseResponseRejected(t *testing.T) {
	respDER := buildTestResponse(t, 2, nil) // 2 = rejection
	if _, _, err := parseResponse(respDER, make([]byte, sha256.Size), big.NewInt(1)); err == nil {
		t.Error("expected error for rejected response, got nil")
	}
}

func TestParseResponseDigestMismatch(t *testing.T) {
	digest := sha256.Sum256([]byte("merkle-root"))
	other := sha256.Sum256([]byte("tampered"))
	nonce := big.NewInt(777)
	tokenDER := buildTestToken(t, other[:], nonce)
	respDER := buildTestResponse(t, statusGranted, tokenDER)

	if _, _, err := parseResponse(respDER, digest[:], nonce); err == nil {
		t.Error("expected error when token attests a different hash, got nil")
	}
}

func TestParseResponseNonceMismatch(t *testing.T) {
	digest := sha256.Sum256([]byte("merkle-root"))
	tokenDER := buildTestToken(t, digest[:], big.NewInt(1))
	respDER := buildTestResponse(t, statusGranted, tokenDER)

	if _, _, err := parseResponse(respDER, digest[:], big.NewInt(2)); err == nil {
		t.Error("expected error for nonce mismatch, got nil")
	}
}

func TestClientRequestAgainstFakeTSA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/timestamp-query" {
			t.Errorf("content type = %q, want application/timestamp-query", ct)
		}
		body, _ := io.ReadAll(r.Body)

		var req timeStampReq
		if _, err := asn1.Unmarshal(body, &req); err != nil {
			t.Errorf("TSA could not parse request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tokenDER := buildTestToken(t, req.MessageImprint.HashedMessage, req.Nonce)
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(buildTestResponse(t, statusGranted, tokenDER))
	}))
	defer srv.Close()

	digest := sha256.Sum256([]byte("merkle-root"))
	client := NewClient(srv.URL)

	token, info, err := client.Request(digest[:])
	if err != nil {
		t.Fatalf("Request returned error: %v", err)
	}
	if len(token) == 0 {
		t.Error("token is empty")
	}
	if !info.GenTime.Equal(testGenTime) {
		t.Errorf("genTime = %v, want %v", info.GenTime, testGenTime)
	}
}

func TestClientRequestTSARejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(buildTestResponse(t, 2, nil))
	}))
	defer srv.Close()

	digest := sha256.Sum256([]byte("merkle-root"))
	if _, _, err := NewClient(srv.URL).Request(digest[:]); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Errorf("expected rejection error, got %v", err)
	}
}
