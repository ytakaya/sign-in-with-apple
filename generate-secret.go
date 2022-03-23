package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	"github.com/square/go-jose"
)

type secretPayload struct {
	Issuer    string `json:"iss"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
}

func generateClientSecret(signingKey, teamID, clientID, keyID string) (string, error) {
	block, _ := pem.Decode([]byte(signingKey))
	if block == nil {
		return "", errors.New("fail to decode signingKey")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	alg := jose.ES256

	header := &jose.SignerOptions{}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, header.WithHeader("alg", alg).WithHeader("kid", keyID))
	if e != nil {
		return "", err
	}

	now := time.Now()
	payload := secretPayload{
		Issuer:    teamID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour*24*180 - time.Second).Unix(),
		Audience:  "https://appleid.apple.com",
		Subject:   clientID,
	}
	jsonPayload, e := json.Marshal(payload)
	if e != nil {
		return "", err
	}

	signed, e := signer.Sign(jsonPayload)
	if e != nil {
		return "", err
	}

	return signed.CompactSerialize()
}
