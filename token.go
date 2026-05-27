package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	signKey   ed25519.PrivateKey
	verifyKey ed25519.PublicKey
)

const (
	jwtAlg     = "EdDSA"
	audURL     = "assessment-link"
	audSession = "assessment-session"
	audAdmin   = "assessment-admin"
	typURL     = "url"
	typSession = "sess"
	typAdmin   = "admin"
)

type urlClaims struct {
	jwt.RegisteredClaims
	EventID     string `json:"eid"`
	EventName   string `json:"en,omitempty"`
	PresenterID string `json:"pid,omitempty"`
	Typ         string `json:"typ"`
}

type sessClaims struct {
	jwt.RegisteredClaims
	SessionID   string `json:"sid"`
	EventID     string `json:"eid"`
	PresenterID string `json:"pid,omitempty"`
	Typ         string `json:"typ"`
}

type adminClaims struct {
	jwt.RegisteredClaims
	Typ string `json:"typ"`
}

func loadKeys() error {
	v := os.Getenv("JWT_PRIVATE_KEY")
	if v == "" {
		return errors.New("JWT_PRIVATE_KEY required (base64 ed25519 seed, 32 bytes)")
	}
	seed, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return err
	}
	if len(seed) != ed25519.SeedSize {
		return errors.New("JWT_PRIVATE_KEY must decode to 32 bytes")
	}
	signKey = ed25519.NewKeyFromSeed(seed)
	verifyKey = signKey.Public().(ed25519.PublicKey)
	return nil
}

func sign(c jwt.Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, c).SignedString(signKey)
}

func parseInto(raw string, dst jwt.Claims, expectedAud string) error {
	_, err := jwt.ParseWithClaims(raw, dst,
		func(t *jwt.Token) (interface{}, error) { return verifyKey, nil },
		jwt.WithValidMethods([]string{jwtAlg}),
		jwt.WithAudience(expectedAud),
		jwt.WithIssuer("assessment"),
	)
	return err
}

func mintURLToken(tokenID, eventID, eventName, presenterID string, nbf, exp time.Time) (string, error) {
	return sign(urlClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "assessment", Subject: presenterID,
			Audience:  jwt.ClaimStrings{audURL},
			ID:        tokenID,
			NotBefore: jwt.NewNumericDate(nbf),
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		EventID: eventID, EventName: eventName, PresenterID: presenterID,
		Typ: typURL,
	})
}

func parseURLToken(raw string) (*urlClaims, error) {
	var c urlClaims
	if err := parseInto(raw, &c, audURL); err != nil {
		return nil, err
	}
	if c.Typ != typURL {
		return nil, errors.New("token type mismatch")
	}
	return &c, nil
}

func mintSessionToken(sessionID, eventID, presenterID string, exp time.Time) (string, error) {
	return sign(sessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "assessment",
			Audience:  jwt.ClaimStrings{audSession},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		SessionID: sessionID, EventID: eventID, PresenterID: presenterID, Typ: typSession,
	})
}

func parseSessionToken(raw string) (*sessClaims, error) {
	var c sessClaims
	if err := parseInto(raw, &c, audSession); err != nil {
		return nil, err
	}
	if c.Typ != typSession {
		return nil, errors.New("token type mismatch")
	}
	return &c, nil
}

func mintAdminSession(exp time.Time) (string, error) {
	return sign(adminClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "assessment",
			Audience:  jwt.ClaimStrings{audAdmin},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		Typ: typAdmin,
	})
}

func parseAdminSession(raw string) (*adminClaims, error) {
	var c adminClaims
	if err := parseInto(raw, &c, audAdmin); err != nil {
		return nil, err
	}
	if c.Typ != typAdmin {
		return nil, errors.New("token type mismatch")
	}
	return &c, nil
}

func GenerateSeed() (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(seed), nil
}
