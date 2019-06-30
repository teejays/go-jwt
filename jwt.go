package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
	"github.com/teejays/clog"
)

// const SECRET_KEY = "cheese steak jimmy's"

const headerTyp = "JWT"
const headerAlg = "HS256"

type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

type BasicPayload struct {
	Issuer    string    `json:"iss"`
	Subject   string    `json:"sub"`
	Audience  string    `json:"aud"`
	ExpireAt  time.Time `json:"exp"`
	NotBefore time.Time `json:"nbf"`
	IssuedAt  time.Time `json:"iat"`
	UniqueID  string    `json:"jti"`

	Data interface{} `json:"data"`
}

// NewBasicPayload creates a new payload for the JWT token
func NewBasicPayload(data interface{}) *BasicPayload {
	return &BasicPayload{
		UniqueID: uuid.New().String(),
		Data:     data,
	}
}

type client struct {
	secretKey []byte
	lifespan  time.Duration
}

var cl *client

// InitClient initializes the JWT client
func InitClient(secret string, lifespan time.Duration) error {

	// Make sure we're not reinitializing the client
	if cl != nil {
		return fmt.Errorf("JWT client is already initialized")
	}

	// Validate the secret
	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf("secret key cannot be empty")
	}

	// Validate the lifespan
	if lifespan < 0 {
		return fmt.Errorf("lifespan cannot be zero")
	}

	newCl := client{secretKey: []byte(secret), lifespan: lifespan}
	cl = &newCl

	return nil
}

var ErrClientNotInitialized = fmt.Errorf("JWT client is not initialized")

func IsClientInitialized() bool {
	if cl == nil {
		return false
	}
	return true
}

func GetClient() (*client, error) {
	if cl == nil {
		return nil, ErrClientNotInitialized
	}
	return cl, nil
}

func (c *client) CreateToken(payload *BasicPayload) (string, error) {

	now := time.Now()
	// Create the Header
	var header = Header{
		Type:      headerTyp,
		Algorithm: headerAlg,
	}

	// Create the Payload
	payload.ExpireAt = now.Add(c.lifespan)
	payload.IssuedAt = now
	payload.NotBefore = now

	clog.Debugf("JWT: Creating Token: Lifespan: %v", c.lifespan)
	clog.Debugf("JWT: Creating Token: Expiry: %v", payload.ExpireAt)

	// Convert Header to JSON and then base64
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.StdEncoding.EncodeToString(headerJSON)
	clog.Infof("Header: %+v", header)
	clog.Infof("Header JSON: %s", string(headerJSON))
	clog.Infof("Header B64: %s", headerB64)

	// Convert Payload to JSON and then base64
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.StdEncoding.EncodeToString(payloadJSON)

	// Create the Signature
	signatureB64, err := c.getSignatureBase64(headerB64, payloadB64)
	if err != nil {
		return "", err
	}

	token := headerB64 + "." + payloadB64 + "." + signatureB64

	return token, nil

}

func (c *client) getSignatureBase64(headerB64, payloadB64 string) (string, error) {
	// Create the Signature
	// - step 1: header . payload
	data := []byte(headerB64 + "." + payloadB64)
	// - step 2: hash(data)
	hashData, err := c.hash(data)
	if err != nil {
		return "", err
	}

	// Convert Payload to JSON and then base64
	signatureB64 := base64.StdEncoding.EncodeToString(hashData)

	return signatureB64, nil
}

func (c *client) VerifyAndDecode(token string, v interface{}) error {
	var err error

	err = c.VerifySignature(token)
	if err != nil {
		return err
	}

	err = c.VerifyTimestamps(token)
	if err != nil {
		return err
	}

	err = c.Decode(token, v)
	if err != nil {
		return fmt.Errorf("jwt-go: could not decode the verified claim: %v", err)
	}

	return nil
}

func (c *client) VerifySignature(token string) error {

	// Splity the token into three parts (header, payload, signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid number of jwt token part found: expected %d, got %d", 3, len(parts))
	}
	headerB64 := parts[0]
	payloadB64 := parts[1]
	signatureB64 := parts[2]

	// Get new signature and compare
	newSignatureB64, err := c.getSignatureBase64(headerB64, payloadB64)
	if err != nil {
		return err
	}

	isSame := hmac.Equal([]byte(newSignatureB64), []byte(signatureB64))

	if !isSame {
		return fmt.Errorf("signature verification failed")
	}

	return nil

}

func (c *client) VerifyTimestamps(token string) error {

	// Unmarshal payload into basic struct (ignoring any other details)
	var payload BasicPayload
	err := cl.Decode(token, &payload)
	if err != nil {
		return fmt.Errorf("jwt-go: could not decode claim intom BasicPayload: %v", err)
	}

	// Make sure that the JWT token has not expired
	clog.Debugf("JWT Token Expiry: %v", payload.ExpireAt)
	if payload.ExpireAt.Before(time.Now()) {
		return fmt.Errorf("JWT Token as expired")
	}

	clog.Debugf("JWT Token NotBefore: %v", payload.NotBefore)
	if payload.NotBefore.After(time.Now()) {
		return fmt.Errorf("JWT Token as is not yet valid")
	}

	return nil

}

func (c *client) Decode(token string, v interface{}) error {

	tokenP, err := getTokenParts(token)
	if err != nil {
		return err
	}

	// Get the paylaod
	payloadJSON, err := base64.StdEncoding.DecodeString(tokenP.payloadB64)
	if err != nil {
		return err
	}

	err = json.Unmarshal(payloadJSON, &v)
	if err != nil {
		return err
	}

	return nil
}

type partedToken struct {
	headerB64, payloadB64, signatureB64 string
}

func getTokenParts(token string) (partedToken, error) {
	var tokenP partedToken

	// Splity the token into three parts (header, payload, signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return tokenP, fmt.Errorf("invalid number of jwt token part found: expected %d, got %d", 3, len(parts))
	}

	tokenP.headerB64 = parts[0]
	tokenP.payloadB64 = parts[1]
	tokenP.signatureB64 = parts[2]

	return tokenP, nil
}

func mapToStruct(src interface{}, dest interface{}) error {
	stringToDateTimeHook := func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if t == reflect.TypeOf(time.Time{}) && f == reflect.TypeOf("") {
			return time.Parse(time.RFC3339, data.(string))
		}

		return data, nil
	}

	config := mapstructure.DecoderConfig{
		DecodeHook: stringToDateTimeHook,
		Result:     dest,
	}

	decoder, err := mapstructure.NewDecoder(&config)
	if err != nil {
		return err
	}
	err = decoder.Decode(src)
	if err != nil {
		return fmt.Errorf("could not convert map to a struct: %v", err)
	}

	return nil

}

func (c *client) hash(message []byte) ([]byte, error) {
	hash := hmac.New(sha256.New, c.secretKey)
	_, err := hash.Write(message)
	if err != nil {
		return nil, err
	}
	return hash.Sum(message), nil
}
