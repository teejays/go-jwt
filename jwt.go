package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/teejays/clog"
)

const gHeaderTyp = "JWT"
const gHeaderAlg = "HS256"

// Header represents the header part of a JWT
type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

// Claim represents the claim part of JWT. Since we want to allow use of custom claim types,
// this is an interface with just one requirement - we should be able to get the basic/minimum
// required fields for a JWT claim.
type Claim interface {
	GetBaseClaim() *BaseClaim
	VerifyTimestamps() error
}

// BaseClaim represents all the minimum required fields for a JWT claim, as per RFC 7519 standard.
type BaseClaim struct {
	ExternallBaseClaim
	InternalBaseClaim
}

type ExternallBaseClaim struct {
	// Issuer is the authority that generated the JWT
	Issuer string `json:"iss"`
	// Subject is the main entity which is using the JWT, e.g. user
	Subject string `json:"sub"`
	//Audience of a token is the intended recipient of the token. The audience value is a string -- typically, the base address of the resource being accessed, such as https://contoso.com.
	Audience string `json:"aud"`
	// UniqueID is a unique identifier for the JWT
	UniqueID string `json:"jti"`
}

type InternalBaseClaim struct {
	ExpireAt  time.Time `json:"exp"`
	NotBefore time.Time `json:"nbf"`
	IssuedAt  time.Time `json:"iat"`
}

// GetBaseClaim returns the BaseClaim type, which should contain all the
// minimum required JWT claim fields
func (bc *BaseClaim) GetBaseClaim() *BaseClaim {
	return bc
}

// VerifyTimestamps verifies that the claim is valid i.e. not expired and not too early
func (bc *BaseClaim) VerifyTimestamps() error {

	// Make sure that the JWT token has not expired
	clog.Debugf("JWT: token expiry: %v", bc.ExpireAt)
	if bc.ExpireAt.Before(time.Now()) {
		return fmt.Errorf("JWT has expired")
	}

	clog.Debugf("JWT: token valid not before: %v", bc.NotBefore)
	if bc.NotBefore.After(time.Now()) {
		return fmt.Errorf("JWT is not valid yet")
	}

	return nil

}

type Client struct {
	secretKey []byte
}

func NewClient(secret []byte) (*Client, error) {
	return &Client{
		secretKey: secret,
	}, nil
}

func (c *Client) CreateToken(claim Claim, lifespan time.Duration) (string, error) {

	if lifespan < time.Second {
		return "", fmt.Errorf("cannot create a JWT with lifespan less than a second")
	}
	baseClaim := claim.GetBaseClaim()

	now := time.Now()
	// Create the Header
	var header = Header{
		Type:      gHeaderTyp,
		Algorithm: gHeaderAlg,
	}

	// Create the Payload
	baseClaim.ExpireAt = now.Add(lifespan)
	baseClaim.IssuedAt = now
	baseClaim.NotBefore = now

	clog.Debugf("JWT: Creating Token: Lifespan: %s", lifespan)
	clog.Debugf("JWT: Creating Token: Expiry: %v", baseClaim.ExpireAt)

	// Convert Header to JSON and then base64
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	// TODO: Encode directly to []byte and use those
	headerB64 := base64.StdEncoding.EncodeToString(headerJSON)
	clog.Debugf("JWT: Creating Token: Header: %+v", header)

	// Convert Payload to JSON and then base64
	clog.Debugf("JWT: Creating Token: Claim: %+v", claim)
	claimJSON, err := json.Marshal(claim)
	if err != nil {
		return "", err
	}
	// TODO: Encode directly to []byte and use those
	claimB64 := base64.StdEncoding.EncodeToString(claimJSON)

	// Create the Signature
	signatureB64, err := c.getSignatureBase64(headerB64, claimB64)
	if err != nil {
		return "", err
	}

	token := headerB64 + "." + claimB64 + "." + signatureB64

	return token, nil

}

func (c *Client) getSignatureBase64(headerB64, claimB64 string) (string, error) {
	// Create the Signature
	// - step 1: header . payload
	data := []byte(headerB64 + "." + claimB64)
	// - step 2: hash(data)
	hashData, err := c.hash(data)
	if err != nil {
		return "", err
	}

	// Convert Payload to JSON and then base64
	signatureB64 := base64.StdEncoding.EncodeToString(hashData)

	return signatureB64, nil
}

func (c *Client) VerifyAndDecode(token string, claim Claim) error {
	var err error

	err = c.VerifySignature(token)
	if err != nil {
		return err
	}

	err = c.Decode(token, claim)
	if err != nil {
		return fmt.Errorf("jwt: could not decode the claim: %v", err)
	}

	err = claim.VerifyTimestamps()
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) VerifySignature(token string) error {

	// Splity the token into three parts (header, payload, signature)
	tokenP, err := getTokenParts(token)
	if err != nil {
		return err
	}

	// Get new signature and compare
	newSignatureB64, err := c.getSignatureBase64(tokenP.headerB64, tokenP.payloadB64)
	if err != nil {
		return err
	}

	isSame := hmac.Equal([]byte(newSignatureB64), []byte(tokenP.signatureB64))

	if !isSame {
		return fmt.Errorf("signature verification failed")
	}

	return nil

}

func (c *Client) Decode(token string, v interface{}) error {

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
		return fmt.Errorf("jwt-go: could not decode claim intom BasePayload: %v", err)
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

func (c *Client) hash(message []byte) ([]byte, error) {
	hash := hmac.New(sha256.New, c.secretKey)
	_, err := hash.Write(message)
	if err != nil {
		return nil, err
	}
	return hash.Sum(message), nil
}

func Example() {
	fmt.Println("lala!")
	// Output:
	// lala!
}
