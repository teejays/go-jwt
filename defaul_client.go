package jwt

import (
	"fmt"
	"strings"
	"time"
)

var cl *Client

// InitDefaultClient initializes the JWT client
func InitDefaultClient(secret string, lifespan time.Duration) error {

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

	newCl := Client{secretKey: []byte(secret), lifespan: lifespan}
	cl = &newCl

	return nil
}

var ErrClientNotInitialized = fmt.Errorf("JWT client is not initialized")

func IsDefaultClientInitialized() bool {
	if cl == nil {
		return false
	}
	return true
}

func GetDefaultClient() (*Client, error) {
	if cl == nil {
		return nil, ErrClientNotInitialized
	}
	return cl, nil
}
