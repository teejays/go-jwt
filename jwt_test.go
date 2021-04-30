package jwt_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	jwt "github.com/teejays/go-jwt"
)

func TestClient_CreateToken(t *testing.T) {

	// Create Token
	client, err := jwt.NewClient([]byte("secret key"))
	require.NoError(t, err)

	var claim jwt.BaseClaim
	claim.Issuer = "goku-pharmacy-app"
	claim.Subject = "some unique ID"

	require.Empty(t, claim.InternalBaseClaim)

	token, err := client.CreateToken(&claim, time.Hour)
	require.NoError(t, err)

	require.NotEmpty(t, claim.InternalBaseClaim)

	// Parse Token
	var incomingClaim jwt.BaseClaim
	err = client.VerifyAndDecode(token, &incomingClaim)
	require.NoError(t, err)

	require.Equal(t, claim.ExternallBaseClaim, incomingClaim.ExternallBaseClaim)

	require.NotEmpty(t, incomingClaim.InternalBaseClaim)
}
