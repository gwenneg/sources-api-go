package middleware

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwk"
//	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Issuer string
type Subject string  // ValidatedSubject


type JWKSRetriever interface {
    Retrieve(ctx context.Context, issuer string) (jwk.Set, error)
}

type JWTValidator interface {
    Validate(ctx context.Context, token string) (Issuer, Subject, error)
}
