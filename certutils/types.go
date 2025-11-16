package certutils

import (
	"crypto/rsa"
	"crypto/x509"
	"time"
)

// KeyRing represents a certificate-key pair with certificate chain
type KeyRing struct {
	Key   *rsa.PrivateKey
	Cert  *x509.Certificate
	Chain []*x509.Certificate
}

// CachedKeyRing wraps KeyRing with expiration time
type CachedKeyRing struct {
	KeyRing    *KeyRing
	UpdateTime time.Time
	ExpireTime time.Time
}
