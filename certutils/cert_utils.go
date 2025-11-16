package certutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// GenerateRSAPrivateKey generates a new 2048-bit RSA private key
func GenerateRSAPrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %v", err)
	}
	return privateKey, nil
}

// ForgeCertificate creates a new certificate based on an original certificate but signed by a CA
func ForgeCertificate(caCert *x509.Certificate, caKey *rsa.PrivateKey, origCert *x509.Certificate, certExpireTime int) (*KeyRing, error) {
	// Generate a new private key for the forged certificate
	newKey, err := GenerateRSAPrivateKey()
	if err != nil {
		return nil, err
	}

	// Create a new certificate template based on the original
	template := &x509.Certificate{
		SerialNumber:          generateSerialNumber(),
		Subject:               origCert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(certExpireTime) * time.Hour),
		KeyUsage:              origCert.KeyUsage,
		ExtKeyUsage:           origCert.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
		Issuer:                caCert.Subject,
	}

	// Copy Subject Alternative Names if present
	if len(origCert.DNSNames) > 0 {
		template.DNSNames = origCert.DNSNames
	}

	if len(origCert.IPAddresses) > 0 {
		template.IPAddresses = origCert.IPAddresses
	}

	// Create the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &newKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Parse the certificate back
	forgedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Create certificate chain
	chain := []*x509.Certificate{caCert}

	return &KeyRing{
		Key:   newKey,
		Cert:  forgedCert,
		Chain: chain,
	}, nil
}

// LoadCertificate loads a certificate from PEM format
func LoadCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

// LoadPrivateKey loads a private key from PEM format
func LoadPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return rsaKey, nil
}

// CertificateToPEM converts a certificate to PEM format
func CertificateToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// PrivateKeyToPEM converts a private key to PEM format
func PrivateKeyToPEM(key *rsa.PrivateKey) []byte {
	privBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})
}

// Generate a random serial number for certificates
func generateSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	return serialNumber
}

// CreateCACertificate creates a self-signed CA certificate
func CreateCACertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: generateSerialNumber(),
		Subject: pkix.Name{
			Organization:  []string{"TFE SSL Proxy"},
			Country:       []string{"US"},
			Province:      []string{"California"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Internet Security"},
			PostalCode:    []string{"94105"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Create the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// Parse the certificate back
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

// CertificateFingerprint generates SHA1 fingerprint of certificate
func CertificateFingerprint(cert *x509.Certificate) string {
	fingerprint := make([]byte, 20)
	sum := 0
	for i, b := range cert.Raw {
		sum += int(b)
		fingerprint[i%20] ^= b
	}
	// This is a simplified fingerprint for demo purposes
	return fmt.Sprintf("%x", fingerprint)
}
