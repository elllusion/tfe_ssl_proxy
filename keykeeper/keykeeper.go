package keykeeper

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"tfe_ssl_proxy/certutils"
	"tfe_ssl_proxy/config"
	"time"
)

// KeyKeeper manages certificate generation and caching
type KeyKeeper struct {
	config          config.KeyKeeperConfig
	trustedCA       *x509.Certificate
	trustedKey      *rsa.PrivateKey
	untrustedCA     *x509.Certificate
	untrustedKey    *rsa.PrivateKey
	cache           map[string]*certutils.CachedKeyRing
	cacheMutex      sync.RWMutex
	httpClient      *http.Client
	isCertStoreDown bool
	stats           KeyKeeperStats
	statsMutex      sync.RWMutex
}

// KeyRing represents a certificate-key pair with certificate chain
type KeyRing struct {
	Key   *rsa.PrivateKey
	Cert  *x509.Certificate
	Chain []*x509.Certificate
}

// KeyKeeperStats holds statistics about key keeper operations
type KeyKeeperStats struct {
	AskTimes  int64 `json:"ask_times"`
	NewIssue  int64 `json:"new_issue"`
	CachedNum int64 `json:"cached_num"`
}

// NewKeyKeeper creates a new KeyKeeper instance
func NewKeyKeeper(cfg config.KeyKeeperConfig) (*KeyKeeper, error) {
	keeper := &KeyKeeper{
		config:     cfg,
		cache:      make(map[string]*certutils.CachedKeyRing),
		httpClient: &http.Client{Timeout: time.Second * 10},
	}

	if cfg.Mode == "debug" {
		if err := keeper.loadLocalCAs(); err != nil {
			return nil, fmt.Errorf("failed to load local CAs: %v", err)
		}
	}

	return keeper, nil
}

// loadLocalCAs loads trusted and untrusted CA certificates in debug mode
func (k *KeyKeeper) loadLocalCAs() error {
	// Load trusted CA
	trustedCertPEM, err := ioutil.ReadFile(k.config.TrustedCAPath)
	if err != nil {
		// Generate if not found
		cert, key, err := certutils.CreateCACertificate()
		if err != nil {
			return fmt.Errorf("failed to create trusted CA: %v", err)
		}
		k.trustedCA = cert
		k.trustedKey = key
	} else {
		k.trustedCA, err = certutils.LoadCertificate(trustedCertPEM)
		if err != nil {
			return fmt.Errorf("failed to parse trusted CA: %v", err)
		}

		trustedKeyPEM, err := ioutil.ReadFile(k.config.TrustedCAPath)
		if err != nil {
			k.trustedKey, err = certutils.GenerateRSAPrivateKey()
			if err != nil {
				return fmt.Errorf("failed to generate trusted key: %v", err)
			}
		} else {
			k.trustedKey, err = certutils.LoadPrivateKey(trustedKeyPEM)
			if err != nil {
				k.trustedKey, err = certutils.GenerateRSAPrivateKey()
				if err != nil {
					return fmt.Errorf("failed to generate trusted key: %v", err)
				}
			}
		}
	}

	// Load untrusted CA
	untrustedCertPEM, err := ioutil.ReadFile(k.config.UntrustedCAPath)
	if err != nil {
		// Generate if not found
		cert, key, err := certutils.CreateCACertificate()
		if err != nil {
			return fmt.Errorf("failed to create untrusted CA: %v", err)
		}
		k.untrustedCA = cert
		k.untrustedKey = key
	} else {
		k.untrustedCA, err = certutils.LoadCertificate(untrustedCertPEM)
		if err != nil {
			return fmt.Errorf("failed to parse untrusted CA: %v", err)
		}

		untrustedKeyPEM, err := ioutil.ReadFile(k.config.UntrustedCAPath)
		if err != nil {
			k.untrustedKey, err = certutils.GenerateRSAPrivateKey()
			if err != nil {
				return fmt.Errorf("failed to generate untrusted key: %v", err)
			}
		} else {
			k.untrustedKey, err = certutils.LoadPrivateKey(untrustedKeyPEM)
			if err != nil {
				k.untrustedKey, err = certutils.GenerateRSAPrivateKey()
				if err != nil {
					return fmt.Errorf("failed to generate untrusted key: %v", err)
				}
			}
		}
	}

	return nil
}

// GetKeyRing retrieves or generates a certificate-key pair for the given domain
func (k *KeyKeeper) GetKeyRing(sni string, keyringUUID string, isValid bool, origCert *x509.Certificate) (*KeyRing, error) {
	// Generate cache key
	cacheKey := fmt.Sprintf("%s:%s:%t", keyringUUID, sni, isValid)

	// Update stats
	k.statsMutex.Lock()
	k.stats.AskTimes++
	k.statsMutex.Unlock()

	// Check cache first
	if !k.config.NoCache {
		if keyRing := k.getFromCache(cacheKey); keyRing != nil {
			return keyRing, nil
		}
	}

	var keyRing *KeyRing
	var err error

	// Generate based on mode
	switch k.config.Mode {
	case "debug":
		keyRing, err = k.generateLocalKeyRing(isValid, origCert)
	case "normal":
		keyRing, err = k.requestFromCertStore(sni, keyringUUID, isValid, origCert)
	default:
		return nil, fmt.Errorf("unknown mode: %s", k.config.Mode)
	}

	if err != nil {
		return nil, err
	}

	// Cache the result
	if !k.config.NoCache && keyRing != nil {
		k.cacheKeyRing(cacheKey, keyRing)
	}

	return keyRing, nil
}

// generateLocalKeyRing generates a certificate-key pair locally
func (k *KeyKeeper) generateLocalKeyRing(isValid bool, origCert *x509.Certificate) (*KeyRing, error) {
	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey

	if isValid {
		caCert = k.trustedCA
		caKey = k.trustedKey
	} else {
		caCert = k.untrustedCA
		caKey = k.untrustedKey
	}

	certRing, err := certutils.ForgeCertificate(caCert, caKey, origCert, k.config.CertExpireTime)
	if err != nil {
		return nil, fmt.Errorf("failed to forge certificate: %v", err)
	}

	keyRing := &KeyRing{
		Key:   certRing.Key,
		Cert:  certRing.Cert,
		Chain: certRing.Chain,
	}

	// Update stats
	k.statsMutex.Lock()
	k.stats.NewIssue++
	k.statsMutex.Unlock()

	return keyRing, nil
}

// requestFromCertStore requests certificate from a remote certificate store
func (k *KeyKeeper) requestFromCertStore(sni string, keyringUUID string, isValid bool, origCert *x509.Certificate) (*KeyRing, error) {
	// Check if cert store is down
	if k.isCertStoreDown {
		return k.generateLocalKeyRing(isValid, origCert)
	}

	// In a real implementation, this would make an HTTP request to the cert store
	url := fmt.Sprintf("http://%s:%d/ca?keyring_id=%s&sni=%s&is_valid=%d",
		k.config.CertStoreHost, k.config.CertStorePort, keyringUUID, sni, boolToInt(isValid))

	// Make HTTP POST request
	resp, err := k.httpClient.Post(url, "application/x-pem-file", nil)
	if err != nil {
		// Fallback to local generation if cert store is unreachable
		k.isCertStoreDown = true
		return k.generateLocalKeyRing(isValid, origCert)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Fallback to local generation if cert store returns error
		return k.generateLocalKeyRing(isValid, origCert)
	}

	// Parse response
	certRing, err := k.parseCertStoreResponse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert store response: %v", err)
	}

	keyRing := &KeyRing{
		Key:   certRing.Key,
		Cert:  certRing.Cert,
		Chain: certRing.Chain,
	}

	// Update stats
	k.statsMutex.Lock()
	k.stats.NewIssue++
	k.statsMutex.Unlock()

	return keyRing, nil
}

// parseCertStoreResponse parses the response from certificate store
func (k *KeyKeeper) parseCertStoreResponse(body interface{}) (*certutils.KeyRing, error) {
	// This is a simplified implementation
	// In reality, you would parse the actual response from the cert store
	return nil, fmt.Errorf("not implemented")
}

// getFromCache retrieves a KeyRing from cache if it exists and hasn't expired
func (k *KeyKeeper) getFromCache(key string) *KeyRing {
	k.cacheMutex.RLock()
	defer k.cacheMutex.RUnlock()

	if item, exists := k.cache[key]; exists {
		if time.Now().Before(item.ExpireTime) {
			k.statsMutex.Lock()
			k.stats.CachedNum++
			k.statsMutex.Unlock()

			certRing := item.KeyRing
			keyRing := &KeyRing{
				Key:   certRing.Key,
				Cert:  certRing.Cert,
				Chain: certRing.Chain,
			}
			return keyRing
		}
		// Expired, remove from cache
		delete(k.cache, key)
	}

	return nil
}

// cacheKeyRing stores a KeyRing in cache with expiration
func (k *KeyKeeper) cacheKeyRing(key string, keyRing *KeyRing) {
	k.cacheMutex.Lock()
	defer k.cacheMutex.Unlock()

	now := time.Now()
	expireTime := now.Add(time.Duration(k.config.HashExpireSeconds) * time.Second)

	certRing := &certutils.KeyRing{
		Key:   keyRing.Key,
		Cert:  keyRing.Cert,
		Chain: keyRing.Chain,
	}

	k.cache[key] = &certutils.CachedKeyRing{
		KeyRing:    certRing,
		UpdateTime: now,
		ExpireTime: expireTime,
	}
}

// KeyRingToJSON converts a KeyRing to JSON format for transmission
func KeyRingToJSON(keyRing *KeyRing) ([]byte, error) {
	response := map[string]interface{}{
		"CERTIFICATE":       string(certutils.CertificateToPEM(keyRing.Cert)),
		"PRIVATE_KEY":       string(certutils.PrivateKeyToPEM(keyRing.Key)),
		"CERTIFICATE_CHAIN": make([]string, len(keyRing.Chain)),
	}

	chain := make([]string, len(keyRing.Chain))
	for i, cert := range keyRing.Chain {
		chain[i] = string(certutils.CertificateToPEM(cert))
	}
	response["CERTIFICATE_CHAIN"] = chain

	return json.Marshal(response)
}

// GetStats returns key keeper statistics
func (k *KeyKeeper) GetStats() KeyKeeperStats {
	k.statsMutex.RLock()
	defer k.statsMutex.RUnlock()
	return k.stats
}

// Helper function to convert boolean to integer
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
