package config

type Config struct {
	KeyKeeper KeyKeeperConfig `json:"key_keeper"`
	System    SystemConfig    `json:"system"`
}

type KeyKeeperConfig struct {
	Mode              string `json:"mode"`                // debug or normal
	TrustedCAPath     string `json:"ca_path"`             // Trusted CA path
	UntrustedCAPath   string `json:"untrusted_ca_path"`   // Untrusted CA path
	CertStoreHost     string `json:"cert_store_host"`     // Cert store host
	CertStorePort     int    `json:"cert_store_port"`     // Cert store port
	NoCache           bool   `json:"no_cache"`            // Disable cache
	HashExpireSeconds int    `json:"hash_expire_seconds"` // Cache expiration time
	HashSlotSize      int    `json:"hash_slot_size"`      // Cache slot size
	CertExpireTime    int    `json:"cert_expire_time"`    // Certificate expiration time (hours)
	EnableHealthCheck bool   `json:"enable_health_check"` // Enable health check
}

type SystemConfig struct {
	NrWorkerThreads int `json:"nr_worker_threads"` // Number of worker threads
}

func DefaultConfig() *Config {
	return &Config{
		System: SystemConfig{
			NrWorkerThreads: 8,
		},
		KeyKeeper: KeyKeeperConfig{
			Mode:              "debug",
			TrustedCAPath:     "./certs/trusted-ca.pem",
			UntrustedCAPath:   "./certs/untrusted-ca.pem",
			CertStoreHost:     "localhost",
			CertStorePort:     8080,
			NoCache:           false,
			HashExpireSeconds: 300, // 5 minutes
			HashSlotSize:      131072,
			CertExpireTime:    24, // hours
			EnableHealthCheck: true,
		},
	}
}
