package certutil

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ParseRSA private key from a PEM formatted block.
func ParseRSA(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ParseECDSA private key from a PEM formatted block.
func ParseECDSA(s string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// ParseX509 certificate from a PEM formatted block.
func ParseX509(s string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParsePublicKey RSA and ECDSA public keys from a PEM formatted block.
func ParsePublicKey(s string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("data does not contain any valid public keys")
	}

	rawKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawKey = cert.PublicKey
	}

	switch key := rawKey.(type) {
	case *rsa.PublicKey:
		return key, nil
	case *ecdsa.PublicKey:
		return key, nil
	case ed25519.PublicKey:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// ComparePublicKeys reports whether 2 public keys are equal, error if not comparable.
func ComparePublicKeys(key1, key2 crypto.PublicKey) (bool, error) {
	switch key1 := key1.(type) {
	case *rsa.PublicKey:
		key2, ok := key2.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("key types do not match: %T and %T", key1, key2)
		}
		cmp := key1.N.Cmp(key2.N) != 0 || key1.E != key2.E
		return cmp, nil

	case *ecdsa.PublicKey:
		key2, ok := key2.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("key types do not match: %T and %T", key1, key2)
		}
		if key1.X.Cmp(key2.X) != 0 || key1.Y.Cmp(key2.Y) != 0 {
			return false, nil
		}

		par1 := key1.Params()
		par2 := key2.Params()
		cmp := par1.P.Cmp(par2.P) != 0 ||
			par1.N.Cmp(par2.N) != 0 ||
			par1.B.Cmp(par2.B) != 0 ||
			par1.Gx.Cmp(par2.Gx) != 0 ||
			par1.Gy.Cmp(par2.Gy) != 0 ||
			par1.BitSize != par2.BitSize
		return cmp, nil

	case ed25519.PublicKey:
		key2, ok := key2.(ed25519.PublicKey)
		if !ok {
			return false, fmt.Errorf("key types do not match: %T and %T", key1, key2)
		}
		return key1.Equal(key2), nil

	default:
		return false, fmt.Errorf("unsupported key type: %T", key1)
	}
}

// KeySize returns the key size in bits for a given crypto.PrivateKey or crypto.PublicKey.
// Returns -1 it key type is unsupported.
func KeySize(key interface{}) int {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return key.Size() * 8
	case *rsa.PublicKey:
		return key.Size() * 8

	case *ecdsa.PrivateKey:
		return key.Params().BitSize
	case *ecdsa.PublicKey:
		return key.Params().BitSize

	case ed25519.PrivateKey:
		return len(key) * 8
	case ed25519.PublicKey:
		return len(key) * 8

	case dsa.PrivateKey:
		return key.Y.BitLen()
	case dsa.PublicKey:
		return key.Y.BitLen()

	default:
		return -1
	}
}
