package models

import (
	"time"

	"gollum/util"
)

type Protection int

const (
	FullProtection Protection = iota

	MD5Protection
	SHA1Protection
	SHA256Protection
)

type HashFunc func(Credential) string

type Credential struct {
	created time.Time

	hashFunc HashFunc
	password string
}

func createHashFunc(protection Protection) HashFunc {
	switch protection {
	case MD5Protection:
		return func(credential Credential) string {
			return util.CalculateMD5(credential.password)
		}

	case SHA1Protection:
		return func(credential Credential) string {
			return util.CalculateSHA1(credential.password)
		}

	case SHA256Protection:
		return func(credential Credential) string {
			return util.CalculateSHA256(credential.password)
		}
	}

	return nil
}

func NewCredential(password string, protection Protection) Credential {
	return Credential{
		created: time.Now(),

		password: password,
		hashFunc: createHashFunc(protection),
	}
}

func (credential Credential) String() string {
	var hash string

	if credential.hashFunc != nil {
		hash = credential.hashFunc(credential)
		hash = hash[:3] + "***" + hash[len(hash)-3:]
	} else {
		hash = "***"
	}

	return hash
}

func (credential Credential) IsSafe() bool {
	bound := 30 * 24 * time.Hour // 1 month

	return time.Since(credential.created) < bound
}

func (credential Credential) Validate(password string) bool {
	return credential.password == password
}
