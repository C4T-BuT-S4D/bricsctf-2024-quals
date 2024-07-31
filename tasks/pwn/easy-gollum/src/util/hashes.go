package util

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

func calculateHash(hash hash.Hash, data string) string {
	hash.Write([]byte(data))
	result := hash.Sum(nil)

	return hex.EncodeToString(result)
}

func CalculateMD5(data string) string {
	return calculateHash(md5.New(), data)
}

func CalculateSHA1(data string) string {
	return calculateHash(sha1.New(), data)
}

func CalculateSHA256(data string) string {
	return calculateHash(sha256.New(), data)
}
