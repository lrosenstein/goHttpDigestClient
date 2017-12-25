package goHttpDigestClient

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
)

// hash any string to md5 hex string
func toMd5(s string) string {
	sByte := []byte(s)
	return fmt.Sprintf("%x", md5.Sum(sByte))
}

//In RFC 2617
//
//HA1 is equal to MD5("username:realm:password")
func computeHa1(username, realm, password string) string {
	return toMd5(fmt.Sprintf("%s:%s:%s", username, realm, password))
}

func computeHa2(qop, method, digestUri, entity string) string {
	switch qop {
	case "auth-int":
		return toMd5(fmt.Sprintf("%s:%s:%s", method, digestUri, toMd5(entity)))
	default:
		return toMd5(fmt.Sprintf("%s:%s", method, digestUri))
	}
}

func computeResponse(qop, realm, nonce, nonceCount, clientNonce, method, uri, entity, username, password string) (response, cNonce, nc string) {
	if clientNonce == "" {
		b := make([]byte, 32)
		rand.Read(b)
		clientNonce = fmt.Sprintf("%x", md5.Sum(b))
	}
	if nonceCount == "" {
		nonceCount = "00000001"
	}
	ha1 := computeHa1(username, realm, password)
	ha2 := computeHa2(qop, method, uri, entity)
	switch qop {
	case "auth", "auth-int":
		return toMd5(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, nonce, nonceCount, clientNonce, qop, ha2)), clientNonce, nonceCount
	default:
		return toMd5(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2)), clientNonce, nonceCount
	}
}
