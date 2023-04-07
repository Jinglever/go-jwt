package jgjwt_test

import (
	"testing"
	"time"

	jgjwt "github.com/Jinglever/go-jwt"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func newJWT() *jgjwt.JWT {
	j, err := jgjwt.NewJWT(&jgjwt.Config{
		MaxAge:              20 * time.Second,
		HS256SecretIsBase64: false,
		HS256Secret:         "abcdeddd",

		PrivateKeyPath: "./jwt.key", // openssl genrsa -out jwt.key 1024
		PublicKeyPath:  "./jwt.pub", // openssl rsa -pubout -in jwt.key -out jwt.pub
	})
	if err != nil {
		logrus.Fatal(err)
	}
	return j
}

func TestRS256Token(t *testing.T) {
	j := newJWT()
	token, _ := j.GenRS256Token(
		`{"a":1}`,
		nil,
	)
	t.Logf("token: %s", token)
	jwtClaim, err := j.DecodeRS256Token(token)
	assert.Nil(t, err)
	t.Logf("claim: %+v", jwtClaim)
	assert.Equal(t, jwtClaim.Payload, `{"a":1}`)
}

func TestRS256TokenUnverified(t *testing.T) {
	j := newJWT()
	token, _ := j.GenRS256Token(
		`{"a":1}`,
		nil,
	)
	t.Logf("token: %s", token)
	jwtClaim, err := j.DecodeTokenUnverified(token)
	assert.Nil(t, err)
	t.Logf("claim: %+v", jwtClaim)
	assert.Equal(t, jwtClaim.Payload, `{"a":1}`)
}

func TestHS256Token(t *testing.T) {
	j := newJWT()
	token, _ := j.GenHS256Token(
		`{"a":1}`,
		map[string]interface{}{
			"b": 2,
			"c": "cc",
		},
	)
	t.Logf("token: %s", token)
	jwtClaim, err := j.DecodeHS256Token(token)
	assert.Nil(t, err)
	t.Logf("claim: %+v", jwtClaim)
	assert.Equal(t, jwtClaim.Payload, `{"a":1}`)
	assert.Equal(t, jwtClaim.KVs["b"], float64(2))
	assert.Equal(t, jwtClaim.KVs["c"], "cc")
}

func TestHS256TokenUnverified(t *testing.T) {
	j := newJWT()
	token, _ := j.GenHS256Token(
		`{"a":1}`,
		map[string]interface{}{
			"b": 2,
			"c": "cc",
		},
	)
	t.Logf("token: %s", token)
	jwtClaim, err := j.DecodeTokenUnverified(token)
	assert.Nil(t, err)
	t.Logf("claim: %+v", jwtClaim)
	assert.Equal(t, jwtClaim.Payload, `{"a":1}`)
	assert.Equal(t, jwtClaim.KVs["b"], float64(2))
	assert.Equal(t, jwtClaim.KVs["c"], "cc")
}
