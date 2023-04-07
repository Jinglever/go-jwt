package jgjwt

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	jgfile "github.com/Jinglever/go-file"
	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
)

type Config struct {
	MaxAge time.Duration `mapstructure:"max_age"` // 会话有效时长，如：20s

	// HS256相关
	HS256SecretIsBase64 bool   `mapstructure:"hs256_secret_is_base64"`
	HS256Secret         string `mapstructure:"hs256_secret"`

	// RS256相关
	PrivateKeyPath string `mapstructure:"private_key_path"`
	PublicKeyPath  string `mapstructure:"public_key_path"`
}

type JWT struct {
	Cfg         Config
	HS256Secret []byte
	PublicKey   *rsa.PublicKey
	PrivateKey  *rsa.PrivateKey
}

type Claims struct {
	Iat     int64                  `json:"iat"`     // issued at, 签发时间
	Exp     int64                  `json:"exp"`     // expiration time, 过期时间
	Payload string                 `json:"payload"` // payload, 有效载荷
	KVs     map[string]interface{} `json:"kvs"`     // 其他自定义字段
}

const (
	KeyIat     = "iat"
	KeyExp     = "exp"
	KeyPayload = "payload"
	KeyKVs     = "kvs"
)

func NewJWT(cfg *Config) (*JWT, error) {
	j := &JWT{
		Cfg: *cfg,
	}

	// HS256的密钥
	if j.Cfg.HS256Secret != "" {
		if j.Cfg.HS256SecretIsBase64 {
			key, err := base64.StdEncoding.DecodeString(j.Cfg.HS256Secret)
			if err != nil {
				logrus.Errorf("fail to base64 decode secret: %v", err)
				return nil, err
			}
			j.HS256Secret = key
		} else {
			j.HS256Secret = []byte(j.Cfg.HS256Secret)
		}
	}

	// RS256的密钥对
	if jgfile.IsFile(cfg.PrivateKeyPath) && jgfile.IsFile(cfg.PublicKeyPath) {
		data, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			logrus.Errorf("fail to read private key file: %v", err)
			return nil, err
		}

		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(data)
		if err != nil {
			logrus.Errorf("invalid private key: %v", err)
			return nil, err
		}

		j.PrivateKey = privateKey

		data, err = os.ReadFile(cfg.PublicKeyPath)
		if err != nil {
			logrus.Errorf("fail to read public key file: %v", err)
			return nil, err
		}

		publicKey, err := jwt.ParseRSAPublicKeyFromPEM(data)
		if err != nil {
			logrus.Errorf("invalid private key: %v", err)
			return nil, err
		}

		j.PublicKey = publicKey
	}

	return j, nil
}

func (j *JWT) GenHS256Token(payload string, kvs map[string]interface{}) (string, error) {
	var token string
	var err error
	mpClaims := jwt.MapClaims{
		KeyIat:     time.Now().Unix(),
		KeyExp:     time.Now().Add(j.Cfg.MaxAge).Unix(),
		KeyPayload: payload,
	}
	for k, v := range kvs {
		mpClaims[k] = v
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, mpClaims)
	token, err = jwtToken.SignedString(j.HS256Secret)
	if err != nil {
		logrus.Errorf("fail to sign token: %v", err)
		return "", err
	}
	return token, nil
}

func (j *JWT) DecodeHS256Token(token string) (*Claims, error) {
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.HS256Secret, nil
	})
	if err != nil {
		logrus.Errorf("fail to parse token: %v", err)
		return nil, err
	}

	mapClaims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok || !jwtToken.Valid {
		logrus.Errorf("invalid token: %v", token)
		return nil, err
	}

	claims, err := mapClaims2Claims(&mapClaims)
	if err != nil {
		logrus.Errorf("fail to map claims to claims: %v", err)
		return nil, err
	}
	return claims, nil
}

func (j *JWT) DecodeTokenUnverified(token string) (*Claims, error) {
	parser := jwt.Parser{}
	var mapClaims jwt.MapClaims
	_, _, err := parser.ParseUnverified(token, &mapClaims)
	if err != nil {
		logrus.Errorf("fail to parse token: %v", err)
		return nil, err
	}

	claims, err := mapClaims2Claims(&mapClaims)
	if err != nil {
		logrus.Errorf("fail to map claims to claims: %v", err)
		return nil, err
	}
	return claims, nil
}

func (j *JWT) GenRS256Token(payload string, kvs map[string]interface{}) (string, error) {
	if j.PrivateKey == nil {
		logrus.Errorf("RS256 private key is nil")
		return "", fmt.Errorf("RS256 private key is nil")
	}
	mpClaims := jwt.MapClaims{
		KeyIat:     time.Now().Unix(),
		KeyExp:     time.Now().Add(j.Cfg.MaxAge).Unix(),
		KeyPayload: payload,
	}
	for k, v := range kvs {
		mpClaims[k] = v
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, mpClaims)
	token, err := jwtToken.SignedString(j.PrivateKey)
	if err != nil {
		logrus.Errorf("fail to sign token: %v", err)
		return "", err
	}
	return token, nil
}

func (j *JWT) DecodeRS256Token(token string) (*Claims, error) {
	if j.PublicKey == nil {
		logrus.Errorf("RS256 public key is nil")
		return nil, fmt.Errorf("RS256 public key is nil")
	}

	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.PublicKey, nil
	})
	if err != nil {
		logrus.Errorf("fail to parse token: %v", err)
		return nil, err
	}

	mapClaims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok || !jwtToken.Valid {
		logrus.Errorf("invalid token: %v", token)
		return nil, err
	}
	claims, err := mapClaims2Claims(&mapClaims)
	if err != nil {
		logrus.Errorf("fail to map claims to claims: %v", err)
		return nil, err
	}
	return claims, nil
}

func mapClaims2Claims(mp *jwt.MapClaims) (*Claims, error) {
	claims := Claims{
		KVs: make(map[string]interface{}),
	}
	var (
		ok bool
		t  float64
	)
	for k, v := range *mp {
		switch k {
		case KeyIat:
			t, ok = v.(float64)
			if !ok {
				return nil, fmt.Errorf("invalid iat")
			}
			claims.Iat = int64(t)
		case KeyExp:
			t, ok = v.(float64)
			if !ok {
				return nil, fmt.Errorf("invalid exp: %v", v)
			}
			claims.Exp = int64(t)
		case KeyPayload:
			claims.Payload, ok = v.(string)
			if !ok {
				return nil, fmt.Errorf("invalid payload")
			}
		default:
			claims.KVs[k] = v
		}
	}
	return &claims, nil
}
