package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	//"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/microlib/simple"
)

var (
	logger *simple.Logger
)

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
}

// A Signer is can create signatures that verify against a public key.
type Unsigner interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Unsign(data []byte, sig []byte) error
}

// GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		logger.Error(fmt.Sprintf(" %v\n", err))
	}
	return privkey, &privkey.PublicKey
}

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		logger.Error(fmt.Sprintf(" %v\n", err))
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

// BytesToPrivateKey bytes to private key
func BytesToPrivateKey(priv []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		logger.Info("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			logger.Error(fmt.Sprintf(" %v\n", err))
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		logger.Error(fmt.Sprintf(" %v\n", err))
	}
	return key
}

// BytesToPublicKey bytes to public key
func BytesToPublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		logger.Info("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			logger.Error(fmt.Sprintf(" %v\n", err))
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		logger.Error(fmt.Sprintf(" %v\n", err))
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		logger.Error("not ok")
	}
	return key
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		logger.Error(fmt.Sprintf(" %v\n", err))
	}
	return ciphertext
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		logger.Error(fmt.Sprintf(" %v\n", err))
	}
	return plaintext
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPublicKey(path string) (Unsigner, error) {
	data, err := ioutil.ReadFile(path)
	logger.Debug(fmt.Sprintf("Public file %v %v\n", data, err))

	if err != nil {
		return nil, err
	}
	return parsePublicKey(data)
}

// parsePublicKey parses a PEM encoded private key.
func parsePublicKey(pemBytes []byte) (Unsigner, error) {
	block, _ := pem.Decode(pemBytes)
	logger.Debug(fmt.Sprintf("Public key parse %v\n", block))
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}

	logger.Trace(fmt.Sprintf("Public rawkey %v\n", rawkey))
	return newUnsignerFromKey(rawkey)
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPrivateKey(path string) (Signer, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePrivateKey(data)
}

// parsePublicKey parses a PEM encoded private key.
func parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

func newUnsignerFromKey(k interface{}) (Unsigner, error) {
	var sshKey Unsigner
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey = &rsaPublicKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

type rsaPublicKey struct {
	*rsa.PublicKey
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

// Sign signs data with rsa-sha256
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
}

// Unsign encrypts data with rsa-sha256
func (r *rsaPublicKey) Unsign(message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	logger.Info(fmt.Sprintf("in Unsign %v : %v \n", d, sig))
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, sig)
}

// aes section
func Encrypt(key []byte, text []byte) ([]byte, error) {
	//c, err := aes.NewCipher(key)
	//if err != nil {
	//	logger.Error(fmt.Sprintf("NewCipher(%d bytes) = %s", len(key), err))
	//	panic(err)
	//}
	//out := make([]byte, len(plaintext))
	//c.Encrypt(out, []byte(plaintext))

	//return hex.EncodeToString(out)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func Decrypt(key []byte, text []byte) {
	//ciphertext, _ := hex.DecodeString(ct)
	//c, err := aes.NewCipher(key)
	//if err != nil {
	//	logger.Error(fmt.Sprintf("NewCipher(%d bytes) = %s", len(key), err))
	//	panic(err)
	//}
	//plain := make([]byte, len(ciphertext))
	//c.Decrypt(plain, ciphertext)
	//s := string(plain[:])
	//logger.Info(fmt.Sprintf("AES Decryptrd Text %s", s))
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error("AES NewCipher")
	}
	if len(text) < aes.BlockSize {
		logger.Error("AES Descrypt blocksize too short")
		//return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		logger.Error(fmt.Sprintf("AES Decrypt %v\n", err))
		//return nil, err
	}
	logger.Info(fmt.Sprintf("AES Decrypt %s\n", string(data)))
	//return data, nil
}

func main() {
	logger = &simple.Logger{Level: "info"}
	// lets test our pk keys
	pk, pub := GenerateKeyPair(2048)
	logger.Info(fmt.Sprintf("Private Key %v\n", pk))
	logger.Info(fmt.Sprintf("Public Key %v\n", pub))
	//msg := EncryptWithPublicKey([]byte("akjsjhkjs its a new worl out there hello luigi"), pub)

	//decoded := DecryptWithPrivateKey(msg, pk)

	//logger.Info(fmt.Sprintf("Decoded %s\n", string(decoded)))

	privKey := PrivateKeyToBytes(pk)
	err := ioutil.WriteFile("/tmp/keys/receiver-private.pem", privKey, 0644)
	if err != nil {
		logger.Error(fmt.Sprintf("Private key write to file %v\n", err))
	}

	pubKey := PublicKeyToBytes(pub)
	err = ioutil.WriteFile("/tmp/keys/receiver-public.pem", pubKey, 0755)
	if err != nil {
		logger.Error(fmt.Sprintf("Public key write to file %v\n", err))
	}

	// we are on the sender side

	// signing
	signer, err := loadPrivateKey("/tmp/keys/private.pem")
	if err != nil {
		logger.Error(fmt.Sprintf("Private read file %v\n", err))
	}

	key := []byte("myverystrongpasswordo32bitlength")

	signed, err := signer.Sign([]byte(key))
	if err != nil {
		logger.Error(fmt.Sprintf("Signing failed %v\n", err))
	}
	sig := base64.StdEncoding.EncodeToString(signed)
	logger.Info(fmt.Sprintf("Signature %v\n", sig))

	plainText := []byte("we now have 1234567890123456 more data Luigi Mario Zuccarelli")
	ct, err := Encrypt([]byte(key), plainText)
	logger.Info(fmt.Sprintf("AES encrypt %v\n", ct))

	data, err := ioutil.ReadFile("/tmp/keys/receiver-public.pem")
	if err != nil {
		logger.Error(fmt.Sprintf("Reading public key %v\n", err))
	}
	block, _ := pem.Decode(data)
	if block == nil {
		logger.Error("No ssh key")
	}
	pubRsa, err := x509.ParsePKIXPublicKey(block.Bytes)
	encAesKey := EncryptWithPublicKey([]byte(key), pubRsa.(*rsa.PublicKey))

	// we are on the receiver side now

	prv, err := ioutil.ReadFile("/tmp/keys/receiver-private.pem")
	if err != nil {
		logger.Error(fmt.Sprintf("Reading private key %v\n", err))
	}
	block, _ = pem.Decode(prv)
	if block == nil {
		logger.Error("No ssh key")
	}

	prvsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	aesKey := DecryptWithPrivateKey(encAesKey, prvsa)
	logger.Info(fmt.Sprintf("AES decrypt %v\n", aesKey))

	parser, err := loadPublicKey("/tmp/keys/public.pem")
	if err != nil {
		logger.Error(fmt.Sprintf("Public read file %v\n", err))
	}

	err = parser.Unsign([]byte(key), signed)
	if err != nil {
		logger.Error(fmt.Sprintf("Unsign failed %v\n", err))
	}

	Decrypt([]byte(aesKey), ct)
}
