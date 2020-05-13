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
	"encoding/hex"
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
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error("AES NewCipher")
	}
	if len(text) < aes.BlockSize {
		logger.Error("AES Descrypt blocksize too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		logger.Error(fmt.Sprintf("AES Decrypt %v\n", err))
	}
	logger.Info(fmt.Sprintf("AES Decrypt %s\n", string(data)))
}

func main() {
	logger = &simple.Logger{Level: "info"}

	//pk, pub := GenerateKeyPair(2048)
	//logger.Info(fmt.Sprintf("Private Key %v\n", pk))
	//logger.Info(fmt.Sprintf("Public Key %v\n", pub))
	//msg := EncryptWithPublicKey([]byte("akjsjhkjs its a new worl out there hello luigi"), pub)
	//decoded := DecryptWithPrivateKey(msg, pk)
	//logger.Info(fmt.Sprintf("Decoded %s\n", string(decoded)))

	//privKey := PrivateKeyToBytes(pk)
	//err := ioutil.WriteFile("/tmp/keys/receiver-private.pem", privKey, 0644)
	//if err != nil {
	//	logger.Error(fmt.Sprintf("Private key write to file %v\n", err))
	//}

	//pubKey := PublicKeyToBytes(pub)
	//err = ioutil.WriteFile("/tmp/keys/receiver-public.pem", pubKey, 0755)
	//if err != nil {
	//	logger.Error(fmt.Sprintf("Public key write to file %v\n", err))
	//}

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
	logger.Info(fmt.Sprintf("Signature (ObjectA) %s\n", sig))

	plainText := []byte("we now have 1234567890123456 more data Luigi Mario Zuccarelli")
	ct, err := Encrypt([]byte(key), plainText)
	logger.Info(fmt.Sprintf("AES encrypt (ObjectB) %s\n", hex.EncodeToString(ct)))

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
	logger.Info(fmt.Sprintf("Encrypt AES key (ObjectC) %s\n", hex.EncodeToString(encAesKey)))

	// curl -d'{"metainfo":"Initial Payment","objectA":"YuKUVFsEGGJjmm+TxDaTMpNfntWt5UhnhviYwCsRD6C3W8QVhAeznE+5EDeOK8/r3Lpjy9piY9T1b59si3gor5KYWHMCumK3ChjwPoq/T9Dl1X73YB1gzHWTy+p70av74+E6hSDT7Ua9n3Lw2cTBZSM8s8M8rSAtaCJHjM3isHrltVN1eUmUi5sH5xCKEN8WR4631yrlz6paOShuExYxXJj4CEUyhTmYGEky6zTMMkJM5XcEQ5dMx96zQeJHA4Qt02nFuk2sxNqdWC0ySuZ3ykQv+Z/gRou452wIXHk7irE4MB35EXYs+TBj0hUF8v4G+j++vFQ4uv03+q/d8j5gvA==","objectB":"ed4fb7deb645ebe2cff98a52a67522b24c07cf58c3ee6306924e30eba165c0fc4b558d0c7cafe85889247a07e3030670bcad418dd969256c8ce1efd610a40ef1e528bb8ee09e32f900caa60eaf7ab4732619cd5c3f0d2d98ef73d47a763d09826179cc1f","objectC":"4d616c1e1b09d2afb3203b89a9dcc854983a7001f99ea1582df0cf5049eb071a4d534e1b6de68dec7dd8b325dc69139d782568d9535a83418b6d3c2522b238bcc416db2e08e4a7f6e61e449cc3896a10befed5b19366457983fe5173ecf98f45abbce46e9e362e271b81cab995941d9c809a6bdc61ed627c8f1805c3ae1c7251177a4c73905bafe326bf6b58ede21d6f110c451d0d5774af5c286f0dc092ab1e5501ded59cc166879b1a41d279cf52137936bd2a0536a8c541f9a37893ee70acf629db945d98720765b77440364b025f4428ab7a66171c20e98d0279af889cf6e9bfb558b990ee106f5be35bfe3829fedb7b10a01ce1262fcee518f03fc38382"}' http://127.0.0.1:9000/api/v1/blockchain

}
