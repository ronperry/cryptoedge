package lioness

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_Construct(t *testing.T) {
	l, err := Construct(aes.NewCipher, sha256.New, 32, nil, ModeZero)
	if err != nil {
		t.Fatalf("New returned error: %s", err)
	}
	_ = l
}

func Test_Explode(t *testing.T) {
	l, err := Construct(aes.NewCipher, sha256.New, 32, nil, ModeZero)
	if err != nil {
		t.Fatalf("New returned error: %s", err)
	}
	l.ExplodeKey([]byte("Test Key"))
}

func Test_ZeroEncrypt(t *testing.T) {
	key := []byte("test key")
	data := []byte("really important test data that is encrypted and decrypted yeeha")
	l, err := Construct(aes.NewCipher, sha256.New, 32, key, ModeZero)
	if err != nil {
		t.Fatalf("New returned error: %s", err)
	}
	e, err := l.Encrypt(data)
	if err != nil {
		t.Fatalf("Encrypt returned error: %s", err)
	}
	if bytes.Equal(data, e) {
		t.Error("No operation")
	}
	d, err := l.Decrypt(e)
	if err != nil {
		t.Fatalf("Decrypt returned error: %s", err)
	}
	if !bytes.Equal(data, d) {
		t.Error("En-De-Crypt failed")
	}
}

func Test_IVEncrypt(t *testing.T) {
	key := []byte("test key")
	data := []byte("really important test data that is encrypted and decrypted yeeha")
	l, err := Construct(aes.NewCipher, sha256.New, 32, key, ModeIV)
	if err != nil {
		t.Fatalf("New returned error: %s", err)
	}
	e, err := l.Encrypt(data)
	if err != nil {
		t.Fatalf("Encrypt returned error: %s", err)
	}
	if bytes.Equal(data, e) {
		t.Error("No operation")
	}
	d, err := l.Decrypt(e)
	if err != nil {
		t.Fatalf("Decrypt returned error: %s", err)
	}
	if !bytes.Equal(data, d) {
		t.Error("En-De-Crypt failed")
	}
}

func Test_ZeroEncryptReverse(t *testing.T) {
	key := []byte("test key")
	data := []byte("really important test data that is encrypted and decrypted yeeha")
	l, err := Construct(aes.NewCipher, sha256.New, 32, key, ModeZero)
	if err != nil {
		t.Fatalf("New returned error: %s", err)
	}
	e, err := l.Decrypt(data)
	if err != nil {
		t.Fatalf("Encrypt returned error: %s", err)
	}
	if bytes.Equal(data, e) {
		t.Error("No operation")
	}
	d, err := l.Encrypt(e)
	if err != nil {
		t.Fatalf("Decrypt returned error: %s", err)
	}
	if !bytes.Equal(data, d) {
		t.Error("En-De-Crypt failed")
	}
}

func Test_IVEncryptReverse(t *testing.T) {
	key := []byte("test key")
	data := []byte("really important test data that is encrypted and decrypted yeeha")
	l, err := Construct(aes.NewCipher, sha256.New, 32, key, ModeIV)
	if err != nil {
		t.Fatalf("New returned error: %s", err)
	}
	e, err := l.Decrypt(data)
	if err != nil {
		t.Fatalf("Encrypt returned error: %s", err)
	}
	if bytes.Equal(data, e) {
		t.Error("No operation")
	}
	d, err := l.Encrypt(e)
	if err != nil {
		t.Fatalf("Decrypt returned error: %s", err)
	}
	if !bytes.Equal(data, d) {
		t.Error("En-De-Crypt failed")
	}
}

func Test_Xor(t *testing.T) {
	l := new(Lioness)
	l.keylen = 100
	data1 := []byte("1234567890123456")
	data2 := []byte("133456789012345")
	x := l.xor(data1, data2)
	y := l.xor(x, data1)
	if bytes.Equal(data1, x) {
		t.Error("Xor no operation")
	}
	if !bytes.Equal(data2, y) {
		t.Error("Xor failed")
	}
}

func Test_Rop(t *testing.T) {
	key := []byte("trivial key of some length 12345")
	plaintext := []byte("input data")
	l, err := Construct(aes.NewCipher, sha256.New, 32, nil, ModeZero)
	if err != nil {
		t.Fatalf("New returned error: %s", err)
	}
	ciphertext, err := l.rop(make([]byte, aes.BlockSize), key, plaintext)
	if err != nil {
		t.Fatalf("CTREnc failed: %s", err)
	}
	plaintext2, err := l.rop(make([]byte, aes.BlockSize), key, ciphertext)
	if err != nil {
		t.Fatalf("CTREnc failed: %s", err)
	}
	if hex.EncodeToString(ciphertext) != "798eff3651a457968fc7" {
		t.Error("Encryption produces wrong result")
	}
	if !bytes.Equal(plaintext, plaintext2) {
		t.Error("Plaintexts do not match")
	}
}

func Test_RopHMAC(t *testing.T) {
	key := []byte("trivial key")
	plaintext := []byte("input data")
	l, err := Construct(aes.NewCipher, sha256.New, 32, nil, ModeZero)
	if err != nil {
		t.Fatalf("New returned error: %s", err)
	}
	hm := l.ropHMAC(key, plaintext)
	if hex.EncodeToString(hm) != "53b7726810eea80d5f8746d3bdf5fe994a39d880dfe77fe45a2f5a4ff4e86c9c" {
		t.Error("HMAC wrong")
	}
}

func ExampleNew() {
	// Define encryption key and data to be encrypted
	key := []byte("This is the secret encryption key")
	// Data must be keylen +1 bytes or longer
	data := []byte("Some data to be encrypted. It must be long enough to cover at least one key length.")

	// Create new lioness with default algorithms, mode and automatic key expansion.
	l, err := New(key)

	// Errors returned if keylength and algorithm choice conflict.
	if err != nil {
		fmt.Printf("Error occured in New: %s", err)
	}

	// Encrypt data. Error is returned if data is not long enough
	encrypted, err := l.Encrypt(data)
	if err != nil {
		fmt.Printf("Error occured in Encrypt: %s", err)
	}

	// Decrypt data.
	decrypted, err := l.Decrypt(encrypted)
	if err != nil {
		fmt.Printf("Error occured in Decrypt: %s", err)
	}
	fmt.Printf("Data after decryption: %s\n", decrypted)

	// Output: Data after decryption: Some data to be encrypted. It must be long enough to cover at least one key length.
}

func ExampleConstruct() {
	// Define encryption key and data to be encrypted
	key := []byte("This is the secret encryption key")
	// Data must be keylen +1 bytes or longer
	data := []byte("Some data to be encrypted. It must be long enough to cover at least one key length.")

	// Create new lioness. aes will be used for stream encryption (in CTR mode), sha256 is our hmac hash.
	// The keylen is set to 32 (AES256) and we are using ModeZero (IV is all zero). The key given will
	// be expanded automatically to fill the subkeys k1-k4.
	l, err := Construct(aes.NewCipher, sha256.New, 32, key, ModeZero)

	// Errors returned if keylength and algorithm choice conflict.
	if err != nil {
		fmt.Printf("Error occured in New: %s", err)
	}

	// Encrypt data. Error is returned if data is not long enough
	encrypted, err := l.Encrypt(data)
	if err != nil {
		fmt.Printf("Error occured in Encrypt: %s", err)
	}

	// Decrypt data.
	decrypted, err := l.Decrypt(encrypted)
	if err != nil {
		fmt.Printf("Error occured in Decrypt: %s", err)
	}
	fmt.Printf("Data after decryption: %s\n", decrypted)

	// Output: Data after decryption: Some data to be encrypted. It must be long enough to cover at least one key length.
}

func ExampleLioness_Setkeys() {
	// Define four (independent) encryption keys. Keys must have keylen length.
	key1 := []byte("11111178901234567890123456781111")
	key2 := []byte("22222278901234567890123456782222")
	key3 := []byte("33333378901234567890123456783333")
	key4 := []byte("44444478901234567890123456784444")

	// Data must be keylen +1 bytes or longer
	data := []byte("Some data to be encrypted. It must be long enough to cover at least one key length.")

	// Create new lioness. aes will be used for stream encryption (in CTR mode), sha256 is our hmac hash.
	// The keylen is set to 32 (AES256) and we are using ModeIV (L is used as IV). Key is nil, we will use
	// SetKeys instead
	l, err := Construct(aes.NewCipher, sha256.New, 32, nil, ModeIV)
	if err != nil {
		fmt.Printf("Error occured in New: %s", err)
	}

	// Set the four keys required for the operation. An error will occur if the key lengths != keylen
	err = l.Setkeys(key1, key2, key3, key4)
	if err != nil {
		fmt.Printf("Error occured in EetKey: %s", err)
	}

	// Encrypt data. Error is returned if data is not long enough
	encrypted, err := l.Encrypt(data)
	if err != nil {
		fmt.Printf("Error occured in Encrypt: %s", err)
	}

	// Decrypt data.
	decrypted, err := l.Decrypt(encrypted)
	if err != nil {
		fmt.Printf("Error occured in Decrypt: %s", err)
	}
	fmt.Printf("Data after setkeys and decryption: %s\n", decrypted)

	// Output: Data after setkeys and decryption: Some data to be encrypted. It must be long enough to cover at least one key length.
}
