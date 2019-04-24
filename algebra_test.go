package phcc

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"github.com/joekir/phcc/elgamal"
	"math/big"
	"testing"
)

func TestMultiplyDecrypt(t *testing.T) {
	ledgerKeys, ledger := NewLedger()

	var int1 int64 = 4
	m1 := big.NewInt(int1).Bytes()
	var int2 int64 = 2
	m2 := big.NewInt(int2).Bytes()

	cipher1, err := ledger.mulKeyPub.Encrypt(rand.Reader, m1)
	if err != nil {
		t.Fatalf("error encrypting: %s", err)
	}

	cipher2, err := ledger.mulKeyPub.Encrypt(rand.Reader, m2)
	if err != nil {
		t.Fatalf("error encrypting: %s", err)
	}

	ledger.Multiply(cipher1, cipher2)

	buffer := bytes.NewBuffer(ledger.ciphertext)
	dec := gob.NewDecoder(buffer)

	c := &elgamal.Ciphertext{}
	err = dec.Decode(c)
	if err != nil {
		t.Fatalf("error decoding: %s", err)
	}
	t.Logf("decoded 'c' is: %#v", c)

	plaintext, err := ledgerKeys.mulKeyPriv.Decrypt(c)
	if err != nil {
		t.Fatalf("error decrypting: %s", err)
	}
	t.Logf("decrypted 'plaintext' is: %#v", plaintext)

	expected := new(big.Int).Mod(big.NewInt(int1*int2), ledger.mulKeyPub.P).Bytes()

	if !bytes.Equal(plaintext, expected) {
		t.Fatalf("decryption failed, got: %#v, want: %#v", plaintext, expected)
	}
}

func TestAddDecrypt(t *testing.T) {
	ledgerKeys, ledger := NewLedger()

	var int1 int64 = 4
	m1 := big.NewInt(int1)
	var int2 int64 = 2
	m2 := big.NewInt(int2)

	cipher1, err := ledger.addKeyPub.Encrypt(rand.Reader, m1)
	if err != nil {
		t.Fatalf("error encrypting: %s", err)
	}

	cipher2, err := ledger.addKeyPub.Encrypt(rand.Reader, m2)
	if err != nil {
		t.Fatalf("error encrypting: %s", err)
	}

	ledger.Add(cipher1, cipher2)

	buffer := bytes.NewBuffer(ledger.ciphertext)
	dec := gob.NewDecoder(buffer)

	c := new(big.Int)
	err = dec.Decode(c)
	if err != nil {
		t.Fatalf("error decoding: %s", err)
	}
	t.Logf("decoded 'c' is: %#v", c)

	plaintext := ledgerKeys.addKeyPriv.Decrypt(c)
	if err != nil {
		t.Fatalf("error decrypting: %s", err)
	}
	t.Logf("decrypted 'plaintext' is: %#v", plaintext)

	expected := new(big.Int).Add(m1, m2)

	if expected.Cmp(plaintext) != 0 {
		t.Fatalf("decryption failed, got: %#v, want: %#v", plaintext, expected)
	}
}
