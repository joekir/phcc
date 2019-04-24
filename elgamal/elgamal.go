package elgamal

/* Golang's https://github.com/golang/crypto/blob/master/openpgp/elgamal/elgamal.go
was not suitable for usage by phcc without some tweaks, the foundations of this file
come from there.
*/

import (
	"crypto/rand"
	"io"
	"math/big"
)

// PublicKey represents an ElGamal public key.
type PublicKey struct {
	G, P, Y *big.Int
}

// PrivateKey represents an ElGamal private key.
type PrivateKey struct {
	PublicKey
	X *big.Int
}

type Ciphertext struct {
	C1 *big.Int
	C2 *big.Int
}

// Encrypt encrypts the given message to the given public key. The result is a
// pair of integers. Errors can result from reading random, or because msg is
// too large to be encrypted to the public key.
func (pub *PublicKey) Encrypt(random io.Reader, msg []byte) (c *Ciphertext, err error) {
	m := new(big.Int).SetBytes(msg)

	k, err := rand.Int(random, pub.P)
	if err != nil {
		return
	}

	c = &Ciphertext{}

	c.C1 = new(big.Int).Exp(pub.G, k, pub.P)
	s := new(big.Int).Exp(pub.Y, k, pub.P)
	c.C2 = s.Mul(s, m)
	c.C2.Mod(c.C2, pub.P)

	return c, nil
}

// Decrypt takes two integers, resulting from an ElGamal encryption, and
// returns the plaintext of the message. An error can result only if the
// ciphertext is invalid. Users should keep in mind that this is a padding
// oracle and thus, if exposed to an adaptive chosen ciphertext attack, can
// be used to break the cryptosystem.  See ``Chosen Ciphertext Attacks
// Against Protocols Based on the RSA Encryption Standard PKCS #1'', Daniel
// Bleichenbacher, Advances in Cryptology (Crypto '98),
func (priv *PrivateKey) Decrypt(c *Ciphertext) (msg []byte, err error) {
	s := new(big.Int).Exp(c.C1, priv.X, priv.P)
	s.ModInverse(s, priv.P)
	s.Mul(s, c.C2)
	s.Mod(s, priv.P)
	return s.Bytes(), nil
}

// nonZeroRandomBytes fills the given slice with non-zero random octets.
func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
	_, err = io.ReadFull(rand, s)
	if err != nil {
		return
	}

	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = io.ReadFull(rand, s[i:i+1])
			if err != nil {
				return
			}
		}
	}

	return
}

func HexToBigInt(hex string) *big.Int {
	n, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("failed to parse hex number")
	}
	return n
}
