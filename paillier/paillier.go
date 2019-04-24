package paillier

/*
	The API of https://github.com/didiercrunch/paillier did not work for the usecase
	It has been taken as the foundation and modified to suit the purpose here
*/

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

type PublicKey struct {
	N *big.Int
}

type PrivateKey struct {
	PublicKey
	Lambda *big.Int
}

func ZERO() *big.Int {
	return big.NewInt(0)
}

func ONE() *big.Int {
	return big.NewInt(1)
}

func NEG_ONE() *big.Int {
	return big.NewInt(-1)
}

// CreatePrivateKey generates a Paillier private key accepting two large prime
// numbers of equal length or other such that gcd(pq, (p-1)(q-1)) = 1.
//
// Algorithm is based on approach described in [KL 08], construction 11.32,
// page 414 which is compatible with one described in [DJN 10], section 3.2
// except that instead of generating Lambda private key component from LCM
// of p and q we use Euler's totient function as suggested in [KL 08].
//
//     [KL 08]:  Jonathan Katz, Yehuda Lindell, (2008)
//               Introduction to Modern Cryptography: Principles and Protocols,
//               Chapman & Hall/CRC
//
//     [DJN 10]: Ivan Damgard, Mads Jurik, Jesper Buus Nielsen, (2010)
//               A Generalization of Paillier’s Public-Key System
//               with Applications to Electronic Voting
//               Aarhus University, Dept. of Computer Science, BRICS
func CreatePrivateKey(p, q *big.Int) *PrivateKey {
	// TODO Primality checks
	// https://golang.org/src/math/big/prime.go

	n := new(big.Int).Mul(p, q)
	lambda := computePhi(p, q)

	return &PrivateKey{
		PublicKey: PublicKey{
			N: n,
		},
		Lambda: lambda,
	}
}

func (pub *PublicKey) getNSquare() *big.Int {
	return new(big.Int).Mul(pub.N, pub.N)
}

// EncryptWithR encrypts a plaintext into a cypher one with random `r` specified
// in the argument. The plain text must be smaller that N and bigger than or
// equal zero. `r` is the randomness used to encrypt the plaintext. `r` must be
// a random element from a multiplicative group of integers modulo N.
//
// If you don't need to use the specific `r`, you should use the `Encrypt`
// function instead.
//
// m - plaintext to encrypt
// r - randomness used for encryption
// E(m, r) = [(1 + N) r^N] mod N^2
//
// See [KL 08] construction 11.32, page 414.
func (pub *PublicKey) encryptWithR(m, r *big.Int) (*big.Int, error) {
	if m.Cmp(ZERO()) == -1 || m.Cmp(pub.N) != -1 { // m < 0 || m >= N  ?
		return nil, fmt.Errorf(
			"%v is out of allowed plaintext space [0, %v)",
			m,
			pub.N,
		)
	}

	nSquare := pub.getNSquare()

	// g is _always_ equal n+1
	// Threshold encryption is safe only for g=n+1 choice.
	// See [DJN 10], section 5.1
	g := new(big.Int).Add(pub.N, ONE())
	gm := new(big.Int).Exp(g, m, nSquare)
	rn := new(big.Int).Exp(r, pub.N, nSquare)
	return new(big.Int).Mod(r.Mul(rn, gm), nSquare), nil
}

// Encrypt a plaintext into a cipher one. The plain text must be smaller that
// N and bigger than or equal zero. random is usually rand.Reader from the
// package crypto/rand.
//
// m - plaintext to encrypt
// E(m, r) = [(1 + N) r^N] mod N^2
//
// See [KL 08] construction 11.32, page 414.
//
// Returns an error if an error has be returned by io.Reader.
func (pub *PublicKey) Encrypt(random io.Reader, m *big.Int) (*big.Int, error) {
	r, err := GetRandomNumberInMultiplicativeGroup(pub.N, random)
	if err != nil {
		return nil, err
	}

	return pub.encryptWithR(m, r)
}

// Add takes an arbitrary number of ciphertexts and returns one that encodes
// their sum.
//
// It's possible because Paillier is a homomorphic encryption scheme, where
// the product of two ciphertexts will decrypt to the sum of their corresponding
// plaintexts:
//
// D( (E(m1) * E(m2) mod n^2) ) = m1 + m2 mod n
func (pub *PublicKey) Add(ciphertexts ...*big.Int) *big.Int {
	accumulator := ONE()

	for _, c := range ciphertexts {
		accumulator = new(big.Int).Mod(
			new(big.Int).Mul(accumulator, c),
			pub.getNSquare(),
		)
	}

	return accumulator
}

// Mul returns a product of `c` and `scalar` without decrypting `c`.
//
// It's possible because Paillier is a homomorphic encryption scheme, where
// an encrypted plaintext `m` raised to an integer `k` will decrypt to the
// product of the plaintext `m` and `k`:
//
// D( E(m)^k mod N^2 ) = km mod N
func (pub *PublicKey) Mul(c, scalar *big.Int) *big.Int {
	return new(big.Int).Exp(c, scalar, pub.getNSquare())
}

// Decodes ciphertext into a plaintext message.
//
// c - ciphertext to decrypt
// N, lambda - key attributes
//
// D(c) = [ ((c^lambda) mod N^2) - 1) / N ] lambda^-1 mod N
//
// See [KL 08] construction 11.32, page 414.
func (priv *PrivateKey) Decrypt(c *big.Int) (msg *big.Int) {
	mu := new(big.Int).ModInverse(priv.Lambda, priv.PublicKey.N)
	tmp := new(big.Int).Exp(c, priv.Lambda, priv.PublicKey.getNSquare())
	msg = new(big.Int).Mod(new(big.Int).Mul(L(tmp, priv.PublicKey.N), mu), priv.PublicKey.N)
	return
}

func L(u, n *big.Int) *big.Int {
	t := new(big.Int).Add(u, NEG_ONE())
	return new(big.Int).Div(t, n)
}

func minusOne(x *big.Int) *big.Int {
	return x.Add(x, NEG_ONE())
}

func computePhi(p, q *big.Int) *big.Int {
	return q.Mul(minusOne(p), minusOne(q))
}

// Generate a random element in the group of all the elements in Z/nZ that
// has a multiplicative inverse.
func GetRandomNumberInMultiplicativeGroup(n *big.Int, random io.Reader) (*big.Int, error) {
	r, err := rand.Int(random, n)
	if err != nil {
		return nil, err
	}

	if ZERO().Cmp(r) == 0 || ONE().Cmp(new(big.Int).GCD(nil, nil, n, r)) != 0 {
		return GetRandomNumberInMultiplicativeGroup(n, random)
	}
	return r, nil

}
