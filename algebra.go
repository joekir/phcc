package phcc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"github.com/joekir/phcc/elgamal"
	"github.com/joekir/phcc/paillier"
	"log"
	"math/big"
)

// TODO would like to use EC (due to speed of encryption) but for now using RSA as the corelib support seems better
// Refs:
// 	- https://www.quora.com/How-much-faster-can-encryption-and-signing-be-with-an-elliptic-curve-EC-certificate-compared-to-an-RSA-certificate
// 	- https://safecurves.cr.yp.to

type LedgerKeys struct {
	chainKeyPriv rsa.PrivateKey
	mulKeyPriv   elgamal.PrivateKey
	addKeyPriv   paillier.PrivateKey
}

type Ledger struct {
	chainKeyPub rsa.PublicKey
	mulKeyPub   elgamal.PublicKey
	addKeyPub   paillier.PublicKey
	operations  []byte // current encrypted state
	ciphertext  []byte
}

// TODO improve types
const ADD_OP = "Add"
const MUL_OP = "Multiply"
const DIVIDER = "|"

// TODO factor out
// This is the 1024-bit MODP group from RFC 5114, section 2.1:
const primeHex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
const generatorHex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"

func NewLedger() (*LedgerKeys, *Ledger) {
	// Chain Keys
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// Multiply Keys
	elPriv := &elgamal.PrivateKey{
		PublicKey: elgamal.PublicKey{
			G: elgamal.HexToBigInt(generatorHex),
			P: elgamal.HexToBigInt("71"),
		},
		X: elgamal.HexToBigInt("42"),
	}
	elPriv.PublicKey.Y = new(big.Int).Exp(elPriv.G, elPriv.X, elPriv.P)

	// Addition Keys
	paillierPriv := paillier.CreatePrivateKey(big.NewInt(17), big.NewInt(13))

	ledgerKeys := &LedgerKeys{
		chainKeyPriv: *rsaPriv,
		mulKeyPriv:   *elPriv,
		addKeyPriv:   *paillierPriv,
	}

	ledger := &Ledger{
		chainKeyPub: rsaPriv.PublicKey,
		mulKeyPub:   elPriv.PublicKey,
		addKeyPub:   paillierPriv.PublicKey,
		operations:  []byte{},
		ciphertext:  []byte{},
	}

	return ledgerKeys, ledger
}

func (ledger *Ledger) Multiply(cipher1, cipher2 *elgamal.Ciphertext) {
	c1 := new(big.Int).Mod(new(big.Int).Mul(cipher1.C1, cipher2.C1), ledger.mulKeyPub.P)
	c2 := new(big.Int).Mod(new(big.Int).Mul(cipher1.C2, cipher2.C2), ledger.mulKeyPub.P)

	input := append(ledger.operations, []byte(DIVIDER)...)
	input = append(input, []byte(MUL_OP)...)

	updatedOperations, err :=
		rsa.EncryptOAEP(sha256.New(), rand.Reader, &ledger.chainKeyPub, input, nil)

	if err != nil {
		log.Fatalln(err)
	}

	cipher3 := &elgamal.Ciphertext{
		C1: c1,
		C2: c2,
	}

	buffer := new(bytes.Buffer)
	enc := gob.NewEncoder(buffer)
	err = enc.Encode(cipher3)
	if err != nil {
		log.Fatalln(err)
	}

	encoded := buffer.Bytes()
	ledger.ciphertext = encoded
	ledger.operations = updatedOperations
}

func (ledger *Ledger) Add(c1, c2 *big.Int) {
	input := append(ledger.operations, []byte(DIVIDER)...)
	input = append(input, []byte(ADD_OP)...)

	updatedOperations, err :=
		rsa.EncryptOAEP(sha256.New(), rand.Reader, &ledger.chainKeyPub, input, nil)

	if err != nil {
		log.Fatalln(err)
	}

	c3 := ledger.addKeyPub.Add(c1, c2)

	buffer := new(bytes.Buffer)
	enc := gob.NewEncoder(buffer)
	err = enc.Encode(c3)
	if err != nil {
		log.Fatalln(err)
	}

	encoded := buffer.Bytes()
	ledger.ciphertext = encoded
	ledger.operations = updatedOperations
}
