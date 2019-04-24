# partially-homomorphic crypto chaining (PHCC)

Some encryption schemes are closed under multiplication, in that you can multiply 2 ciphertexts and decrypt to obtain the result of the multiplication of the plaintext. 

Examples that do this are [textbook-RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Attacks_against_plain_RSA) and [ElGamal](https://en.wikipedia.org/wiki/ElGamal_encryption) public-key schemes. Using ElGamal here as it is non-deterministic ([IND-CPA](https://blog.cryptographyengineering.com/why-ind-cpa-implies-randomized-encryption/)) as textbook-RSA is.

In a more rare instance others are closed under addition, in that you can add 2 ciphertexts, decrypt to obtain the result of the addition of the 2 plaintexts. Using [Paillier](https://en.wikipedia.org/wiki/Paillier_cryptosystem) cryptosystem for this.

Hence instead of seeking a purely homomorphic numerical foundation this is an attempt to bind these 2 partials via some other signing mechanism, such that many operations can be performed on the ciphertext and only the one with the chain's private-key can verify and decrypt the result.

## Warning

Not suitable for production systems, just an exploration POC

## Running the Tests

_requires go > 1.11 for gomodules feature_

`$ go test ./...`

## Some Related Reading

- [Fully Homomorphic Encryption: Cryptography’s Holy Grail](https://www.cs.virginia.edu/dwu4/papers/XRDSFHE.pdf) (David J. Wu)
- [Multiparty Homomorphic Encryption](https://courses.csail.mit.edu/6.857/2016/files/17.pdf) (Alex Padron, Guillermo Vargas)
