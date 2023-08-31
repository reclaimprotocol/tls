
type Key = Uint8Array

type SymmetricCryptoAlgorithm = 'AES-GCM'
	| 'CHACHA20-POLY1305'
type CurveAlgorithm = 'RSA-PSS-RSAE-SHA256'
	| 'ED25519'
	| 'RSA-PKCS1-SHA512'
	| 'ECDSA-SECP256R1-SHA256'
type CryptoAlgorithm = SymmetricCryptoAlgorithm

type Awaitable<T> = T | Promise<T>

type AuthenticatedCryptOptions = {
	key: Uint8Array
	iv: Uint8Array
	data: Uint8Array
	aead: Uint8Array
	authTag?: Uint8Array
}

type VerifyOptions = {
	data: Uint8Array,
	signature: Uint8Array,
	publicKey: Key
}

export type KeyPair = {
	pubKey: Key
	privKey: Key
}

export type CurveImplementation = {
	generateKeyPair(): KeyPair
	calculateSharedKey(privateKey: Key, publicKey: Key): Key
}

export type Crypto = {
	importKey(raw: Uint8Array, alg: CryptoAlgorithm): Awaitable<Key>
	exportKey(key: Key): Awaitable<Uint8Array>
	randomBytes(length: number): Uint8Array
	authenticatedEncrypt(
		cipherSuite: SymmetricCryptoAlgorithm,
		opts: AuthenticatedCryptOptions
	): Awaitable<{ ciphertext: Uint8Array, authTag: Uint8Array }>
	authenticatedDecrypt(
		cipherSuite: SymmetricCryptoAlgorithm,
		opts: AuthenticatedCryptOptions
	): Awaitable<{ plaintext: Uint8Array }>
	verify(
		alg: CurveAlgorithm,
		opts: VerifyOptions
	): Awaitable<boolean>
}