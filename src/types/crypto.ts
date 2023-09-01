
export type Key = CryptoKey

export type SymmetricCryptoAlgorithm = 'AES-256-GCM'
	| 'AES-128-GCM'
	| 'CHACHA20-POLY1305'
export type CurveAlgorithm = 'RSA-PSS-RSAE-SHA256'
	| 'ED25519'
	| 'RSA-PKCS1-SHA512'
	| 'ECDSA-SECP256R1-SHA256'

export type HashAlgorithm = 'SHA-256' | 'SHA-384'
type CryptoAlgorithm = SymmetricCryptoAlgorithm

type Awaitable<T> = T | Promise<T>

type AuthenticatedCryptOptions = {
	key: Key
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
	calculateSharedSecret(privateKey: Key, publicKey: Key): Key
}

export type Crypto = {
	importKey(raw: Uint8Array, alg: CryptoAlgorithm): Awaitable<Key>
	exportKey(key: Key): Awaitable<Uint8Array>

	generateKeyPair(alg: CurveAlgorithm): Awaitable<KeyPair>
	calculateSharedSecret(alg: CurveAlgorithm, privateKey: Key, publicKey: Key): Awaitable<Uint8Array>
	exportPublicKey(key: Key): Awaitable<Uint8Array>
	importPrivateKey(alg: CurveAlgorithm, raw: Uint8Array): Awaitable<Key>
	importPublicKey(alg: CurveAlgorithm, raw: Uint8Array): Awaitable<Key>

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

	hash(alg: HashAlgorithm, data: Uint8Array): Awaitable<Uint8Array>
	hmac(alg: HashAlgorithm, key: Uint8Array, data: Uint8Array): Awaitable<Uint8Array>
	extract(alg: HashAlgorithm, hashLength: number, ikm: Uint8Array, salt: Uint8Array | string): Awaitable<Uint8Array>
	expand(alg: HashAlgorithm, hashLength: number, key: Uint8Array, expLength: number, label: Uint8Array): Awaitable<Uint8Array>
}