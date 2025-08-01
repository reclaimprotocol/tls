
export type Key = CryptoKey

export type AuthenticatedSymmetricCryptoAlgorithm = 'AES-256-GCM'
	| 'AES-128-GCM'
	| 'CHACHA20-POLY1305'
export type SymmetricCryptoAlgorithm = 'AES-128-CBC'
export type AsymmetricCryptoAlgorithm = 'X25519'
	| 'P-256' // SECP256R1
	| 'P-384' // SECP384R1
export type SignatureAlgorithm = 'RSA-PSS-SHA256'
	| 'ECDSA-SECP384R1-SHA384'
	| 'ECDSA-SECP256R1-SHA256'
	| 'ED25519'
	| 'RSA-PKCS1-SHA512'
	| 'RSA-PKCS1-SHA384'
	| 'RSA-PKCS1-SHA256'

export type HashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-1'

type Awaitable<T> = T | Promise<T>

type CryptOptions = {
	key: Key
	iv: Uint8Array
	data: Uint8Array
}

type AuthenticatedCryptOptions = {
	key: Key
	iv: Uint8Array
	data: Uint8Array
	aead: Uint8Array
	authTag?: Uint8Array
}

type VerifyOptions = {
	data: Uint8Array
	signature: Uint8Array
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
	importKey(alg: AuthenticatedSymmetricCryptoAlgorithm | SymmetricCryptoAlgorithm, raw: Uint8Array): Awaitable<Key>
	importKey(alg: HashAlgorithm, raw: Uint8Array): Awaitable<Key>
	importKey(alg: SignatureAlgorithm, raw: Uint8Array, type: 'public'): Awaitable<Key>
	importKey(alg: AsymmetricCryptoAlgorithm, raw: Uint8Array, type: 'private' | 'public'): Awaitable<Key>
	exportKey(key: Key): Awaitable<Uint8Array>

	generateKeyPair(alg: AsymmetricCryptoAlgorithm): Awaitable<KeyPair>
	calculateSharedSecret(alg: AsymmetricCryptoAlgorithm, privateKey: Key, publicKey: Key): Awaitable<Uint8Array>

	randomBytes(length: number): Uint8Array
	/**
	 * Encrypts data with the given cipher suite and options.
	 * Expects padding has already been applied to the data.
	 */
	encrypt(
		cipherSuite: SymmetricCryptoAlgorithm,
		opts: CryptOptions
	): Awaitable<Uint8Array>
	decrypt(
		cipherSuite: SymmetricCryptoAlgorithm,
		opts: CryptOptions
	): Awaitable<Uint8Array>
	authenticatedEncrypt(
		cipherSuite: AuthenticatedSymmetricCryptoAlgorithm,
		opts: AuthenticatedCryptOptions
	): Awaitable<{ ciphertext: Uint8Array, authTag: Uint8Array }>
	authenticatedDecrypt(
		cipherSuite: AuthenticatedSymmetricCryptoAlgorithm,
		opts: AuthenticatedCryptOptions
	): Awaitable<{ plaintext: Uint8Array }>
	verify(
		alg: SignatureAlgorithm,
		opts: VerifyOptions
	): Awaitable<boolean>

	hash(alg: HashAlgorithm, data: Uint8Array): Awaitable<Uint8Array>
	hmac(alg: HashAlgorithm, key: Key, data: Uint8Array): Awaitable<Uint8Array>
	extract(alg: HashAlgorithm, hashLength: number, ikm: Uint8Array, salt: Uint8Array | string): Awaitable<Uint8Array>
	expand(alg: HashAlgorithm, hashLength: number, key: Key, expLength: number, info: Uint8Array): Awaitable<Uint8Array>
}