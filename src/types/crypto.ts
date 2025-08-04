
export type Key = unknown

export type AuthenticatedSymmetricCryptoAlgorithm = 'AES-256-GCM'
	| 'AES-128-GCM'
	| 'CHACHA20-POLY1305'
export type SymmetricCryptoAlgorithm = 'AES-128-CBC'
export type AsymmetricCryptoAlgorithm = 'X25519'
	| 'P-256' // SECP256R1
	| 'P-384' // SECP384R1
export type AsymmetricEncDecAlgorithm = 'RSA-PCKS1_5'
export type SignatureAlgorithm = 'RSA-PSS-SHA256'
	| 'ECDSA-SECP384R1-SHA384'
	| 'ECDSA-SECP256R1-SHA256'
	| 'RSA-PKCS1-SHA512'
	| 'RSA-PKCS1-SHA384'
	| 'RSA-PKCS1-SHA256'

export type HashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-1'

type Awaitable<T> = T | Promise<T>

type CryptOptions<K = Key> = {
	key: K
	iv: Uint8Array
	data: Uint8Array
}

type AuthenticatedCryptOptions<K = Key> = {
	key: K
	iv: Uint8Array
	data: Uint8Array
	aead: Uint8Array
}

type VerifyOptions<K = Key> = {
	data: Uint8Array
	signature: Uint8Array
	publicKey: K
}

export type KeyPair<K = Key> = {
	pubKey: K
	privKey: K
}

export type Crypto<K> = {
	importKey(
		alg: AuthenticatedSymmetricCryptoAlgorithm | SymmetricCryptoAlgorithm,
		raw: Uint8Array,
		empty?: unknown
	): Awaitable<K>
	importKey(alg: HashAlgorithm, raw: Uint8Array, empty?: unknown): Awaitable<K>
	importKey(
		alg: SignatureAlgorithm | AsymmetricEncDecAlgorithm,
		raw: Uint8Array,
		type: 'public'
	): Awaitable<K>
	importKey(alg: AsymmetricCryptoAlgorithm, raw: Uint8Array, type: 'private' | 'public'): Awaitable<K>
	exportKey(key: K): Awaitable<Uint8Array>

	generateKeyPair(alg: AsymmetricCryptoAlgorithm): Awaitable<KeyPair<K>>
	calculateSharedSecret(alg: AsymmetricCryptoAlgorithm, privateKey: K, publicKey: K): Awaitable<Uint8Array>

	randomBytes(length: number): Uint8Array
	asymmetricEncrypt(
		cipherSuite: AsymmetricEncDecAlgorithm,
		opts: {
			publicKey: K
			data: Uint8Array
		}
	): Awaitable<Uint8Array>
	/**
	 * Encrypts data with the given cipher suite and options.
	 * Expects padding has already been applied to the data.
	 */
	encrypt(
		cipherSuite: SymmetricCryptoAlgorithm,
		opts: CryptOptions<K>
	): Awaitable<Uint8Array>
	decrypt(
		cipherSuite: SymmetricCryptoAlgorithm,
		opts: CryptOptions<K>
	): Awaitable<Uint8Array>
	authenticatedEncrypt(
		cipherSuite: AuthenticatedSymmetricCryptoAlgorithm,
		opts: AuthenticatedCryptOptions<K>
	): Awaitable<{ ciphertext: Uint8Array, authTag: Uint8Array }>
	authenticatedDecrypt(
		cipherSuite: AuthenticatedSymmetricCryptoAlgorithm,
		opts: AuthenticatedCryptOptions<K> & { authTag: Uint8Array }
	): Awaitable<{ plaintext: Uint8Array }>
	verify(
		alg: SignatureAlgorithm,
		opts: VerifyOptions<K>
	): Awaitable<boolean>

	hash(alg: HashAlgorithm, data: Uint8Array): Awaitable<Uint8Array>
	hmac(alg: HashAlgorithm, key: K, data: Uint8Array): Awaitable<Uint8Array>
	extract(alg: HashAlgorithm, hashLength: number, ikm: Uint8Array, salt: Uint8Array | string): Awaitable<Uint8Array>
}