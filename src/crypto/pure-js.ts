import { cbc as aesCbc, gcm as aesGcm } from '@noble/ciphers/aes'
import { chacha20poly1305 } from '@noble/ciphers/chacha'
import type { Cipher } from '@noble/ciphers/utils'
import type { MontgomeryECDH } from '@noble/curves/abstract/montgomery'
import type { CurveFn } from '@noble/curves/abstract/weierstrass'
import { x25519 } from '@noble/curves/ed25519'
import { p256, p384 } from '@noble/curves/nist'
import { extract } from '@noble/hashes/hkdf'
import { hmac } from '@noble/hashes/hmac'
import { sha1 } from '@noble/hashes/legacy'
import { sha256, sha384 } from '@noble/hashes/sha2'
import type { CHash } from '@noble/hashes/utils'
import { OriginatorPublicKey } from '@peculiar/asn1-cms'
import { AsnParser } from '@peculiar/asn1-schema'
import { mgf1, PKCS1_KEM, PKCS1_SHA256, PKCS1_SHA384, PKCS1_SHA512, PSS } from 'micro-rsa-dsa-dh/rsa.js'
import type { AsymmetricCryptoAlgorithm, AuthenticatedSymmetricCryptoAlgorithm, Crypto, HashAlgorithm } from '../types/index.ts'
import { asciiToUint8Array, concatenateUint8Arrays } from '../utils/generics.ts'
import { bufToUint8Array, parseRsaPublicKeyFromAsn1 } from './common.ts'
import { randomBytes } from './insecure-rand.ts'

type MakeCipher
	= (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => Cipher

const CURVE_MAP: {
	[C in AsymmetricCryptoAlgorithm]: CurveFn | MontgomeryECDH
} = {
	'P-256': p256,
	'P-384': p384,
	'X25519': x25519
}

const AUTH_CIPHER_MAP: {
	[C in AuthenticatedSymmetricCryptoAlgorithm]: MakeCipher
} = {
	'AES-128-GCM': aesGcm,
	'AES-256-GCM': aesGcm,
	'CHACHA20-POLY1305': chacha20poly1305,
}

const HASH_MAP: { [C in HashAlgorithm]: CHash } = {
	'SHA-1': sha1,
	'SHA-256': sha256,
	'SHA-384': sha384
}

const AUTH_TAG_BYTE_LENGTH = 16

export const pureJsCrypto: Crypto<Uint8Array> = {
	importKey(_, raw) {
		return raw
	},
	exportKey(key) {
		return key
	},
	async generateKeyPair(alg) {
		const curve = CURVE_MAP[alg]
		const secretKey = curve.utils.randomSecretKey()
		if(alg === 'P-256' || alg === 'P-384') {
			// @ts-expect-error: need uncompressed public key for TLS
			const pubKey = curve.getPublicKey(secretKey, false)
			return { privKey: secretKey, pubKey }
		}

		return { privKey: secretKey, pubKey: curve.getPublicKey(secretKey) }
	},
	calculateSharedSecret(alg, privateKey, publicKey) {
		const curve = CURVE_MAP[alg]
		if(!curve) {
			throw new Error(`Unsupported algorithm: ${alg}`)
		}

		const secret = curve.getSharedSecret(privateKey, publicKey)
		if(alg === 'P-256' || alg === 'P-384') {
			// from noble curves, the secret is packed with 1 y-coordinate byte
			// so we need to remove the first byte
			return secret.slice(1) // remove the first byte
		}

		return secret
	},
	randomBytes: randomBytes,
	asymmetricEncrypt(cipherSuite, { publicKey, data }) {
		if(cipherSuite !== 'RSA-PCKS1_5') {
			throw new Error(`Unsupported cipher suite ${cipherSuite}`)
		}

		return PKCS1_KEM.encrypt(parseRsaPublicKeyFromAsn1(publicKey), data)
	},
	encrypt(cipherSuite, { key, iv, data }) {
		if(cipherSuite !== 'AES-128-CBC') {
			throw new Error(`Unsupported cipher suite: ${cipherSuite}`)
		}

		const cipher = aesCbc(key, iv, { disablePadding: true })
		return cipher.encrypt(data)
	},
	decrypt(cipherSuite, { key, iv, data }) {
		if(cipherSuite !== 'AES-128-CBC') {
			throw new Error(`Unsupported cipher suite: ${cipherSuite}`)
		}

		const cipher = aesCbc(key, iv, { disablePadding: true })
		const decrypted = cipher.decrypt(data)
		return decrypted
	},
	authenticatedEncrypt(cipherSuite, { key, iv, data, aead }) {
		const cipher = AUTH_CIPHER_MAP[cipherSuite](key, iv, aead)
		const ciphertext = cipher.encrypt(data)
		return {
			ciphertext: ciphertext.slice(0, -AUTH_TAG_BYTE_LENGTH),
			authTag: ciphertext.slice(-AUTH_TAG_BYTE_LENGTH),
		}
	},
	authenticatedDecrypt(cipherSuite, { key, iv, data, aead, authTag }) {
		const cipher = AUTH_CIPHER_MAP[cipherSuite](key, iv, aead)
		const decrypted = cipher.decrypt(concatenateUint8Arrays([data, authTag]))
		return { plaintext: decrypted }
	},
	verify(alg, { data, signature, publicKey }) {
		if(alg === 'ECDSA-SECP256R1-SHA256') {
			const parsedPubKey = parseAsn1PublicKey(publicKey)
			return p256.verify(signature, data, parsedPubKey, {
				prehash: true,
				format: 'der'
			})
		}

		if(alg === 'ECDSA-SECP384R1-SHA384') {
			const parsedPubKey = parseAsn1PublicKey(publicKey)
			return p384.verify(signature, data, parsedPubKey, {
				prehash: true,
				format: 'der'
			})
		}

		if(alg === 'RSA-PSS-SHA256') {
			const rsaPubKey = parseRsaPublicKeyFromAsn1(publicKey)
			const pss = PSS(sha256, mgf1(sha256), 32)
			return pss.verify(rsaPubKey, data, signature)
		}

		if(alg === 'RSA-PKCS1-SHA256') {
			const rsaPubKey = parseRsaPublicKeyFromAsn1(publicKey)
			return PKCS1_SHA256.verify(rsaPubKey, data, signature)
		}

		if(alg === 'RSA-PKCS1-SHA384') {
			const rsaPubKey = parseRsaPublicKeyFromAsn1(publicKey)
			return PKCS1_SHA384.verify(rsaPubKey, data, signature)
		}

		if(alg === 'RSA-PKCS1-SHA512') {
			const rsaPubKey = parseRsaPublicKeyFromAsn1(publicKey)
			return PKCS1_SHA512.verify(rsaPubKey, data, signature)
		}

		throw new Error(`Unsupported signature algorithm: ${alg}`)
	},
	hash(alg, data) {
		const hasher = HASH_MAP[alg].create()
		hasher.update(data)
		return hasher.digest()
	},
	hmac(alg, key, data) {
		return hmac(HASH_MAP[alg], key, data)
	},
	extract(alg, hashLength, ikm, salt) {
		salt = typeof salt === 'string' ? asciiToUint8Array(salt) : salt
		if(!salt.length) {
			salt = new Uint8Array(hashLength).fill(0)
		}

		return extract(HASH_MAP[alg], ikm, salt)
	}
}

function parseAsn1PublicKey(pubKey: Uint8Array) {
	const parsed = AsnParser.parse(pubKey, OriginatorPublicKey)
	return bufToUint8Array(parsed.publicKey)
}