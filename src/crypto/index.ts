import { ECDSASigValue } from '@peculiar/asn1-ecc'
import { AsnParser } from '@peculiar/asn1-schema'
import { ChaCha20Poly1305 } from '@stablelib/chacha20poly1305'
import type { webcrypto as WebCrypto } from 'crypto'
import { PKCS1_KEM, PublicKey as RSAPubKey } from 'micro-rsa-dsa-dh/rsa.js'
import { AsymmetricCryptoAlgorithm, Crypto, Key } from '../types/crypto'
import { concatenateUint8Arrays, strToUint8Array } from '../utils/generics'
import { webcrypto } from '../utils/webcrypto'
import { parseRsaPublicKeyFromAsn1 } from './common'

const subtle = webcrypto.subtle

const X25519_PRIVATE_KEY_DER_PREFIX = new Uint8Array([
	48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
])

const P384_PRIVATE_KEY_DER_PREFIX = new Uint8Array([
	0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0x02, 0x01, 0x01, 0x04, 0x30
])

const P256_PRIVATE_KEY_DER_PREFIX = new Uint8Array([
	0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0x02, 0x01, 0x01, 0x04, 0x30
])

const SHARED_KEY_LEN_MAP: { [T in AsymmetricCryptoAlgorithm]: number } = {
	'X25519': 32,
	'P-384': 48,
	'P-256': 32,
}

const AUTH_TAG_BYTE_LENGTH = 16

export const crypto: Crypto = {
	importKey(alg, raw, ...args) {
		let subtleArgs: Parameters<typeof subtle.importKey>[2]
		let keyUsages: Parameters<typeof subtle.importKey>[4]
		let keyType: Parameters<typeof subtle.importKey>[0] = 'raw'
		switch (alg) {
		case 'AES-256-GCM':
		case 'AES-128-GCM':
			subtleArgs = {
				name: 'AES-GCM',
				length: alg === 'AES-256-GCM' ? 256 : 128
			}
			keyUsages = ['encrypt', 'decrypt']
			break
		case 'AES-128-CBC':
			subtleArgs = {
				name: 'AES-CBC',
				length: 128
			}
			keyUsages = ['encrypt', 'decrypt']
			break
		case 'CHACHA20-POLY1305':
			// chaCha20 is not supported by webcrypto
			// so we "fake" create a key
			return raw as unknown as Key
		case 'SHA-1':
		case 'SHA-256':
		case 'SHA-384':
			subtleArgs = {
				name: 'HMAC',
				hash: { name: alg }
			}
			keyUsages = ['sign', 'verify']
			break
		case 'P-384':
		case 'P-256':
			subtleArgs = {
				name: 'ECDH',
				namedCurve: alg,
			}
			keyUsages = []
			if(args[0] === 'private') {
				keyUsages = ['deriveBits']
				keyType = 'pkcs8'

				const prefix = alg === 'P-256'
					? P256_PRIVATE_KEY_DER_PREFIX
					: P384_PRIVATE_KEY_DER_PREFIX
				raw = concatenateUint8Arrays([
					prefix,
					raw
				])
			}

			break
		case 'X25519':
			subtleArgs = { name: 'X25519' }
			keyUsages = []
			if(args[0] === 'private') {
				keyUsages = ['deriveBits']
				keyType = 'pkcs8'
				raw = concatenateUint8Arrays([
					X25519_PRIVATE_KEY_DER_PREFIX,
					raw
				])
			}

			break
		case 'RSA-PSS-SHA256':
			keyType = 'spki'
			keyUsages = ['verify']
			subtleArgs = {
				name: 'RSA-PSS',
				hash: 'SHA-256'
			}
			break
		case 'RSA-PKCS1-SHA512':
		case 'RSA-PKCS1-SHA256':
		case 'RSA-PKCS1-SHA384':
			keyType = 'spki'
			keyUsages = ['verify']
			subtleArgs = {
				name: 'RSASSA-PKCS1-v1_5',
				hash: alg === 'RSA-PKCS1-SHA256'
					? 'SHA-256'
					: (alg === 'RSA-PKCS1-SHA384' ? 'SHA-384' : 'SHA-512')
			}
			break
		case 'RSA-PCKS1_5':
			return parseRsaPublicKeyFromAsn1(raw) as unknown as Key
		case 'ECDSA-SECP256R1-SHA256':
			keyType = 'spki'
			keyUsages = ['verify']
			subtleArgs = {
				name: 'ECDSA',
				namedCurve: 'P-256',
			}
			break
		case 'ECDSA-SECP384R1-SHA384':
			keyType = 'spki'
			keyUsages = ['verify']
			subtleArgs = {
				name: 'ECDSA',
				namedCurve: 'P-384',
			}
			break
		default:
			throw new Error(`Unsupported algorithm ${alg}`)
		}

		return subtle.importKey(
			keyType,
			raw,
			subtleArgs,
			true,
			keyUsages
		)
	},
	async exportKey(key) {
		// handle ChaCha20-Poly1305, RSA-PCKS1_5
		// as that's already a Uint8Array
		if(key instanceof Uint8Array) {
			return key
		}

		if(
			key.type === 'private'
			&& (
				key.algorithm.name === 'X25519'
				|| key.algorithm.name === 'ECDH'
			)
		) {
			const form = toUint8Array(await subtle.exportKey('pkcs8', key))
			const algPrefix = key.algorithm.name === 'X25519'
				? X25519_PRIVATE_KEY_DER_PREFIX
				: P384_PRIVATE_KEY_DER_PREFIX
			return form.slice(algPrefix.length)
		}

		return toUint8Array(await subtle.exportKey('raw', key))
	},
	async generateKeyPair(alg) {
		let genKeyArgs: RsaHashedKeyGenParams | EcKeyGenParams | AlgorithmIdentifier
		switch (alg) {
		case 'P-384':
		case 'P-256':
			genKeyArgs = {
				name: 'ECDH',
				namedCurve: alg,
			}
			break
		case 'X25519':
			genKeyArgs = { name: 'X25519' }
			break
		default:
			throw new Error(`Unsupported algorithm ${alg}`)
		}

		const keyPair = await subtle.generateKey(
			genKeyArgs,
			true,
			['deriveBits']
		) as WebCrypto.CryptoKeyPair
		return {
			pubKey: keyPair.publicKey,
			privKey: keyPair.privateKey,
		}
	},
	async calculateSharedSecret(alg, privateKey, publicKey) {
		const genKeyName = alg === 'X25519' ? 'X25519' : 'ECDH'
		const key = await subtle.deriveBits(
			{ name: genKeyName, public: publicKey },
			privateKey,
			8 * SHARED_KEY_LEN_MAP[alg],
		)
		return toUint8Array(key)
	},
	randomBytes(length) {
		const buffer = new Uint8Array(length)
		return webcrypto.getRandomValues(buffer)
	},
	asymmetricEncrypt(cipherSuite, { publicKey, data }) {
		if(cipherSuite !== 'RSA-PCKS1_5') {
			throw new Error(`Unsupported cipher suite ${cipherSuite}`)
		}

		return PKCS1_KEM.encrypt(publicKey as unknown as RSAPubKey, data)
	},
	async encrypt(cipherSuite, { iv, data, key }) {
		const name = cipherSuite === 'AES-128-CBC' ? 'AES-CBC' : ''
		return toUint8Array(await subtle.encrypt({ name, iv }, key, data))
			.slice(0, data.length)
	},
	async decrypt(cipherSuite, opts) {
		if(cipherSuite === 'AES-128-CBC') {
			const { decryptAesCbc } = await import('./aes-cbc')
			const exported = toUint8Array(await subtle.exportKey('raw', opts.key))
			return decryptAesCbc(exported, opts.iv, opts.data)
		}

		throw new Error(`Unsupported cipher suite ${cipherSuite}`)
	},
	async authenticatedEncrypt(cipherSuite, { iv, aead, key, data }) {
		let ciphertext: Uint8Array
		if(cipherSuite === 'CHACHA20-POLY1305') {
			const rawKey = key instanceof Uint8Array
				? key
				: await this.exportKey(key)

			const cipher = new ChaCha20Poly1305(rawKey)
			ciphertext = cipher.seal(iv, data, aead)
		} else {
			ciphertext = toUint8Array(
				await subtle.encrypt(
					{ name: 'AES-GCM', iv, additionalData: aead },
					key,
					data
				)
			)
		}

		return {
			ciphertext: ciphertext.slice(0, -AUTH_TAG_BYTE_LENGTH),
			authTag: ciphertext.slice(-AUTH_TAG_BYTE_LENGTH),
		}
	},
	async authenticatedDecrypt(cipherSuite, { iv, aead, key, data, authTag }) {
		if(!authTag) {
			throw new Error('authTag is required')
		}

		const ciphertext = concatenateUint8Arrays([ data, authTag ])
		let plaintext: Uint8Array
		if(cipherSuite === 'CHACHA20-POLY1305') {
			const rawKey = key instanceof Uint8Array
				? key
				: await this.exportKey(key)

			const cipher = new ChaCha20Poly1305(rawKey)
			plaintext = cipher.open(iv, ciphertext, aead)!
			if(!plaintext) {
				throw new Error('Failed to authenticate ChaCha20 ciphertext')
			}
		} else {
			plaintext = toUint8Array(
				await subtle.decrypt(
					{ name: 'AES-GCM', iv, additionalData: aead },
					key,
					ciphertext
				)
			)
		}

		return { plaintext }
	},
	async verify(alg, { data, signature, publicKey }) {
		let verifyArgs: Parameters<typeof subtle.verify>[0]
		switch (alg) {
		case 'RSA-PSS-SHA256':
			verifyArgs = { name: 'RSA-PSS', saltLength: 32 }
			break
		case 'RSA-PKCS1-SHA512':
		case 'RSA-PKCS1-SHA256':
		case 'RSA-PKCS1-SHA384':
			verifyArgs = {
				name: 'RSASSA-PKCS1-v1_5',
				hash: alg === 'RSA-PKCS1-SHA256'
					? 'SHA-256'
					: (alg === 'RSA-PKCS1-SHA384' ? 'SHA-384' : 'SHA-512')
			}
			break
		case 'ECDSA-SECP256R1-SHA256':
			signature = convertASN1toRS(signature)
			verifyArgs = { name: 'ECDSA', hash: 'SHA-256' }
			break
		case 'ECDSA-SECP384R1-SHA384':
			signature = convertASN1toRS(signature)
			verifyArgs = { name: 'ECDSA', hash: 'SHA-384' }
			break
		default:
			throw new Error(`Unsupported algorithm ${alg}`)
		}

		return subtle.verify(verifyArgs, publicKey, signature, data)
	},
	async hash(alg, data) {
		return toUint8Array(
			await subtle.digest(alg, data)
		)
	},
	async hmac(alg, key, data) {
		return toUint8Array(
			await subtle.sign(
				{ name: 'HMAC', hash: alg },
				key,
				data
			)
		)
	},
	// extract & expand logic referenced from:
	// https://github.com/futoin/util-js-hkdf/blob/master/hkdf.js
	async extract(alg, hashLength, ikm, salt) {
		salt = typeof salt === 'string' ? strToUint8Array(salt) : salt
		if(!salt.length) {
			salt = new Uint8Array(hashLength)
		}

		const key = await this.importKey(alg, salt)
		return this.hmac(alg, key, ikm)
	},
	async expand(alg, hashLength, key, expLength, info) {
		info = info || new Uint8Array(0)
		const infoLength = info.length
		const steps = Math.ceil(expLength / hashLength)
		if(steps > 0xFF) {
			throw new Error(`OKM length ${expLength} is too long for ${alg} hash`)
		}

		// use single buffer with unnecessary create/copy/move operations
		const t = new Uint8Array(hashLength * steps + infoLength + 1)
		for(let c = 1, start = 0, end = 0; c <= steps; ++c) {
			// add info
			t.set(info, end)
			// add counter
			t.set([c], end + infoLength)
			// use view: T(C) = T(C-1) | info | C
			const hmac = await this
				.hmac(alg, key, t.slice(start, end + infoLength + 1))
			// put back to the same buffer
			t.set(hmac.slice(0, t.length - end), end)

			start = end // used for T(C-1) start
			end += hashLength // used for T(C-1) end & overall end
		}

		return t.slice(0, expLength)
	},
}

function toUint8Array(buffer: ArrayBuffer) {
	return new Uint8Array(buffer)
}

// mostly from ChatGPT
function convertASN1toRS(signatureBytes: Uint8Array) {
	const data = AsnParser.parse(signatureBytes, ECDSASigValue)
	const r = cleanBigNum(new Uint8Array(data.r))
	const s = cleanBigNum(new Uint8Array(data.s))
	return concatenateUint8Arrays([ r, s ])
}

function cleanBigNum(bn: Uint8Array) {
	if(bn.length > 32 && bn[0] === 0) {
		bn = bn.slice(1)
	} else if(bn.length < 32) {
		bn = concatenateUint8Arrays([
			new Uint8Array(32 - bn.length).fill(0),
			bn
		])
	}

	return bn
}