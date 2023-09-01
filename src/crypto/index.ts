import { webcrypto } from 'crypto'
import { AsymmetricCryptoAlgorithm, Crypto } from '../types/crypto'
import { concatenateUint8Arrays, strToUint8Array } from '../utils/generics'

const subtle = webcrypto.subtle

const X25519_PRIVATE_KEY_DER_PREFIX = Buffer.from([
	48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
])

const SHARED_KEY_LEN_MAP: { [T in AsymmetricCryptoAlgorithm]: number } = {
	'X25519': 32,
	'P-384': 48,
}

export const crypto = {
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
		case 'CHACHA20-POLY1305':
			subtleArgs = { name: 'AES-GCM', length: 256 }
			keyUsages = ['encrypt', 'decrypt']
			break
		case 'SHA-256':
		case 'SHA-384':
			subtleArgs = {
				name: 'HMAC',
				hash: { name: alg }
			}
			keyUsages = ['sign', 'verify']
			break
		case 'P-384':
			subtleArgs = {
				name: 'ECDH',
				namedCurve: 'P-384',
			}
			keyUsages = []
			if(args[0] === 'private') {
				keyUsages = ['deriveBits']
				keyType = 'pkcs8'
				raw = Buffer.concat([
					Buffer.from([0x04]),
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
				raw = Buffer.concat([
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
		case 'ECDSA-SECP256R1-SHA256':
			keyType = 'spki'
			keyUsages = ['verify']
			subtleArgs = {
				name: 'ECDSA',
				namedCurve: 'P-256',
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
		if(
			key.type === 'private'
			&& (
				key.algorithm.name === 'X25519'
				|| key.algorithm.name === 'P-256'
			)
		) {
			const form = toUint8Array(
				await subtle.exportKey('pkcs8', key)
			)
			return form.slice(X25519_PRIVATE_KEY_DER_PREFIX.length)
		}

		return toUint8Array(
			await subtle.exportKey('raw', key)
		)
	},
	async generateKeyPair(alg) {
		let genKeyArgs: Parameters<typeof subtle.generateKey>[0]
		switch (alg) {
		case 'P-384':
			genKeyArgs = {
				name: 'ECDH',
				// @ts-ignore
				namedCurve: 'P-384',
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
		) as webcrypto.CryptoKeyPair
		return {
			pubKey: keyPair.publicKey,
			privKey: keyPair.privateKey,
		}
	},
	async calculateSharedSecret(alg, privateKey, publicKey) {
		const genKeyName = alg === 'X25519'
			? 'X25519'
			: 'ECDH'
		const key = await subtle.deriveBits(
			{
				name: genKeyName,
				public: publicKey,
			},
			privateKey,
			8 * SHARED_KEY_LEN_MAP[alg],
		)
		return toUint8Array(key)
	},
	randomBytes(length) {
		const buffer = new Uint8Array(length)
		return webcrypto.getRandomValues(buffer)
	},
	async authenticatedEncrypt(cipherSuite, { iv, aead, key, data }) {
		if(cipherSuite === 'CHACHA20-POLY1305') {
			throw new Error('CHACHA20-POLY1305 not supported')
		}

		const ciphertext = toUint8Array(
			await subtle.encrypt(
				{
					name: 'AES-GCM',
					iv,
					additionalData: aead,
				},
				key,
				data
			)
		)

		return {
			ciphertext: ciphertext.slice(0, -16),
			authTag: ciphertext.slice(-16),
		}
	},
	async authenticatedDecrypt(cipherSuite, { iv, aead, key, data, authTag }) {
		if(cipherSuite === 'CHACHA20-POLY1305') {
			throw new Error('CHACHA20-POLY1305 not supported')
		}

		const ciphertext = concatenateUint8Arrays([ data, authTag! ])
		const plaintext = toUint8Array(
			await subtle.decrypt(
				{
					name: 'AES-GCM',
					iv,
					additionalData: aead,
				},
				key,
				ciphertext
			)
		)

		return { plaintext }
	},
	async verify(alg, { data, signature, publicKey }) {
		let verifyArgs: Parameters<typeof subtle.verify>[0]
		switch (alg) {
		case 'RSA-PSS-SHA256':
			verifyArgs = {
				name: 'RSA-PSS',
				saltLength: 32
			}
			break
		case 'ECDSA-SECP256R1-SHA256':
			signature = convertASN1toRS(signature)
			verifyArgs = {
				name: 'ECDSA',
				hash: 'SHA-256',
			}
			break
		default:
			throw new Error(`Unsupported algorithm ${alg}`)
		}

		return subtle.verify(
			verifyArgs,
			publicKey,
			signature,
			data,
		)
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
} as Crypto

function toUint8Array(buffer: ArrayBuffer) {
	return new Uint8Array(buffer)
}

// mostly from ChatGPT
function convertASN1toRS(signatureBytes: Uint8Array) {
	// Check if the signature is in the expected ASN.1 format (SEQUENCE)
	if(signatureBytes[0] !== 0x30) {
		throw new Error('Invalid ASN.1 signature format.')
	}

	// Get the lengths of the r and s components
	const rLength = signatureBytes[3]
	const sLength = signatureBytes[5 + rLength]

	// Extract the r and s components from the signature
	const rStart = 4
	const rEnd = rStart + rLength
	const sStart = rEnd + 2
	const sEnd = sStart + sLength

	// Create separate r and s arrays
	let r = signatureBytes.slice(rStart, rEnd)
	let s = signatureBytes.slice(sStart, sEnd)
	r = cleanBigNum(r)
	s = cleanBigNum(s)

	return concatenateUint8Arrays([ r, s ])
}

function cleanBigNum(bn: Uint8Array) {
	// Trim leading zeros
	if(bn[0] === 0x00) {
		return bn.slice(1)
	}

	bn = concatenateUint8Arrays([
		new Uint8Array(32 - bn.length).fill(0),
		bn
	])

	return bn
}