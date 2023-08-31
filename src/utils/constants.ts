import { getWebCrypto } from '../utils/x509'
import { concatenateUint8Arrays } from './generics'

// TLS 1.2 -- used in header of all messages
export const LEGACY_PROTOCOL_VERSION = new Uint8Array([ 0x03, 0x03 ])
// TLS 1.3
export const CURRENT_PROTOCOL_VERSION = new Uint8Array([ 0x03, 0x04 ])
// no compression, as TLS 1.3 does not support it
export const COMPRESSION_MODE = new Uint8Array([ 0x01, 0x00 ])

export const SUPPORTED_KEY_TYPE_MAP = {
	SECP384R1: new Uint8Array([ 0x00, 0x18 ]),
	X25519: new Uint8Array([ 0x00, 0x1d ]),
}

export const SUPPORTED_RECORD_TYPE_MAP = {
	CLIENT_HELLO: 0x01,
	SERVER_HELLO: 0x02,
	SESSION_TICKET: 0x04,
	ENCRYPTED_EXTENSIONS: 0x08,
	CERTIFICATE: 0x0b,
	CERTIFICATE_REQUEST: 0x0d,
	CERTIFICATE_VERIFY: 0x0f,
	FINISHED: 0x14,
	KEY_UPDATE: 0x18
}

export const CONTENT_TYPE_MAP = {
	CHANGE_CIPHER_SPEC: 0x14,
	ALERT: 0x15,
	HANDSHAKE: 0x16,
	APPLICATION_DATA: 0x17,
}

// The length of AEAD auth tag, appended after encrypted data in wrapped records
export const AUTH_TAG_BYTE_LENGTH = 16

export const SUPPORTED_KEY_TYPES = Object.keys(SUPPORTED_KEY_TYPE_MAP) as (keyof typeof SUPPORTED_KEY_TYPE_MAP)[]

export const SUPPORTED_CIPHER_SUITE_MAP = {
	TLS_CHACHA20_POLY1305_SHA256:{
		identifier: new Uint8Array([0x13, 0x03]),
		keyLength: 32,
		hashLength: 32,
		hashAlgorithm: 'sha256',
		cipher: 'chacha20-poly1305'
	},
	TLS_AES_256_GCM_SHA384: {
		identifier: new Uint8Array([ 0x13, 0x02 ]),
		keyLength: 32,
		hashLength: 48,
		hashAlgorithm: 'sha384',
		cipher: 'aes-256-gcm',
	},
	TLS_AES_128_GCM_SHA256: {
		identifier: new Uint8Array([ 0x13, 0x01 ]),
		keyLength: 16,
		hashLength: 32,
		hashAlgorithm: 'sha256',
		cipher: 'aes-128-gcm',
	},
} as const

export const ALERT_LEVEL = {
	WARNING: 1,
	FATAL: 2,
}

export const ALERT_DESCRIPTION = {
	CLOSE_NOTIFY: 0,
	UNEXPECTED_MESSAGE: 10,
	BAD_RECORD_MAC: 20,
	RECORD_OVERFLOW: 22,
	HANDSHAKE_FAILURE: 40,
	BAD_CERTIFICATE: 42,
	UNSUPPORTED_CERTIFICATE: 43,
	CERTIFICATE_REVOKED: 44,
	CERTIFICATE_EXPIRED: 45,
	CERTIFICATE_UNKNOWN: 46,
	ILLEGAL_PARAMETER: 47,
	UNKNOWN_CA: 48,
	ACCESS_DENIED: 49,
	DECODE_ERROR: 50,
	DECRYPT_ERROR: 51,
	PROTOCOL_VERSION: 70,
	INSUFFICIENT_SECURITY: 71,
	INTERNAL_ERROR: 80,
	INAPPROPRIATE_FALLBACK: 86,
	USER_CANCELED: 90,
	MISSING_EXTENSION: 109,
	UNSUPPORTED_EXTENSION: 110,
	UNRECOGNIZED_NAME: 112,
	BAD_CERTIFICATE_STATUS_RESPONSE: 113,
	UNKNOWN_PSK_IDENTITY: 115,
	CERTIFICATE_REQUIRED: 116,
	NO_APPLICATION_PROTOCOL: 120,
}

export const SUPPORTED_CIPHER_SUITES = Object.keys(SUPPORTED_CIPHER_SUITE_MAP) as (keyof typeof SUPPORTED_CIPHER_SUITE_MAP)[]

type SignatureAlgType = 'RSA_PSS_RSAE_SHA256'
	| 'ED25519'
	| 'RSA_PKCS1_SHA512'
	| 'ECDSA_SECP256R1_SHA256'

type SupportedSignatureAlg = {
	identifier: Uint8Array
	verify(data: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean | Promise<boolean>
}

export const SUPPORTED_SIGNATURE_ALGS_MAP: { [K in SignatureAlgType]: SupportedSignatureAlg } = {
	RSA_PSS_RSAE_SHA256: {
		identifier: new Uint8Array([ 0x08, 0x04 ]),
		async verify(data, signature, publicKey) {
			const { subtle } = getWebCrypto()
			const pubKey = await subtle.importKey(
				'spki',
				publicKey,
				{
					name: 'RSA-PSS',
					hash: 'SHA-256'
				},
				true,
				['verify']
			)

			const result = await subtle.verify(
				{
					name: 'RSA-PSS',
					saltLength: 32
				},
				pubKey,
				signature,
				data,
			)

			return result
		},
	},
	ECDSA_SECP256R1_SHA256: {
		identifier: new Uint8Array([ 0x04, 0x03 ]),
		async verify(data, signature, publicKey) {
			const { subtle } = getWebCrypto()
			const pubKey = await subtle.importKey(
				'spki',
				publicKey,
				{
					name: 'ECDSA',
					namedCurve: 'P-256',
				},
				true,
				['verify']
			)

			const sig2 = convertASN1toRS(signature)

			const result = await subtle.verify(
				{
					name: 'ECDSA',
					hash: 'SHA-256',
				},
				pubKey,
				sig2,
				data,
			)

			return result

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
		}
	},
	ED25519: {
		identifier: new Uint8Array([ 0x08, 0x07 ]),
		verify() {
			throw new Error('Not implemented')
		}
	},
	RSA_PKCS1_SHA512: {
		identifier: new Uint8Array([ 0x06, 0x01 ]),
		verify() {
			throw new Error('Not implemented')
		}
	},
}

export const SUPPORTED_SIGNATURE_ALGS = Object.keys(SUPPORTED_SIGNATURE_ALGS_MAP) as (keyof typeof SUPPORTED_SIGNATURE_ALGS_MAP)[]

export const SUPPORTED_EXTENSION_MAP = {
	SERVER_NAME: 0x00,
	KEY_SHARE: 0x33,
	SUPPORTED_GROUPS: 0x0a,
	SIGNATURE_ALGS: 0x0d,
	SUPPORTED_VERSIONS: 0x2b,
	SESSION_TICKET: 0x23,
	EARLY_DATA: 0x2a,
	PRE_SHARED_KEY: 0x29,
	PRE_SHARED_KEY_MODE: 0x2d,
}

export const SUPPORTED_EXTENSIONS = Object.keys(SUPPORTED_EXTENSION_MAP) as (keyof typeof SUPPORTED_EXTENSION_MAP)[]

export const PACKET_TYPE = {
	HELLO: 0x16,
	WRAPPED_RECORD: 0x17,
	CHANGE_CIPHER_SPEC: 0x14,
	ALERT: 0x15,
}

export const KEY_UPDATE_TYPE_MAP = {
	UPDATE_NOT_REQUESTED: 0,
	UPDATE_REQUESTED: 1
}

export const CLIENT_CERTIFICATE_RESPONSE_CIPHERTEXT_SIZE = 37