export const TLS_PROTOCOL_VERSION_MAP = {
	'TLS1_3': new Uint8Array([ 0x03, 0x04 ]),
	'TLS1_2': new Uint8Array([ 0x03, 0x03 ]),
}

export const SUPPORTED_NAMED_CURVE_MAP = {
	SECP256R1: {
		identifier: new Uint8Array([ 0x00, 0x17 ]),
		algorithm: 'P-256'
	} as const,
	SECP384R1: {
		identifier: new Uint8Array([ 0x00, 0x18 ]),
		algorithm: 'P-384'
	} as const,
	X25519: {
		identifier: new Uint8Array([ 0x00, 0x1d ]),
		algorithm: 'X25519'
	} as const,
}

export const SUPPORTED_RECORD_TYPE_MAP = {
	CLIENT_HELLO: 0x01,
	SERVER_HELLO: 0x02,
	SESSION_TICKET: 0x04,
	ENCRYPTED_EXTENSIONS: 0x08,
	CERTIFICATE: 0x0b,
	SERVER_KEY_SHARE: 0x0c,
	CERTIFICATE_REQUEST: 0x0d,
	SERVER_HELLO_DONE: 0x0e,
	CERTIFICATE_VERIFY: 0x0f,
	CLIENT_KEY_SHARE: 0x10,
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

export const SUPPORTED_NAMED_CURVES = Object.keys(SUPPORTED_NAMED_CURVE_MAP) as (keyof typeof SUPPORTED_NAMED_CURVE_MAP)[]

/**
 * Supported cipher suites.
 * In a client hello, these are sent in order of preference
 * as listed below
 */
export const SUPPORTED_CIPHER_SUITE_MAP = {
	// TLS 1.3 --------------------
	TLS_CHACHA20_POLY1305_SHA256: {
		identifier: new Uint8Array([0x13, 0x03]),
		keyLength: 32,
		hashLength: 32,
		ivLength: 12,
		hashAlgorithm: 'SHA-256',
		cipher: 'CHACHA20-POLY1305'
	},
	TLS_AES_256_GCM_SHA384: {
		identifier: new Uint8Array([ 0x13, 0x02 ]),
		keyLength: 32,
		hashLength: 48,
		ivLength: 12,
		hashAlgorithm: 'SHA-384',
		cipher: 'AES-256-GCM',
	},
	TLS_AES_128_GCM_SHA256: {
		identifier: new Uint8Array([ 0x13, 0x01 ]),
		keyLength: 16,
		hashLength: 32,
		ivLength: 12,
		hashAlgorithm: 'SHA-256',
		cipher: 'AES-128-GCM',
	},
	// TLS 1.2 -------------------
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: {
		identifier: new Uint8Array([ 0xcc, 0xa8 ]),
		keyLength: 32,
		hashLength: 32,
		ivLength: 12,
		hashAlgorithm: 'SHA-256',
		cipher: 'CHACHA20-POLY1305',
	},
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: {
		identifier: new Uint8Array([ 0xcc, 0xa9 ]),
		keyLength: 32,
		hashLength: 32,
		ivLength: 12,
		hashAlgorithm: 'SHA-256',
		cipher: 'CHACHA20-POLY1305',
	},
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: {
		identifier: new Uint8Array([ 0xc0, 0x2f ]),
		keyLength: 16,
		hashLength: 32,
		ivLength: 4,
		hashAlgorithm: 'SHA-256',
		cipher: 'AES-128-GCM',
	},
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {
		identifier: new Uint8Array([ 0xc0, 0x2b ]),
		keyLength: 16,
		hashLength: 32,
		ivLength: 4,
		hashAlgorithm: 'SHA-256',
		cipher: 'AES-128-GCM',
	},
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: {
		identifier: new Uint8Array([ 0xc0, 0x30 ]),
		keyLength: 32,
		hashLength: 48,
		ivLength: 4,
		hashAlgorithm: 'SHA-384',
		cipher: 'AES-256-GCM',
	},
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {
		identifier: new Uint8Array([ 0xc0, 0x2c ]),
		keyLength: 32,
		hashLength: 48,
		ivLength: 4,
		hashAlgorithm: 'SHA-384',
		cipher: 'AES-256-GCM',
	},
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: {
		identifier: new Uint8Array([ 0xc0, 0x13 ]),
		keyLength: 16,
		hashLength: 20,
		ivLength: 16,
		hashAlgorithm: 'SHA-1',
		prfHashAlgorithm: 'SHA-256',
		cipher: 'AES-128-CBC',
	},
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: {
		identifier: new Uint8Array([ 0xc0, 0x09 ]),
		keyLength: 16,
		hashLength: 20,
		ivLength: 16,
		hashAlgorithm: 'SHA-1',
		prfHashAlgorithm: 'SHA-256',
		cipher: 'AES-128-CBC',
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
	// TLS1.2
	DECRYPTION_FAILED_RESERVED: 21,
	DECOMPRESSION_FAILURE: 30,
	NO_CERTIFICATE_RESERVED: 41,
	EXPORT_RESTRICTION_RESERVED: 60,
	NO_RENEGOTIATION: 100,
}

export const SUPPORTED_CIPHER_SUITES = Object.keys(SUPPORTED_CIPHER_SUITE_MAP) as (keyof typeof SUPPORTED_CIPHER_SUITE_MAP)[]

export const SUPPORTED_SIGNATURE_ALGS_MAP = {
	RSA_PSS_RSAE_SHA256: {
		identifier: new Uint8Array([ 0x08, 0x04 ]),
		algorithm: 'RSA-PSS-SHA256',
	},
	ECDSA_SECP256R1_SHA256: {
		identifier: new Uint8Array([ 0x04, 0x03 ]),
		algorithm: 'ECDSA-SECP256R1-SHA256'
	},
	ED25519: {
		identifier: new Uint8Array([ 0x08, 0x07 ]),
		algorithm: 'ED25519'
	},
	RSA_PKCS1_SHA512: {
		identifier: new Uint8Array([ 0x06, 0x01 ]),
		algorithm: 'RSA-PKCS1-SHA512'
	},
} as const

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