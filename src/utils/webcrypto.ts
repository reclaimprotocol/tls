import type { webcrypto as WebCrypto } from 'crypto'

declare global {
	interface CryptoHolder {
		crypto?: WebCrypto.Crypto
	}

	const window: CryptoHolder
	const self: CryptoHolder
}

export const webcrypto = (() => {
	// if we're in node, we need to use
	// webcrypto provided by the crypto module
	if(typeof window !== 'undefined' && window.crypto) {
		return window.crypto
	}

	if(typeof self !== 'undefined' && self.crypto) {
		return self.crypto
	}

	const { webcrypto } = require('crypto')
	return webcrypto as WebCrypto.Crypto
})()