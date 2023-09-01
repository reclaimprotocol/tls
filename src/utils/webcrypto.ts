import type { webcrypto as Crypto } from 'crypto'

export const webcrypto = (() => {
	// if we're in node, we need to use
	// webcrypto provided by the crypto module
	if(typeof window === 'undefined') {
		const { webcrypto } = require('crypto')
		return webcrypto as Crypto
	}

	return window.crypto
})()