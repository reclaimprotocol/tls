export const webcrypto = (() => {
	// if we're in node, we need to use
	// webcrypto provided by the crypto module
	if(typeof window !== 'undefined') {
		return window.crypto
	}

	if(typeof self !== 'undefined' && self.crypto) {
		return self.crypto
	}

	const { webcrypto } = require('crypto')
	return webcrypto as Crypto
})()