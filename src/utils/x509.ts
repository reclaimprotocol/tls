import * as peculiar from '@peculiar/x509'
// not using types/index to avoid circular dependency
import type { X509Certificate } from '../types/x509'

export function loadX509FromPem(pem: string | Buffer): X509Certificate<peculiar.X509Certificate> {
	setCryptoIfRequired()
	let cert: peculiar.X509Certificate
	try {
		cert = new peculiar.X509Certificate(pem)
	} catch(e) {
		throw new Error(`Unsupported certificate: ${e}`)
	}

	return {
		internal: cert,
		isIssuer({ internal: ofCert }) {
			var i = ofCert.issuer
			var s = cert.subject

			return i === s
		},
		getPublicKey() {
			return Buffer.from(cert.publicKey.rawData)
		},
		verifyIssued(otherCert) {
			return otherCert.internal.verify({
				publicKey: cert.publicKey
			})
		},
		serialiseToPem() {
			return cert.toString('pem')
		},
	}
}

export function loadX509FromDer(der: Buffer) {
	const PEM_PREFIX = '-----BEGIN CERTIFICATE-----\n'
	const PEM_POSTFIX = '-----END CERTIFICATE-----'

	const splitText = der.toString('base64').match(/.{0,64}/g)!.join('\n')
	const pem = `${PEM_PREFIX}${splitText}${PEM_POSTFIX}`
	return loadX509FromPem(pem)
}

export function getWebCrypto() {
	setCryptoIfRequired()
	return peculiar.cryptoProvider.get()
}

let setCrypto = false
function setCryptoIfRequired() {
	if(!setCrypto) {
		// const envType = detectEnvironment()
		// if(envType === 'node') {
			const { webcrypto } = require('crypto')
			peculiar.cryptoProvider.set(webcrypto)
		// }

		setCrypto = true
	}
}