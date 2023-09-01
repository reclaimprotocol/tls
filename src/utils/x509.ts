import * as peculiar from '@peculiar/x509'
// not using types/index to avoid circular dependency
import type { X509Certificate } from '../types/x509'
import { webcrypto } from './webcrypto'

peculiar.cryptoProvider.set(webcrypto)

export function loadX509FromPem(pem: string | Uint8Array): X509Certificate<peculiar.X509Certificate> {
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
			return new Uint8Array(cert.publicKey.rawData)
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

export function loadX509FromDer(der: Uint8Array) {
	// const PEM_PREFIX = '-----BEGIN CERTIFICATE-----\n'
	// const PEM_POSTFIX = '-----END CERTIFICATE-----'

	// const splitText = der.toString('base64').match(/.{0,64}/g)!.join('\n')
	// const pem = `${PEM_PREFIX}${splitText}${PEM_POSTFIX}`
	return loadX509FromPem(der)
}