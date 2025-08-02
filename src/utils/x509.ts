import * as peculiar from '@peculiar/x509'
import { SubjectAlternativeNameExtension } from '@peculiar/x509'
// not using types/index to avoid circular dependency
import type { X509Certificate } from '../types'
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
		isWithinValidity() {
			const now = new Date()
			return now > cert.notBefore && now < cert.notAfter
		},
		getSubjectField(name) {
			return cert.subjectName.getField(name)
		},
		getAlternativeDNSNames(): string[] {
			//search for names in SubjectAlternativeNameExtension
			const ext = cert.extensions.find(e => e.type === '2.5.29.17') //subjectAltName
			if(ext instanceof SubjectAlternativeNameExtension) {
				return ext.names.items.filter(n => n.type === 'dns').map(n => n.value)
			}

			return []
		},
		isIssuer({ internal: ofCert }) {
			var i = ofCert.issuer
			var s = cert.subject

			return i === s
		},
		getPublicKeyAlgorithm() {
			return cert.publicKey.algorithm
		},
		getPublicKey() {
			return {
				buffer: new Uint8Array(cert.publicKey.rawData),
				algorithm: cert.publicKey.algorithm.name,
			}
		},
		verifyIssued(otherCert) {
			return otherCert.internal.verify({ publicKey: cert.publicKey })
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