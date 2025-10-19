import * as peculiar from '@peculiar/x509'
import { SubjectAlternativeNameExtension } from '@peculiar/x509'
import { crypto } from '../crypto/index.ts'
// not using types/index to avoid circular dependency
import type { SignatureAlgorithm, X509Certificate } from '../types/index.ts'

export function loadX509FromPem(
	pem: string | Uint8Array
): X509Certificate<peculiar.X509Certificate> {
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
			// search for names in SubjectAlternativeNameExtension
			const ext = cert.extensions
				.find(e => e.type === '2.5.29.17') //subjectAltName
			if(ext instanceof SubjectAlternativeNameExtension) {
				return ext.names.items
					.filter(n => n.type === 'dns')
					.map(n => n.value)
			}

			return []
		},
		isIssuer({ internal: ofCert }) {
			var i = ofCert.issuer
			var s = cert.subject

			return i === s
		},
		getPublicKey() {
			return {
				buffer: new Uint8Array(cert.publicKey.rawData),
				algorithm: cert.publicKey.algorithm.name,
			}
		},
		async verifyIssued(otherCert) {
			const sigAlg = getSigAlgorithm(cert.publicKey, otherCert.internal)
			const impPublicKey = await crypto
				.importKey(sigAlg, new Uint8Array(cert.publicKey.rawData), 'public')
			const signature = new Uint8Array(otherCert.internal.signature)
			const verified = await crypto.verify(sigAlg, {
				publicKey: impPublicKey,
				signature,
				data: new Uint8Array(otherCert.internal['tbs'])
			})
			return verified
		},
		serialiseToPem() {
			return cert.toString('pem')
		},
	}
}

function getSigAlgorithm(
	key: peculiar.PublicKey, { signatureAlgorithm }: peculiar.X509Certificate
): SignatureAlgorithm {
	if(!('name' in signatureAlgorithm)) {
		throw new Error('Missing signature algorithm name')
	}

	const { name, hash } = signatureAlgorithm

	const { algorithm: keyAlg } = key
	if(keyAlg.name !== name) {
		throw new Error(
			`Signature algorithm ${name} does not match`
			+ ` public key algorithm ${keyAlg.name}`
		)
	}

	let hashName: 'SHA256' | 'SHA384' | 'SHA512'
	switch (hash.name) {
	case 'SHA-256':
		hashName = 'SHA256'
		break
	case 'SHA-384':
		hashName = 'SHA384'
		break
	case 'SHA-512':
		hashName = 'SHA512'
		break
	default:
		throw new Error(`Unsupported hash algorithm: ${hash.name}`)
	}

	switch (name) {
	case 'RSASSA-PKCS1-v1_5':
		return `RSA-PKCS1-${hashName}`
	case 'ECDSA':
		if(hashName === 'SHA512') {
			throw new Error(`Unsupported hash algorithm for ECDSA: ${hashName}`)
		}

		switch (keyAlg.namedCurve) {
		case 'P-256':
			return `ECDSA-SECP256R1-${hashName}`
		case 'P-384':
			return `ECDSA-SECP384R1-${hashName}`
		default:
			throw new Error(`Unsupported named curve: ${keyAlg.namedCurve}`)
		}

	default:
		throw new Error(`Unsupported signature algorithm: ${name}`)
	}
}

export function loadX509FromDer(der: Uint8Array) {
	// peculiar handles both
	return loadX509FromPem(der)
}