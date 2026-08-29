import * as peculiar from '@peculiar/x509'
import assert from 'node:assert'
import { webcrypto } from 'node:crypto'
import { describe, it } from 'node:test'
import type { X509Certificate } from '../types/index.ts'
import { loadX509FromDer, verifyCertificateChain } from '../utils/index.ts'
import { logger } from './utils.ts'

type MockCertificate = X509Certificate<{
	issuer: string
	issuerName: peculiar.Name
	subject: string
	subjectName: peculiar.Name
}>

describe('Certificate chain verification', () => {
	it('stops at the first trusted anchor in a cross-signed chain', async() => {
		const verifiedBy: string[] = []
		const leaf = makeMockCertificate(
			'www.example.com',
			'Intermediate CA',
			['www.example.com'],
			verifiedBy
		)
		const intermediate = makeMockCertificate(
			'Intermediate CA',
			'Trusted Root',
			[],
			verifiedBy
		)
		const crossSignedRoot = makeMockCertificate(
			'Trusted Root',
			'Legacy Root',
			[],
			verifiedBy
		)
		const legacyRoot = makeMockCertificate(
			'Legacy Root',
			'Legacy Root',
			[],
			verifiedBy
		)
		const trustedRoot = makeMockCertificate(
			'Trusted Root',
			'Trusted Root',
			[],
			verifiedBy
		)

		await verifyCertificateChain(
			[leaf, intermediate, crossSignedRoot, legacyRoot],
			'www.example.com',
			logger,
			async() => {
				throw new Error('AIA fetch should not be called')
			},
			[trustedRoot]
		)

		assert.deepEqual(verifiedBy, [
			'www.example.com -> Intermediate CA',
			'Intermediate CA -> Trusted Root',
		])
	})

	it('matches normalized issuer names and authority key identifiers', async() => {
		const algorithm = {
			name: 'ECDSA',
			namedCurve: 'P-256',
		}
		const signingAlgorithm = {
			name: 'ECDSA',
			hash: 'SHA-256',
		}
		const issuerKeys = await webcrypto.subtle.generateKey(
			algorithm,
			true,
			['sign', 'verify']
		)
		const otherIssuerKeys = await webcrypto.subtle.generateKey(
			algorithm,
			true,
			['sign', 'verify']
		)
		const leafKeys = await webcrypto.subtle.generateKey(
			algorithm,
			true,
			['sign', 'verify']
		)
		const subjectKeyId = await peculiar.SubjectKeyIdentifierExtension
			.create(issuerKeys.publicKey, false, webcrypto)
		const authorityKeyId = await peculiar.AuthorityKeyIdentifierExtension
			.create(issuerKeys.publicKey, false, webcrypto)
		const otherSubjectKeyId = await peculiar.SubjectKeyIdentifierExtension
			.create(otherIssuerKeys.publicKey, false, webcrypto)
		const validity = {
			notBefore: new Date('2020-01-01T00:00:00Z'),
			notAfter: new Date('2030-01-01T00:00:00Z'),
		}
		const issuer = await peculiar.X509CertificateGenerator.createSelfSigned({
			serialNumber: '01',
			name: 'CN=Example CA',
			keys: issuerKeys,
			signingAlgorithm,
			extensions: [subjectKeyId],
			...validity,
		}, webcrypto)
		const otherIssuer = await peculiar.X509CertificateGenerator
			.createSelfSigned({
				serialNumber: '02',
				name: 'CN=EXAMPLE CA',
				keys: otherIssuerKeys,
				signingAlgorithm,
				extensions: [otherSubjectKeyId],
				...validity,
			}, webcrypto)
		const leaf = await peculiar.X509CertificateGenerator.create({
			serialNumber: '03',
			subject: 'CN=www.example.com',
			issuer: 'CN=  example   ca  ',
			publicKey: leafKeys.publicKey,
			signingKey: issuerKeys.privateKey,
			signingAlgorithm,
			extensions: [authorityKeyId],
			...validity,
		}, webcrypto)
		const wrappedIssuer = loadX509FromDer(new Uint8Array(issuer.rawData))
		const wrappedOtherIssuer = loadX509FromDer(
			new Uint8Array(otherIssuer.rawData)
		)
		const wrappedLeaf = loadX509FromDer(new Uint8Array(leaf.rawData))

		assert.equal(wrappedIssuer.isIssuer(wrappedLeaf), true)
		assert.equal(wrappedOtherIssuer.isIssuer(wrappedLeaf), false)
		await verifyCertificateChain(
			[wrappedLeaf],
			'www.example.com',
			logger,
			async() => {
				throw new Error('AIA fetch should not be called')
			},
			[wrappedIssuer]
		)
	})
})

function makeMockCertificate(
	subject: string,
	issuer: string,
	commonNames: string[],
	verifiedBy: string[]
): MockCertificate {
	return {
		internal: {
			issuer,
			issuerName: new peculiar.Name(`CN=${issuer}`),
			subject,
			subjectName: new peculiar.Name(`CN=${subject}`),
		},
		isWithinValidity: () => true,
		getAIAExtension: () => undefined,
		getSubjectField: field => field === 'CN' ? commonNames : [],
		getAlternativeDNSNames: () => [],
		isIssuer: cert => cert.internal.issuer === subject,
		getPublicKey: () => ({
			algorithm: 'mock',
			buffer: new Uint8Array(),
		}),
		verifyIssued: cert => {
			verifiedBy.push(`${cert.internal.subject} -> ${subject}`)
			return cert.internal.issuer === subject
		},
		serialiseToPem: () => subject,
	}
}
