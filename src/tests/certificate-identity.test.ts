import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'
import { verifyCertificateChain } from '../utils/parse-certificate.ts'
import { loadX509FromPem } from '../utils/x509.ts'
import { logger } from './utils.ts'

const ipSanCertificate = loadFixture('fixtures-ip-san.generated.pem')
const ipDnsCertificate = loadFixture('fixtures-ip-cn-dns-san.generated.pem')

describe('certificate IP identity verification', () => {
	it('extracts real IP address SANs', () => {
		assert.deepEqual(
			ipSanCertificate.getAlternativeIPAddresses(),
			['192.0.2.10', '2001:db8::1']
		)
	})

	it('accepts an exact IPv4 IP address SAN', async() => {
		await verifyFixture(ipSanCertificate, '192.0.2.10')
	})

	it('rejects a mismatched IPv4 IP address SAN', async() => {
		await assertHostRejected(ipSanCertificate, '192.0.2.11')
	})

	it('accepts equivalent expanded IPv6 identity bytes', async() => {
		await verifyFixture(
			ipSanCertificate,
			'2001:0db8:0:0:0:0:0:1'
		)
	})

	it('rejects a different IPv6 identity', async() => {
		await assertHostRejected(ipSanCertificate, '2001:db8::2')
	})

	it('rejects an IP-valued CN and DNS SAN without an IP SAN', async() => {
		assert.deepEqual(ipDnsCertificate.getAlternativeIPAddresses(), [])
		await assertHostRejected(ipDnsCertificate, '192.0.2.10')
	})

	it('does not apply wildcard matching to an IP identity', async() => {
		assert.ok(
			ipSanCertificate.getAlternativeDNSNames().includes('*.*.*.*')
		)
		await assertHostRejected(ipSanCertificate, '203.0.113.7')
	})

	it('keeps IPv4 and IPv4-mapped IPv6 identities distinct', async() => {
		await assertHostRejected(ipSanCertificate, '::ffff:192.0.2.10')
	})

	it('preserves DNS identity matching', async() => {
		await verifyFixture(ipSanCertificate, 'www.example.test')
	})
})

function loadFixture(file: string) {
	return loadX509FromPem(
		readFileSync(new URL(file, import.meta.url), 'utf8')
	)
}

async function verifyFixture(
	certificate: typeof ipSanCertificate,
	host: string
) {
	await verifyCertificateChain(
		[certificate],
		host,
		logger,
		undefined,
		[certificate]
	)
}

async function assertHostRejected(
	certificate: typeof ipSanCertificate,
	host: string
) {
	await assert.rejects(
		() => verifyFixture(certificate, host),
		new Error(`Certificate is not for host ${host}`)
	)
}
