import assert from 'node:assert'
import { X509Certificate } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'

const MIN_REMAINING_VALIDITY_MS = 365 * 24 * 60 * 60 * 1000
const FIXTURES = [
	'../../cert/public-cert.pem',
	'fixtures-ip-san.generated.pem',
	'fixtures-ip-cn-dns-san.generated.pem',
]

describe('certificate fixture validity', () => {
	for(const file of FIXTURES) {
		it(`${file} remains valid for at least one year`, () => {
			const certificate = new X509Certificate(
				readFileSync(new URL(file, import.meta.url), 'utf8')
			)
			const expiresAt = new Date(certificate.validTo)
			const remainingValidity = expiresAt.getTime() - Date.now()

			assert.ok(
				remainingValidity >= MIN_REMAINING_VALIDITY_MS,
				`${file} expires on ${expiresAt.toISOString()}`
			)
		})
	}
})
