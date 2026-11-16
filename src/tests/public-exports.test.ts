import assert from 'node:assert'
import { describe, it } from 'node:test'
import * as tls from '../index.ts'

describe('public exports', () => {
	it('keeps host identity parsing internal', () => {
		assert.equal('classifyHostIdentity' in tls, false)
		assert.equal('parseIpLiteral' in tls, false)
	})
})
