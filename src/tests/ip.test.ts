import assert from 'node:assert'
import { describe, it } from 'node:test'
import { parseIpLiteral } from '../utils/ip.ts'

const ACCEPTED_IP_ADDRESSES = [
	['0.0.0.0', '00000000'],
	['192.0.2.10', 'c000020a'],
	['255.255.255.255', 'ffffffff'],
	['::', '00000000000000000000000000000000'],
	['::1', '00000000000000000000000000000001'],
	['2001:db8::1', '20010db8000000000000000000000001'],
	['2001:0db8:0:0:0:0:0:1', '20010db8000000000000000000000001'],
	['2001:db8:1:2:3:4:5:6', '20010db8000100020003000400050006'],
	['::ffff:192.0.2.10', '00000000000000000000ffffc000020a'],
] as const

const REJECTED_IP_ADDRESSES = [
	'',
	'192.0.2',
	'192.0.2.10.1',
	'192..2.10',
	'192.0.2.256',
	'192.0.-1.10',
	'192.0.+2.10',
	'192.00.2.10',
	'0xC0.0.2.10',
	'0300.0.2.10',
	' 192.0.2.10',
	'192.0.2.10 ',
	'192.0.2.10.',
	'2001:db8::1::1',
	'1:2:3:4:5:6:7:8:9',
	'1:2:3:4:5:6:7',
	'12345::1',
	'2001:db8::g',
	'::ffff:192.0.2.10:1',
	'::192.0.2.10:1',
	'2001:db8:192.0.2.10::',
	'2001:db8::1%eth0',
	'[2001:db8::1]',
]

describe('IP literal parser', () => {
	for(const [value, expected] of ACCEPTED_IP_ADDRESSES) {
		it(`parses ${value} to canonical bytes`, () => {
			const result = parseIpLiteral(value)
			assert.ok(result)
			assert.equal(Buffer.from(result).toString('hex'), expected)
		})
	}

	for(const value of REJECTED_IP_ADDRESSES) {
		it(`rejects ${JSON.stringify(value)}`, () => {
			assert.equal(parseIpLiteral(value), null)
		})
	}
})
