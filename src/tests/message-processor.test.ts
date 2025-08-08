import assert from 'node:assert'
import { beforeEach, describe, it } from 'node:test'
import type { PacketProcessor, TLSPacket, TLSPacketWithType } from '../types/index.ts'
import { logger } from '../utils/index.ts'
import { makeMessageProcessor } from '../utils/index.ts'
import { expectBuffsEq } from './utils.ts'

describe('TLS Message Processor', () => {

	let processor: PacketProcessor
	beforeEach(() => {
		processor = makeMessageProcessor(logger)
	})

	it('should process a complete message', () => {
		const pkts = Array.from(
			processor.onData(Buffer.from('15030300050101010101', 'hex'))
		)
		assert.equal(pkts.length, 1)
		expectBuffsEq(pkts[0].packet.header, Buffer.from('1503030005', 'hex'))
		expectBuffsEq(pkts[0].packet.content, Buffer.from('0101010101', 'hex'))
	})

	it('should process a message byte-by-byte', () => {
		const buffer = Buffer.from('15030300050101010101', 'hex')
		for(let i = 0;i < buffer.length;i++) {
			const pkts = Array.from(processor.onData(buffer.subarray(i, i + 1)))
			if(i < buffer.length - 1) {
				assert.equal(pkts.length, 0)
			} else {
				assert.equal(pkts.length, 1)
				expectBuffsEq(pkts[0].packet.content, Buffer.from('0101010101', 'hex'))
			}
		}
	})

	it('should process multiple messages', async() => {
		const buffers = [
			Buffer.from('15030300050101010101', 'hex'),
			Buffer.from('1503030006010101010101', 'hex')
		]
		const pkts = Array.from(processor.onData(Buffer.concat(buffers)))
		assert.equal(pkts.length, 2)
		expectBuffsEq(pkts[0].packet.content, Buffer.from('0101010101', 'hex'))
		expectBuffsEq(pkts[1].packet.content, Buffer.from('010101010101', 'hex'))
	})

	it('should process a message and a half', async() => {
		const msgAndHalfBuffer = Buffer.concat(
			[
				Buffer.from('15030300050101010101', 'hex'),
				Buffer.from('1503030006', 'hex')
			]
		)
		const finalBuffer = Buffer.from('010101010101', 'hex')
		const pkts = Array.from(processor.onData(msgAndHalfBuffer))
		assert.equal(pkts.length, 1)
		const pkts2 = Array.from(processor.onData(finalBuffer))
		assert.equal(pkts2.length, 1)
	})
})