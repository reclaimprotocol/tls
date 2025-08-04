import assert from 'node:assert'
import { describe, it } from 'node:test'
import type { TLSPacket } from '../types/index.ts'
import { logger } from '../utils/index.ts'
import { makeMessageProcessor } from '../utils/index.ts'
import { expectBuffsEq } from './utils.ts'

describe('TLS Message Processor', () => {

	it('should process a complete message', async() => {
		const processor = makeTestMsgProcessor()
		const pkts = await processor.onData(
			Buffer.from('15030300050101010101', 'hex')
		)
		assert.equal(pkts.length, 1)
		expectBuffsEq(pkts[0].header, Buffer.from('1503030005', 'hex'))
		expectBuffsEq(pkts[0].content, Buffer.from('0101010101', 'hex'))
	})

	it('should process a message byte-by-byte', async() => {
		const processor = makeTestMsgProcessor()
		const buffer = Buffer.from('15030300050101010101', 'hex')
		for(let i = 0;i < buffer.length;i++) {
			const pkts = await processor.onData(buffer.subarray(i, i + 1))
			if(i < buffer.length - 1) {
				assert.equal(pkts.length, 0)
			} else {
				assert.equal(pkts.length, 1)
				expectBuffsEq(pkts[0].content, Buffer.from('0101010101', 'hex'))
			}
		}
	})

	it('should process multiple messages', async() => {
		const processor = makeTestMsgProcessor()
		const buffers = [
			Buffer.from('15030300050101010101', 'hex'),
			Buffer.from('1503030006010101010101', 'hex')
		]
		const pkts = await processor.onData(Buffer.concat(buffers))
		assert.equal(pkts.length, 2)
		expectBuffsEq(pkts[0].content, Buffer.from('0101010101', 'hex'))
		expectBuffsEq(pkts[1].content, Buffer.from('010101010101', 'hex'))
	})

	it('should process a message and a half', async() => {
		const processor = makeTestMsgProcessor()
		const msgAndHalfBuffer = Buffer.concat(
			[
				Buffer.from('15030300050101010101', 'hex'),
				Buffer.from('1503030006', 'hex')
			]
		)
		const finalBuffer = Buffer.from('010101010101', 'hex')
		const pkts = await processor.onData(msgAndHalfBuffer)
		assert.equal(pkts.length, 1)
		const pkts2 = await processor.onData(finalBuffer)
		assert.equal(pkts2.length, 1)
	})

	// eslint-disable-next-line unicorn/consistent-function-scoping
	function makeTestMsgProcessor() {
		const processor = makeMessageProcessor(logger)

		return {
			...processor,
			async onData(packet: Buffer) {
				const packets: TLSPacket[] = []
				await processor.onData(
					packet,
					(_, pkt) => {
						packets.push(pkt)
					}
				)

				return packets
			}
		}
	}
})