import { TLSPacket } from '../types'
import { logger } from '../utils'
import { makeMessageProcessor } from '../utils'
import { expectBuffsEq } from './utils'

describe('TLS Message Processor', () => {

	it('should process a complete message', () => {
		const processor = makeTestMsgProcessor()
		const pkts = processor.onData(
			Buffer.from('15030300050101010101', 'hex')
		)
		expect(pkts.length).toBe(1)
		expectBuffsEq(pkts[0].header, Buffer.from('1503030005', 'hex'))
		expectBuffsEq(pkts[0].content, Buffer.from('0101010101', 'hex'))
	})

	it('should process a message byte-by-byte', () => {
		const processor = makeTestMsgProcessor()
		const buffer = Buffer.from('15030300050101010101', 'hex')
		for(let i = 0;i < buffer.length;i++) {
			const pkts = processor.onData(buffer.subarray(i, i + 1))
			if(i < buffer.length - 1) {
				expect(pkts.length).toBe(0)
			} else {
				expect(pkts.length).toBe(1)
				expectBuffsEq(pkts[0].content, Buffer.from('0101010101', 'hex'))
			}
		}
	})

	it('should process multiple messages', () => {
		const processor = makeTestMsgProcessor()
		const buffers = [
			Buffer.from('15030300050101010101', 'hex'),
			Buffer.from('1503030006010101010101', 'hex')
		]
		const pkts = processor.onData(
			Buffer.concat(buffers)
		)
		expect(pkts.length).toBe(2)
		expectBuffsEq(pkts[0].content, Buffer.from('0101010101', 'hex'))
		expectBuffsEq(pkts[1].content, Buffer.from('010101010101', 'hex'))
	})

	it('should process a message and a half', () => {
		const processor = makeTestMsgProcessor()
		const msgAndHalfBuffer = Buffer.concat(
			[
				Buffer.from('15030300050101010101', 'hex'),
				Buffer.from('1503030006', 'hex')
			]
		)
		const finalBuffer = Buffer.from('010101010101', 'hex')
		const pkts = processor.onData(msgAndHalfBuffer)
		expect(pkts.length).toBe(1)

		const pkts2 = processor.onData(finalBuffer)
		expect(pkts2.length).toBe(1)
	})

	// eslint-disable-next-line unicorn/consistent-function-scoping
	function makeTestMsgProcessor() {
		const processor = makeMessageProcessor(logger)

		return {
			...processor,
			onData(packet: Buffer) {
				const packets: TLSPacket[] = []
				processor.onData(
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