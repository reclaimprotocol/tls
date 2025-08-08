import type { Logger, TLSPacketWithType, TLSProtocolVersion } from '../types/index.ts'
import { PACKET_TYPE, TLS_PROTOCOL_VERSION_MAP } from './constants.ts'
import { concatenateUint8Arrays, uint8ArrayToDataView } from './generics.ts'

type PacketType = keyof typeof PACKET_TYPE

export type PacketHeaderOptions = {
	type: PacketType
	/**
	 * TLS version to use in the header packet
	 * */
	version?: TLSProtocolVersion
}

export type PacketOptions = PacketHeaderOptions & {
	data: Uint8Array
}

export function packPacketHeader(
	dataLength: number,
	{ type, version = 'TLS1_2' }: PacketHeaderOptions
) {
	const lengthBuffer = new Uint8Array(2)
	const dataView = uint8ArrayToDataView(lengthBuffer)
	dataView.setUint16(0, dataLength)

	return concatenateUint8Arrays([
		new Uint8Array([ PACKET_TYPE[type] ]),
		TLS_PROTOCOL_VERSION_MAP[version],
		lengthBuffer
	])
}

export function packPacket(opts: PacketOptions) {
	return concatenateUint8Arrays([
		packPacketHeader(opts.data.length, opts),
		opts.data
	])
}

/**
 * Packs data prefixed with the length of the data;
 * Length encoded UInt24 big endian
 */
export function packWith3ByteLength(data: Uint8Array) {
	return concatenateUint8Arrays([
		new Uint8Array([ 0x00 ]),
		packWithLength(data)
	])
}

export function readWithLength(data: Uint8Array, lengthBytes = 2) {
	const dataView = uint8ArrayToDataView(data)
	const length = lengthBytes === 1
		? dataView.getUint8(0)
		: dataView.getUint16(lengthBytes === 3 ? 1 : 0)
	if(data.length < lengthBytes + length) {
		return undefined
	}

	return data.slice(lengthBytes, lengthBytes + length)
}

/**
 * Read a prefix of the data, that is prefixed with the length of
 * said data. Throws an error if the data is not long enough
 *
 * @param data total data to read from
 * @param lengthBytes number of bytes to read the length from.
 * Default is 2 bytes
 */
export function expectReadWithLength(data: Uint8Array, lengthBytes = 2) {
	const result = readWithLength(data, lengthBytes)
	if(!result) {
		throw new Error(`Expected packet to have at least ${data.length + lengthBytes} bytes, got ${data.length}`)
	}

	return result
}

/**
 * Packs data prefixed with the length of the data;
 * Length encoded UInt16 big endian
 */
export function packWithLength(data: Uint8Array) {
	const buffer = new Uint8Array(2 + data.length)
	const dataView = uint8ArrayToDataView(buffer)
	dataView.setUint16(0, data.length)
	buffer.set(data, 2)

	return buffer
}

// const SUPPORTED_PROTO_VERSIONS = [
// 	LEGACY_PROTOCOL_VERSION,
// 	CURRENT_PROTOCOL_VERSION,
// ]

/**
 * Processes an incoming stream of TLS packets
 */
export function makeMessageProcessor(logger: Logger) {
	let currentMessageType: number | undefined = undefined
	let currentMessageHeader: Uint8Array | undefined = undefined
	let buffer: Uint8Array = new Uint8Array(0)
	let bytesLeft = 0

	return {
		getPendingBuffer() {
			return buffer
		},
		/**
		 * @param packet TLS packet;
		 * can be multiple packets concatenated
		 * or incomplete packet
		 * or a single packet
		 * @param onChunk handle a complete packet
		 */
		*onData(packet: Uint8Array) {
			buffer = concatenateUint8Arrays([ buffer, packet ])
			while(buffer.length) {
				// if we already aren't processing a packet
				// this is the first byte
				if(!currentMessageType) {
					if(buffer.length < 5) {
						// we don't have enough bytes to process the header
						// wait for more bytes
						break
					}

					// bytes[0] tells us which packet type we're processing
					// bytes[1:2] tell us the protocol version
					// bytes[3:4] tell us the length of the packet
					const packTypeNum = buffer[0]
					currentMessageType = packTypeNum

					// get the number of bytes we need to process
					// to complete the packet
					const buffDataView = uint8ArrayToDataView(buffer)
					bytesLeft = buffDataView.getUint16(3)
					currentMessageHeader = buffer.slice(0, 5)

					// const protoVersion = currentMessageHeader.slice(1, 3)
					// const isSupportedVersion = SUPPORTED_PROTO_VERSIONS
					// 	.some((v) => areUint8ArraysEqual(v, protoVersion))

					// if(!isSupportedVersion) {
					// 	throw new Error(`Unsupported protocol version (${protoVersion})`)
					// }

					// remove the packet header
					buffer = buffer.slice(5)
					logger.trace(
						{ bytesLeft, recvBuffer: buffer.length, type: currentMessageType },
						'starting processing packet'
					)
				}

				if(buffer.length < bytesLeft) {
					// we don't have enough bytes to process the packet
					// wait for more bytes
					break
				}

				const body = buffer.slice(0, bytesLeft)

				logger.trace({ type: currentMessageType }, 'got complete packet')
				const pktWithType: TLSPacketWithType = {
					type: currentMessageType,
					packet: {
						header: currentMessageHeader!,
						content: body
					}
				}

				currentMessageType = undefined

				// if the current chunk we have still has bytes left
				// then that means we have another packet in the chunk
				// this will be processed in the next iteration of the loop
				buffer = buffer.slice(body.length)

				yield pktWithType
			}
		},
		reset() {
			currentMessageType = undefined
			currentMessageHeader = undefined
			buffer = new Uint8Array(0)
			bytesLeft = 0
		}
	}
}