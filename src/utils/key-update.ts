import { KEY_UPDATE_TYPE_MAP, SUPPORTED_RECORD_TYPE_MAP } from './constants'
import { packWithLength } from './packets'

export function packKeyUpdateRecord(type: keyof typeof KEY_UPDATE_TYPE_MAP) {
	const encoded = packWithLength(Buffer.from([ KEY_UPDATE_TYPE_MAP[type] ]))
	const packet = Buffer.concat([
		Buffer.from([
			SUPPORTED_RECORD_TYPE_MAP.KEY_UPDATE,
			0x00,
		]),
		encoded
	])

	return packet
}