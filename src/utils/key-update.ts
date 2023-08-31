import { KEY_UPDATE_TYPE_MAP, SUPPORTED_RECORD_TYPE_MAP } from './constants'
import { concatenateUint8Arrays } from './generics'
import { packWithLength } from './packets'

export function packKeyUpdateRecord(type: keyof typeof KEY_UPDATE_TYPE_MAP) {
	const encoded = packWithLength(new Uint8Array([ KEY_UPDATE_TYPE_MAP[type] ]))
	const packet = concatenateUint8Arrays([
		new Uint8Array([
			SUPPORTED_RECORD_TYPE_MAP.KEY_UPDATE,
			0x00,
		]),
		encoded
	])

	return packet
}