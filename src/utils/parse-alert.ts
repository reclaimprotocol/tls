import { ALERT_DESCRIPTION, ALERT_LEVEL } from './constants'
import { uint8ArrayToDataView } from './generics'

const ALERT_LEVEL_ENTRIES = Object
	.entries(ALERT_LEVEL) as [keyof typeof ALERT_LEVEL, number][]

const ALERT_DESCRIPTION_ENTRIES = Object
	.entries(ALERT_DESCRIPTION) as [keyof typeof ALERT_DESCRIPTION, number][]

/**
 * Parse a TLS alert message
 */
export function parseTlsAlert(buffer: Uint8Array) {
	const view = uint8ArrayToDataView(buffer)
	const level = view.getUint8(0)
	const description = view.getUint8(1)

	const levelStr = ALERT_LEVEL_ENTRIES
		.find(([, value]) => value === level)?.[0]
	if(!levelStr) {
		throw new Error(`Unknown alert level ${level}`)
	}

	const descriptionStr = ALERT_DESCRIPTION_ENTRIES
		.find(([, value]) => value === description)?.[0]
	if(!descriptionStr) {
		throw new Error(`Unknown alert description ${description}`)
	}

	return {
		level: levelStr,
		description: descriptionStr
	}
}