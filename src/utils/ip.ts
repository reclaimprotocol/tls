export type HostIdentity = {
	type: 'dns'
	value: string
} | {
	type: 'ip'
	value: Uint8Array
}

export function classifyHostIdentity(value: string): HostIdentity {
	const ip = parseIpLiteral(value)
	if(ip) {
		return { type: 'ip', value: ip }
	}

	if(!isDnsIdentity(value)) {
		throw new Error(`Invalid TLS host identity ${value}`)
	}

	return { type: 'dns', value }
}

function parseIpLiteral(value: string): Uint8Array | null {
	return parseIpv4(value) || parseIpv6(value)
}

function isDnsIdentity(value: string) {
	if(
		!value
		|| /\s/.test(value)
		|| value.includes(':')
		|| value.includes('%')
		|| value.startsWith('[')
		|| value.endsWith(']')
	) {
		return false
	}

	const labels = value.split('.')
	return !labels.every(label => (
		/^(?:[+-]?(?:\d+|0x[0-9a-f]+))?$/i.test(label)
	))
}

function parseIpv4(value: string): Uint8Array | null {
	const components = value.split('.')
	if(components.length !== 4) {
		return null
	}

	const result = new Uint8Array(4)
	for(const [i, component] of components.entries()) {
		if(
			!/^\d+$/.test(component)
			|| (component.length > 1 && component[0] === '0')
		) {
			return null
		}

		const number = Number(component)
		if(number > 255) {
			return null
		}

		result[i] = number
	}

	return result
}

function parseIpv6(value: string): Uint8Array | null {
	if(!value.includes(':') || value.includes('%')) {
		return null
	}

	const compressionIndex = value.indexOf('::')
	if(compressionIndex !== value.lastIndexOf('::')) {
		return null
	}

	const hasCompression = compressionIndex !== -1
	const sides = hasCompression ? value.split('::') : [value]
	const left = parseIpv6Side(sides[0], !hasCompression)
	const right = hasCompression ? parseIpv6Side(sides[1], true) : []
	if(!left || !right) {
		return null
	}

	const groupCount = left.length + right.length
	if(
		(hasCompression && groupCount >= 8)
		|| (!hasCompression && groupCount !== 8)
	) {
		return null
	}

	const groups = hasCompression
		? [
			...left,
			...new Array<number>(8 - groupCount).fill(0),
			...right
		]
		: left
	const result = new Uint8Array(16)
	for(const [i, group] of groups.entries()) {
		result[i * 2] = group >>> 8
		result[i * 2 + 1] = group & 0xff
	}

	return result
}

function parseIpv6Side(value: string, canContainIpv4: boolean): number[] | null {
	if(!value) {
		return []
	}

	const components = value.split(':')
	if(components.some(component => !component)) {
		return null
	}

	const groups: number[] = []
	for(const [i, component] of components.entries()) {
		if(component.includes('.')) {
			if(!canContainIpv4 || i !== components.length - 1) {
				return null
			}

			const ipv4 = parseIpv4(component)
			if(!ipv4) {
				return null
			}

			groups.push(
				(ipv4[0] << 8) | ipv4[1],
				(ipv4[2] << 8) | ipv4[3]
			)
			continue
		}

		if(!/^[0-9a-f]{1,4}$/i.test(component)) {
			return null
		}

		groups.push(Number.parseInt(component, 16))
	}

	return groups
}
