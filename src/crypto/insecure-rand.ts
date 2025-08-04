
export function randomBytes(length: number) {
	// not the most secure but has to do for an env
	// without crypto.getRandomValues
	const bytes = new Uint8Array(length)
	for(let i = 0; i < length; i++) {
		bytes[i] = Math.floor(Math.random() * 256) % 256
	}

	return bytes
}