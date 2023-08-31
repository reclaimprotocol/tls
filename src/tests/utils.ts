export function delay(ms: number) {
	return new Promise((resolve) => setTimeout(resolve, ms))
}

export function expectBuffsEq(a: Uint8Array, b: Uint8Array) {
	expect(
		Array.from(a)
	).toEqual(
		Array.from(b)
	)
}