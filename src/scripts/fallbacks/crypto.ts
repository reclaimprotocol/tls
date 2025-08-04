import { randomBytes } from '../../crypto/insecure-rand.ts'

export const crypto = { getRandomValues: randomBytes }