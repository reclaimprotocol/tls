import assert from 'node:assert'
import { describe, it } from 'node:test'
import { crypto } from '../crypto/index.ts'
import { packClientHello } from '../utils/client-hello.ts'
import { parseClientHello } from '../utils/parse-client-hello.ts'

const HOSTS = [
	['example.com', true],
	['192.0.2.10', false],
	['2001:db8::1', false],
] as const

describe('ClientHello server name', () => {
	for(const [host, hasServerName] of HOSTS) {
		it(`${hasServerName ? 'includes' : 'omits'} SNI for ${host}`, async() => {
			const keyPair = await crypto.generateKeyPair('X25519')
			const hello = await packClientHello({
				host,
				keysToShare: [{
					type: 'X25519',
					key: keyPair.pubKey
				}]
			})
			const serverName = parseClientHello(hello).extensions.SERVER_NAME

			if(hasServerName) {
				assert.equal(serverName?.serverName, host)
			} else {
				assert.equal(serverName, undefined)
			}
		})
	}
})
