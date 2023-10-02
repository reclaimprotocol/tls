import Chance from 'chance'
import { Socket } from 'net'
import { TLSClientOptions, TLSPresharedKey } from '../types'
import { makeTLSClient, toHexStringWithWhitespace } from '../'
import { createMockTLSServer } from './mock-tls-server'
import { delay } from './utils'

const chance = new Chance()

describe('TLS 1.2 Tests', () => {

	const port = chance.integer({ min: 10000, max: 20000 })
	const srv = createMockTLSServer(port)

	beforeAll(async() => {
		await delay(200)
	})

	afterAll(() => {
		srv.server.close()
	})

	it('should negotiate a TLS 1.2 connection', async() => {
		const { tls, socket } = connectTLS({
			supportedProtocolVersions: ['TLS1_2']
		})

		while(!tls.isHandshakeDone()) {
			await delay(100)

			if(socket.readableEnded) {
				throw new Error('unexpectedly terminated')
			}
		}

		socket.end()

		expect(tls.getSessionId()).toBeDefined()
		expect(tls.getKeys()?.clientEncKey).toBeDefined()
		await tls.end()
	})


	function connectTLS(
		opts?: Partial<TLSClientOptions>,
		psk?: TLSPresharedKey
	) {
		const socket = new Socket()
		const host = 'localhost'
		socket.connect({ host, port })

		const tls = makeTLSClient({
			host,
			verifyServerCertificate: false,
			async write({ header, content, authTag }) {
				console.log(
					toHexStringWithWhitespace(
						Buffer.concat([
							header,
							content,
							authTag || Buffer.from([])
						])
					)
				)
				socket.write(header)
				socket.write(content)
				if(authTag) {
					socket.write(authTag)
				}
			},
			...opts,
		})

		socket.on('data', tls.handleReceivedBytes)

		socket.on('connect', () => tls.startHandshake({ psk }))

		return { tls, socket }
	}
})