import Chance from 'chance'
import { Socket } from 'net'
import { makeTLSClient } from '../'
import { TLSPresharedKey, TLSSessionTicket } from '../types'
import { createMockTLSServer } from './mock-tls-server'
import { delay } from './utils'
import { strToUint8Array } from '../utils/generics'
import { crypto } from '../crypto'

const chance = new Chance()

describe('TLS Tests', () => {
	const port = chance.integer({ min: 10000, max: 20000 })
	const srv = createMockTLSServer(port)

	beforeAll(async() => {
		await delay(200)
	})

	afterAll(() => {
		srv.server.close()
	})

	it('should do handshake with the server', async() => {
		const { tls, socket } = connectTLS()

		while(!tls.isHandshakeDone()) {
			await delay(100)

			if(socket.readableEnded) {
				throw new Error('unexpectedly terminated')
			}
		}

		socket.end()

		expect(tls.getSessionId()).toBeDefined()
		expect(tls.getKeys()?.clientEncKey).toBeDefined()
	})

	it('should send & recv data from the server', async() => {
		const { tls, socket } = connectTLS()

		while(!tls.isHandshakeDone()) {
			await delay(100)
		}

		const data = strToUint8Array('hello world')
		tls.write(data)

		const recvData = await new Promise<Uint8Array>(resolve => {
			tls.ev.on('data', data => {
				resolve(data.plaintext)
			})
		})

		expect(recvData).toEqual(data)

		socket.end()
	})

	it('should recv a session ticket', async() => {
		const { tls, socket } = connectTLS()

		const recvTicket = await new Promise<TLSSessionTicket>(resolve => {
			tls.ev.on('session-ticket', data => {
				resolve(data)
			})
		})
		expect(recvTicket.ticket).toBeDefined()
		expect(recvTicket.expiresAt).toBeDefined()

		socket.end()
	})

	it('should resume a session with ticket', async() => {
		const psk = await getPsk()
		const { tls, socket } = connectTLS(psk)

		while(!tls.isHandshakeDone()) {
			await delay(100)

			if(socket.readableEnded) {
				throw new Error('unexpectedly terminated')
			}
		}

		const data = strToUint8Array('hello resumed session')
		tls.write(data)

		const recvData = await new Promise<Uint8Array>(resolve => {
			tls.ev.on('data', data => {
				resolve(data.plaintext)
			})
		})

		expect(recvData).toEqual(data)

		socket.end()

		async function getPsk() {
			const { tls, socket } = connectTLS()
			const sessionTicket = await new Promise<TLSSessionTicket>(resolve => {
				tls.ev.on('session-ticket', data => {
					resolve(data)
				})
			})

			socket.end()

			const psk = tls.getPskFromTicket(sessionTicket)

			await delay(100)

			await tls.end()

			return psk
		}
	})

	it('should update traffic keys', async() => {
		const { tls, socket } = connectTLS()

		while(!tls.isHandshakeDone()) {
			await delay(100)
		}

		const oldKey = tls.getKeys()?.clientEncKey
		expect(oldKey).toBeDefined()
		await tls.updateTrafficKeys(true)

		const data = strToUint8Array('hello world')
		await tls.write(data)

		const recvData = await new Promise<Uint8Array>(resolve => {
			tls.ev.on('data', data => {
				resolve(data.plaintext)
			})
		})

		expect(recvData).toEqual(data)

		const newKey = tls.getKeys()?.clientEncKey
		expect(
			await crypto.exportKey(newKey!)
		).not.toEqual(
			await crypto.exportKey(oldKey!)
		)

		socket.end()
	})

	function connectTLS(psk?: TLSPresharedKey) {
		const socket = new Socket()
		const host = 'localhost'
		socket.connect({ host, port })

		const tls = makeTLSClient({
			host,
			verifyServerCertificate: false,
			async write({ header, content, authTag }) {
				socket.write(header)
				socket.write(content)
				if(authTag) {
					socket.write(authTag)
				}
			}
		})

		socket.on('data', tls.handleRawData)

		socket.on('connect', () => tls.startHandshake({ psk }))

		return { tls, socket }
	}
})