import assert from 'assert'
import Chance from 'chance'
import { Socket } from 'net'
import { after, before, beforeEach, describe, it, mock } from 'node:test'
import { crypto, makeTLSClient, strToUint8Array, SUPPORTED_NAMED_CURVE_MAP } from '../index.ts'
import type { CipherSuite, TLSClientOptions, TLSPresharedKey, TLSSessionTicket } from '../types/index.ts'
import { createMockTLSServer } from './mock-tls-server.ts'
import { delay, logger } from './utils.ts'

const chance = new Chance()

const TLS_NAMED_CURVES = Object.keys(SUPPORTED_NAMED_CURVE_MAP) as (keyof typeof SUPPORTED_NAMED_CURVE_MAP)[]
const TLS_DATA_MAP = {
	'TLS1_2': {
		NAMED_CURVES: TLS_NAMED_CURVES,
		CIPHER_SUITES: [
			// our test cert is RSA -- so the ECDSA tests won't work
			// 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
			// 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
			// 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
			'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
			'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
			'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
			'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
			'TLS_RSA_WITH_AES_128_GCM_SHA256'
		] as CipherSuite[]
	} as const,
	'TLS1_3': {
		NAMED_CURVES: TLS_NAMED_CURVES,
		CIPHER_SUITES: [
			'TLS_CHACHA20_POLY1305_SHA256',
			'TLS_AES_256_GCM_SHA384',
			'TLS_AES_128_GCM_SHA256'
		] as CipherSuite[]
	} as const
}

const TLS_VERSIONS = Object.keys(TLS_DATA_MAP) as (keyof typeof TLS_DATA_MAP)[]

const DATA_POINTS = [
	strToUint8Array('hi'),
	strToUint8Array('hello world'),
	crypto.randomBytes(chance.integer({ min: 50, max: 150 })),
]

for(const tlsversion of TLS_VERSIONS) {
	const {
		NAMED_CURVES,
		CIPHER_SUITES,
	} = TLS_DATA_MAP[tlsversion]
	describe(`${tlsversion} Tests`, () => {

		const port = chance.integer({ min: 10000, max: 20000 })
		const srv = createMockTLSServer(port)
		const onApplicationData = mock.fn<(arr: Uint8Array) => void>()

		before(async() => {
			await delay(200)
		})

		after(async() => {
			srv.server.close()
			await delay(100)
		})

		beforeEach(() => {
			onApplicationData.mock.resetCalls()
		})

		for(const curve of NAMED_CURVES) {
			it(`[${curve}] should do handshake with the server`, async() => {
				const { tls, socket } = connectTLS({ namedCurves: [curve] })

				while(!tls.isHandshakeDone()) {
					await delay(100)

					if(socket.readableEnded) {
						throw new Error('unexpectedly terminated')
					}
				}

				socket.end()

				assert.ok(tls.getSessionId())
				assert.ok(tls.getKeys()?.clientEncKey)

				await tls.end()
			})
		}

		it('should specify ALPN', async() => {
			const supportedAlpn = 'http/1.1'
			const alpn = ['http/4', supportedAlpn]
			const { tls, socket } = connectTLS({ applicationLayerProtocols: alpn })

			while(!tls.isHandshakeDone()) {
				await delay(100)

				if(socket.readableEnded) {
					throw new Error('unexpectedly terminated')
				}
			}

			socket.end()

			assert.equal(tls.getMetadata().selectedAlpn, supportedAlpn)

			await tls.end()
		})

		for(const cipher of CIPHER_SUITES) {
			describe(`[${cipher}] Data Exchange`, () => {
				let conn: ReturnType<typeof connectTLS>

				before(async() => {
					conn = connectTLS({ cipherSuites: [cipher] })
					while(!conn.tls.isHandshakeDone()) {
						await delay(100)
					}
				})

				after(async() => {
					conn.socket.end()
					await conn.tls.end()
				})

				for(const data of DATA_POINTS) {
					it(`should send & recv ${data.length} bytes from the server`, async() => {
						const { tls } = conn
						const recvDataPromise = new Promise<Uint8Array>(resolve => {
							onApplicationData.mock.mockImplementationOnce((content) => {
								resolve(content)
							})
						})

						await tls.write(data)

						const recvData = await recvDataPromise
						assert.deepEqual(recvData, data)
					})
				}
			})
		}

		if(tlsversion === 'TLS1_2') {
			return
		}

		it('should recv a session ticket', async() => {
			const onSessionTicket = mock.fn<(tls: TLSSessionTicket) => void>()
			const { socket } = connectTLS({
				onSessionTicket
			})
			const recvTicket = await new Promise<TLSSessionTicket>(resolve => {
				onSessionTicket.mock.mockImplementationOnce(
					(ticket) => resolve(ticket)
				)
			})
			assert.ok(recvTicket.ticket)
			assert.ok(recvTicket.expiresAt)

			socket.end()
		})

		it('should resume a session with ticket', async() => {
			const psk = await getPsk()
			const { tls, socket } = connectTLS({}, psk)

			while(!tls.isHandshakeDone()) {
				await delay(100)

				if(socket.readableEnded) {
					throw new Error('unexpectedly terminated')
				}
			}

			const data = strToUint8Array('hello resumed session')
			tls.write(data)

			const recvData = await new Promise<Uint8Array>(resolve => {
				onApplicationData.mock.mockImplementationOnce((content) => {
					resolve(content)
				})
			})

			assert.deepEqual(recvData, data)

			socket.end()

			async function getPsk() {
				const onSessionTicket = mock.fn()
				const { tls, socket } = connectTLS({ onSessionTicket })
				const sessionTicket = await new Promise<TLSSessionTicket>(resolve => {
					onSessionTicket.mock.mockImplementationOnce(ticket => {
						resolve(ticket)
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
			const { tls, socket } = connectTLS({})

			while(!tls.isHandshakeDone()) {
				await delay(100)
			}

			const oldKey = tls.getKeys()?.clientEncKey
			assert.ok(oldKey)
			await tls.updateTrafficKeys(true)

			const data = strToUint8Array('hello world')
			await tls.write(data)

			const recvData = await new Promise<Uint8Array>(resolve => {
				onApplicationData.mock.mockImplementationOnce((content) => {
					resolve(content)
				})
			})

			assert.deepEqual(recvData, data)

			const newKey = tls.getKeys()?.clientEncKey
			assert.notDeepEqual(
				await crypto.exportKey(newKey),
				await crypto.exportKey(oldKey)
			)

			socket.end()
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
				supportedProtocolVersions: [
					tlsversion
				],
				logger,
				onApplicationData,
				async write({ header, content }) {
					socket.write(header)
					socket.write(content)
				},
				...opts,
			})

			socket.on('data', tls.handleReceivedBytes)

			socket.on('connect', () => tls.startHandshake({ psk }))

			return { tls, socket }
		}
	})
}