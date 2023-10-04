import Chance from 'chance'
import { Socket } from 'net'
import { TLSClientOptions, TLSPresharedKey, TLSSessionTicket } from '../types'
import { crypto, makeTLSClient, strToUint8Array, SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_NAMED_CURVE_MAP } from '..'
import { createMockTLSServer } from './mock-tls-server'
import { delay, logger } from './utils'

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
			'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
			'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'
		] as (keyof typeof SUPPORTED_CIPHER_SUITE_MAP)[]
	} as const,
	'TLS1_3': {
		NAMED_CURVES: TLS_NAMED_CURVES,
		CIPHER_SUITES: [
			'TLS_CHACHA20_POLY1305_SHA256',
			'TLS_AES_256_GCM_SHA384',
			'TLS_AES_128_GCM_SHA256'
		] as (keyof typeof SUPPORTED_CIPHER_SUITE_MAP)[]
	} as const
}

const TLS_VERSIONS = Object.keys(TLS_DATA_MAP) as (keyof typeof TLS_DATA_MAP)[]

const DATA_POINTS = [
	strToUint8Array('hi'),
	strToUint8Array('hello world'),
	crypto.randomBytes(chance.integer({ min: 50, max: 150 })),
]

describe.each(TLS_VERSIONS)('%s Tests', (tlsversion) => {

	const port = chance.integer({ min: 10000, max: 20000 })
	const srv = createMockTLSServer(port)

	beforeAll(async() => {
		await delay(200)
	})

	afterAll(async() => {
		srv.server.close()
		await delay(100)
	})

	it.each(
		TLS_DATA_MAP[tlsversion].NAMED_CURVES
	)('[%s] should do handshake with the server', async(curve) => {
		const { tls, socket } = connectTLS({ namedCurves: [curve] })

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

	describe.each(
		TLS_DATA_MAP[tlsversion].CIPHER_SUITES
	)('[%s] Data Exchange', (cipher) => {

		const onRecvData = jest.fn()
		let conn: ReturnType<typeof connectTLS>

		beforeAll(async() => {
			conn = connectTLS({
				onRecvData,
				cipherSuites: [cipher]
			})
			while(!conn.tls.isHandshakeDone()) {
				await delay(100)
			}
		})

		afterAll(async() => {
			conn.socket.end()
			await conn.tls.end()
		})

		for(const data of DATA_POINTS) {
			it(`should send & recv ${data.length} bytes from the server`, async() => {
				const { tls } = conn
				const recvDataPromise = new Promise<Uint8Array>(resolve => {
					onRecvData.mockImplementationOnce((plaintext) => {
						resolve(plaintext)
					})
				})

				await tls.write(data)

				const recvData = await recvDataPromise
				expect(recvData).toEqual(data)
			})
		}
	})

	if(tlsversion === 'TLS1_2') {
		return
	}


	it('should recv a session ticket', async() => {
		const onSessionTicket = jest.fn()
		const { socket } = connectTLS({
			onSessionTicket
		})
		const recvTicket = await new Promise<TLSSessionTicket>(resolve => {
			onSessionTicket.mockImplementationOnce(
				(ticket) => resolve(ticket)
			)
		})
		expect(recvTicket.ticket).toBeDefined()
		expect(recvTicket.expiresAt).toBeDefined()

		socket.end()
	})

	it('should resume a session with ticket', async() => {
		const psk = await getPsk()
		const onRecvData = jest.fn()
		const { tls, socket } = connectTLS({ onRecvData }, psk)

		while(!tls.isHandshakeDone()) {
			await delay(100)

			if(socket.readableEnded) {
				throw new Error('unexpectedly terminated')
			}
		}

		const data = strToUint8Array('hello resumed session')
		tls.write(data)

		const recvData = await new Promise<Uint8Array>(resolve => {
			onRecvData.mockImplementationOnce((plaintext) => {
				resolve(plaintext)
			})
		})

		expect(recvData).toEqual(data)

		socket.end()

		async function getPsk() {
			const onSessionTicket = jest.fn()
			const { tls, socket } = connectTLS({ onSessionTicket })
			const sessionTicket = await new Promise<TLSSessionTicket>(resolve => {
				onSessionTicket.mockImplementationOnce(ticket => {
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
		const onRecvData = jest.fn()
		const { tls, socket } = connectTLS({ onRecvData })

		while(!tls.isHandshakeDone()) {
			await delay(100)
		}

		const oldKey = tls.getKeys()?.clientEncKey
		expect(oldKey).toBeDefined()
		await tls.updateTrafficKeys(true)

		const data = strToUint8Array('hello world')
		await tls.write(data)

		const recvData = await new Promise<Uint8Array>(resolve => {
			onRecvData.mockImplementationOnce((plaintext) => {
				resolve(plaintext)
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