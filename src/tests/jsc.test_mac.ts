/**
 * This file tests that if the TLS library works on javascript
 * core (jsc) environment.
 * 1. Ensure you have the jsc binary installed
 * 2. Ensure you have built the jsc file via `npm run build:jsc`
 */
import assert from 'assert'
import { Chance } from 'chance'
import { exec } from 'child_process'
import { readFile } from 'fs/promises'
import { Socket } from 'net'
import { after, afterEach, before, beforeEach, describe, it, mock } from 'node:test'
import { stderr, stdout } from 'process'
import { asciiToUint8Array, uint8ArrayToBinaryStr } from '../utils/generics.ts'
import { createMockTLSServer } from './mock-tls-server.ts'
import { delay, waitForMockCall } from './utils.ts'

const chance = new Chance()

describe('JSC Test', () => {

	let bridge: Awaited<ReturnType<typeof runJscBridge>>
	let socket: Socket

	const host = 'localhost'
	const port = chance.integer({ min: 10000, max: 20000 })
	const srv = createMockTLSServer(port)
	const onHandshake = mock.fn()
	const onApplData = mock.fn()

	before(async() => {
		await delay(200)
	})

	after(async() => {
		srv.server.close()
		await delay(100)
	})

	beforeEach(async() => {
		onHandshake.mock.resetCalls()
		onApplData.mock.resetCalls()

		socket = new Socket()
		await new Promise<void>(resolve => socket.connect(port, host, resolve))

		bridge = await runJscBridge(
			{
				host,
				rootCAs: [
					await readFile('cert/public-cert.pem', 'utf-8'),
				]
			},
			cmd => {
				if(cmd.type === 'send') {
					const buff = Buffer.from(cmd.dataB64, 'base64')
					socket.write(buff)
					return
				}

				if(cmd.type === 'handshake-done') {
					onHandshake()
					return
				}

				if(cmd.type === 'send-application-data') {
					const data = Buffer.from(cmd.dataB64, 'base64')
					onApplData(data)
					return
				}

				console.log('Received command on JSC:', cmd)
			}
		)

		socket.on('data', bridge.sendRaw)
	})

	afterEach(() => {
		bridge?.exit()
		socket.destroy()
	})

	it('should do handshake w the server', async() => {
		await waitForMockCall(onHandshake)
		await delay(100)
		assert.equal(onHandshake.mock.calls.length, 1)
	})

	it('should send & recv data w server', async() => {
		await waitForMockCall(onHandshake)
		await delay(100)

		const waitForApplData = waitForMockCall(onApplData)

		const data = asciiToUint8Array('Hello, JSC!')
		await bridge.sendApplicationData(data)

		await waitForApplData
		await delay(100)

		assert.equal(onApplData.mock.calls.length, 1)
		const applData = onApplData.mock.calls[0].arguments[0]
		console.log('Received application data:', applData)
		assert.deepEqual(applData, data)
	})
})

async function runJscBridge(
	init: {
		host: string
		rootCAs?: string[]
	},
	onCmd: (cmd: JscOutgoingCmd) => void = () => {}
) {
	const prc = exec('jsc out/jsc-bridge.mjs', { })
	prc.stdout!.on('data', (data) => {
		const cmd = tryReadCmd(data)
		if(!cmd) {
			stdout.write('[JSC] ' + data.toString())
			return
		}

		onCmd(cmd)
	})
	prc.stderr!.on('data', (data) => {
		stderr.write('[JSC-ERR] ' + data.toString())
	})

	await writeCmd({ type: 'connect', ...init })

	return {
		sendRaw(buff: Uint8Array) {
			return writeCmd({
				type: 'send',
				dataB64: Buffer.from(buff).toString('base64')
			})
		},
		sendApplicationData(data: Uint8Array) {
			return writeCmd({
				type: 'send-application-data',
				dataB64: Buffer.from(data).toString('base64')
			})
		},
		exit() {
			prc.kill()
		}
	}

	function writeCmd(cmd: JscIncomingCmd) {
		const cmdStr = JSON.stringify(cmd)
		return new Promise<void>((resolve, reject) => {
			prc.stdin!.write(asciiToUint8Array(cmdStr + '\n'), (err) => {
				if(err) {
					reject(err)
				} else {
					resolve()
				}
			})
		})
	}
}

function tryReadCmd(str: string | Uint8Array): JscOutgoingCmd | undefined {
	str = typeof str === 'string' ? str : uint8ArrayToBinaryStr(str)
	try {
		const cmd = JSON.parse(str)
		return cmd as JscOutgoingCmd
	} catch{}
}