import { Socket } from 'net'
import { pino } from 'pino'
import { makeTLSClient, uint8ArrayToBinaryStr } from '../index.ts'

const LOGGER = pino()
LOGGER.level = process.env.LOG_LEVEL || 'info'

const host = readArg('--host')
if(!host) {
	console.error('Please provide a host to connect to using --host <hostname>')
	process.exit(1)
}

const port = Number(readArg('--port') || 443)

const socket = new Socket()
await new Promise<void>((resolve, reject) => {
	const tls = makeTLSClient({
		host,
		verifyServerCertificate: true,
		logger: LOGGER,
		// write raw bytes to the socket
		async write({ header, content }) {
			socket.write(header)
			socket.write(content)
		},
		async onHandshake() {
			console.log('handshake completed successfully')
			await tls.end()
			socket.end()
		},
		onApplicationData(plaintext) {
			const str = uint8ArrayToBinaryStr(plaintext)
			console.log('received application data: ', str)
		},
		onTlsEnd(error) {
			if(error) {
				reject(error)
				return
			}

			resolve()
			console.error('TLS connect ended: ', error)
		}
	})

	socket.on('data', tls.handleReceivedBytes)
	// start handshake as soon as the socket connects
	socket.on('connect', () => tls.startHandshake())
	socket.once('error', (err) => reject(err))
	// use the TCP socket to connect to the server
	socket.connect({ host, port })
})

console.log(`Connected to ${host} successfully`)

function readArg(arg: string) {
	const index = process.argv.indexOf(arg)
	if(index === -1) {
		return undefined
	}

	return process.argv[index + 1] || ''
}