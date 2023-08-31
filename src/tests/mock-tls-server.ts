import { readFileSync } from 'fs'
import { createServer, TlsOptions } from 'tls'

// TLS echo server
export function createMockTLSServer(port: number) {
	const tlsSessionStore: Record<string, Buffer> = {}

	const options: TlsOptions = {
		key: readFileSync('./cert/private-key.pem'),
		cert: readFileSync('./cert/public-cert.pem'),
		minVersion: 'TLSv1.3'
	}

	const server = createServer(options, socket => {
		socket.on('data', data => {
			console.log('recv record from client ', data)
			// write back same data
			socket.write(data)
		})
	})

	server.listen(port)

	server.on('newSession', (id, data, cb) => {
		tlsSessionStore[id.toString('hex')] = data
		cb()
	})

	server.on('tlsClientError', err => {
		console.log(err)
	})

	server.on('resumeSession', (id, cb) => {
		cb(null, tlsSessionStore[id.toString('hex')] || null)
	})

	return { server, tlsSessionStore }
}