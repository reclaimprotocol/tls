# TLS Client

A TLS client implementation in typescript. This library is fully compatible with the browser (without any polyfills) and on Node Js. 

As all the cryptography is handled by webcrypto -- running on React native requires a polyfill for the "WebCrypto" module.

## Dependencies

1. The ChaCha20-Poly1305 cipher is not supported via WebCrypto -- so we utilise `@stablelib/chacha20-poly1305` to provide this functionality.
2. To handle X509 certificate validation we utilise `@peculiar/x509`

## Supported Crypto Suites & Versions

### TLS
- TLS 1.3

### Curves
- X25519 (only on NodeJs -- not supported in the browser)
- P-256 (SECP256R1)
- P-384 (SECP384R1)

### Signature Algorithms
- RSA-PSS-RSAE-SHA256
- ECDSA-SECP256R1-SHA256

### Cipher Suites
- AES-128-GCM-SHA256
- AES-256-GCM-SHA384
- CHACHA20-POLY1305-SHA256

### Certificates
- The entire Mozilla CA store is supported
- A few additional certificates have also been added. See `src/utils/root-ca.ts`

## Install

Edge version:
``` sh
npm i git+https://github.com/reclaimprotocol/tls
```

## Example Usage

``` ts
import { makeTlsClient } from '@reclaimprotocol/tls'
import { Socket } from 'net'

const socket = new Socket()
const host = 'www.google.com'
const port = 443

const tlsClient = makeTlsClient({
	host,
	// verify the server's certificate
	// disable when using self-signed certificates
	// or if you don't care about the authenticity
	// of the server
	verifyServerCertificate: true,
	// only use the following cipher suites
	// leave undefined to use all supported cipher suites
	cipherSuites: [
		'CHACHA20-POLY1305-SHA256',
		// ... other suites
	],
	// write raw bytes to the socket
	async write({ header, content, authTag }) {
		socket.write(header)
		socket.write(content)
		// auth tag is present for encrypted messages
		if(authTag) {
			socket.write(authTag)
		}
	},
	// handle any received data
	onRecvData(plaintext) {
		console.log('received data: ', plaintext)
	},
	onHandshake() {
		console.log('handshake completed successfully')
		// write encrypted data to the socket
		tls.write('hello world')
	},
	onTlsEnd(error) {
		console.error('TLS connect ended: ', error)
	}
})

socket.on('data', tls.handleReceivedBytes)

// start handshake as soon as the socket connects
socket.on('connect', () => tls.startHandshake({ psk }))

// use the TCP socket to connect to the server
socket.connect({ host, port })
```

### Misc API Usage

Handle a Session Ticket & Resume Session with a PSK
``` ts
const tlsClient = makeTlsClient({
	// ... other options
	onSessionTicket(ticket) {
		// get a PSK (pre-shared key) from the session ticket
		const psk = tls.getPskFromTicket(ticket)
		// this can be used to resume a session
		// if disconnected, using
		// tls.startHandshake({ psk })
	}
})
```

Handle received certificates
``` ts
const tlsClient = makeTlsClient({
	// ... other options

	// handle received certificates
	// (if you want to for some reason)
	onRecvCertificates({ certificates }) {
		// do something I guess?
	}
})
```

Use the TLS KeyUpdate method to update the traffic keys. This sends a KeyUpdate message to the server & generates a fresh set of keys to encrypt/decrypt data. The server will then respond with a KeyUpdate message of its own. This is useful for forward secrecy.
```ts
await tls.updateTrafficKeys()
```