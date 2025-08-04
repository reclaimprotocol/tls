
import { parse } from 'csv-parse/sync'
import * as fs from 'node:fs'
import { loadX509FromPem } from '../utils/index.ts'

async function main() {
	const resp = await fetch('https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV')
	const csv = await resp.text()
	const records = parse(csv, {
		columns: true,
		// eslint-disable-next-line camelcase
		skip_empty_lines: true

	})

	const data = fs.readFileSync('src/scripts/ca-template.ts', 'utf8')

	let certs = ''
	for(const record of records) {
		let pem:string = record['PEM Info']
		pem = pem.slice(1, -1) //remove ' at the beginning and end
		pem = pem.replaceAll(/\s+\n/sgi, '\n') //remove trailing spaces in some certs

		//validate
		const cert = loadX509FromPem(pem)
		if(!cert.isWithinValidity()) {
			throw new Error('certificate is not within validity period')
		}

		pem = '`' + pem + '`, //' + record['Common Name or Certificate Name'] + '\n'

		certs += pem
	}

	const newData = data.replace('\'<<CERTIFICATES>>\'', certs)
	fs.writeFileSync('src/utils/mozilla-root-cas.ts', Buffer.from(newData))
}

main().then()