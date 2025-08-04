import * as esbuild from 'esbuild'

const rslt = await esbuild.build({
	entryPoints: ['./src/scripts/jsc.ts'],
	bundle: true,
	platform: 'browser',
	outfile: 'out/jsc-bridge.mjs',
	format: 'esm',
	tsconfig: 'tsconfig.json',
	legalComments: 'none',
	metafile: true, // Enable metafile generation
	treeShaking: true,
	alias: {
		'@noble/hashes/crypto': './src/scripts/fallbacks/crypto.ts',
	}
})

if(process.argv.includes('--analyze')) {
	// Analyze the metafile
	const analysis = await esbuild.analyzeMetafile(rslt.metafile)
	console.log(analysis)
}