module.exports = {
	'roots': [
		'<rootDir>/src'
	],
	modulePathIgnorePatterns: [
		'<rootDir>/node_modules'
	],
	'testMatch': [
		'**/tests/test.*.+(ts|tsx|js)',
	],
	"transform": {
		"^.+\\.(ts|tsx)$": [
			'@swc/jest',
			{
				"jsc": {
					"parser": {
						"syntax": "typescript",
						"decorators": true,
					}
				}
			}
		]
	},
	setupFiles: []
}