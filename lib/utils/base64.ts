export function base64UrlEncode(buff: Buffer | string) {
	const s = typeof buff === 'string' ? Buffer.from(buff) : buff

	return s
		.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '')
}

export function base64UrlDecode(str: string) {
	str = str.replace(/-/g, '+').replace(/_/g, '/')
	while (str.length % 4) str += '='

	return Buffer.from(str, 'base64').toString()
}
