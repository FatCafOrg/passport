import { Inject, Injectable } from '@nestjs/common'
import { createHmac } from 'node:crypto'

import { PASSPORT_OPTIONS } from './constants'
import { PassportOptions } from './interfaces'
import { base64UrlDecode, base64UrlEncode, constantTimeEqual } from './utils'

@Injectable()
export class PassportService {
	private readonly SECRET_KEY: string

	private static readonly HMAC_DOMAIN = 'PassportTokenAuth/v1'
	private static readonly INTERNAL_SEP = '|'

	constructor(
		@Inject(PASSPORT_OPTIONS) private readonly options: PassportOptions
	) {
		this.SECRET_KEY = options.secretKey
	}

	public serialize(user: string, iat: string, exp: string) {
		return [PassportService.HMAC_DOMAIN, user, iat, exp].join(PassportService.INTERNAL_SEP)
	}

	public computeHmac(payload: string) {
		return createHmac('sha256', this.SECRET_KEY).update(payload).digest('base64')
	}

	public generateToken(userId: string, ttl: number) {
		const issuedAt = this.now()
		const expiresAt = issuedAt + ttl

		const userPart = base64UrlEncode(userId)
		const iatPart = base64UrlEncode(issuedAt.toString())
		const expPart = base64UrlEncode(expiresAt.toString())

		const serialized = this.serialize(userPart, iatPart, expPart)
		const hmac = this.computeHmac(serialized)

		return `${userPart}.${iatPart}.${expPart}.${hmac}`
	}

	public verifyToken(token: string) {
		const parts = token.split('.')
		if (parts.length !== 4)
			return { valid: false, reason: 'Invalid token format' }
		const [userPart, iatPart, expPart, hmacPart] = parts

		const serialized = this.serialize(userPart, iatPart, expPart)
		const hmac = this.computeHmac(serialized)

		if (!constantTimeEqual(hmac, hmacPart))
			return { valid: false, reason: 'Invalid HMAC' }

		const expNumber = Number(base64UrlDecode(expPart))

		if (!Number.isFinite(expNumber))
			return { valid: false, reason: 'Error' }
		if (expNumber < this.now()) return { valid: false, reason: 'Expired' }

		return { valid: true, userId: base64UrlDecode(userPart) }
	}

	private now() {
		return Math.floor(Date.now() / 1000)
	}
}
