import { Inject, Injectable } from '@nestjs/common'
import { createHmac } from 'node:crypto'

import { PASSPORT_OPTIONS } from './constants'
import { PassportOptions } from './interfaces'
import { base64UrlDecode, base64UrlEncode, constantTimeEqual } from './utils'

const HMAC_DOMAIN = 'PassportTokenAuth/v1'
const INTERNAL_SEP = '|'

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
		return [HMAC_DOMAIN, user, iat, exp].join(INTERNAL_SEP)
	}

	public computeHmac(secretKey: string, payload: string) {
		return createHmac('sha256', secretKey).update(payload).digest('base64')
	}

	public generateToken(secretKey: string, userId: string, ttl: number) {
		const issuedAt = this.now()
		const expiresAt = issuedAt + ttl

		const userPart = base64UrlEncode(userId)
		const iatPart = base64UrlEncode(issuedAt.toString())
		const expPart = base64UrlEncode(expiresAt.toString())

		const serialized = this.serialize(userPart, iatPart, expPart)
		const hmac = this.computeHmac(secretKey, serialized)

		return `${userPart}.${iatPart}.${expPart}.${hmac}`
	}

	public verifyToken(secretKey: string, token: string) {
		const parts = token.split('.')
		if (parts.length !== 4)
			return { valid: false, reason: 'Invalid token format' }
		const [userPart, iatPart, expPart, hmacPart] = parts

		const serialized = this.serialize(userPart, iatPart, expPart)
		const hmac = this.computeHmac(secretKey, serialized)

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
