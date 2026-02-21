import { DynamicModule, Global, Module } from '@nestjs/common'

import { PASSPORT_OPTIONS } from './constants'
import { PassportAsyncOptions, PassportOptions } from './interfaces'
import {
	createPassportAsyncOptionsProvider,
	createPassportOptionsProvider
} from './passport.providers'
import { PassportService } from './passport.service'

@Global()
@Module({})
export class PassportModule {
	public static register(options: PassportOptions): DynamicModule {
		const provider = createPassportOptionsProvider(options)

		return {
			module: PassportModule,
			providers: [provider, PassportService],
			exports: [PassportService, PASSPORT_OPTIONS]
		}
	}

	public static registerAsync(options: PassportAsyncOptions): DynamicModule {
		const provider = createPassportAsyncOptionsProvider(options)

		return {
			module: PassportModule,
			imports: options.imports ?? [],
			providers: [provider, PassportService],
			exports: [PassportService, PASSPORT_OPTIONS]
		}
	}
}
