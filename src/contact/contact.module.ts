import { Global, Module } from '@nestjs/common';
import { ContactEmailService } from './contact-email.service';

/** The verified contact email lookup, for billing, growth and the worker. */
@Global()
@Module({ providers: [ContactEmailService], exports: [ContactEmailService] })
export class ContactModule {}
