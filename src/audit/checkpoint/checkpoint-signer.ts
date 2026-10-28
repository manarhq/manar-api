import {
  createPrivateKey,
  generateKeyPairSync,
  type KeyObject,
  sign,
} from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { OpenBaoKvClient } from '../../openbao/openbao-kv.client';
import {
  type CheckpointKeyLookup,
  type CheckpointPublicKey,
  keyIdOf,
  verifyCheckpointSignature,
} from './checkpoint-format';

export type { CheckpointPublicKey };

interface TenantSigningKey extends CheckpointPublicKey {
  privateKey: KeyObject;
}

const DIGEST = /^[0-9a-f]{64}$/;

/**
 * Signs SEALs (audit checkpoints) with **one Ed25519 key per tenant**, so each
 * legal authority's log can be verified and handed over on its own, and a
 * leaked key exposes only that tenant (Mohamed, 28 Oct 2026). The private key
 * lives in OpenBao KV at `audit/checkpoint-signing-key/<tenantId>` and is
 * created on first use with check-and-set, so two replicas racing to create
 * it end up with the same key. Keys are cached in memory after first load.
 */
@Injectable()
export class CheckpointSigner implements CheckpointKeyLookup {
  private readonly keys = new Map<string, Promise<TenantSigningKey>>();

  constructor(private readonly kv: OpenBaoKvClient) {}

  static keyPath(tenantId: string): string {
    return `audit/checkpoint-signing-key/${tenantId}`;
  }

  async sign(tenantId: string, checkpointHashHex: string): Promise<string> {
    if (!DIGEST.test(checkpointHashHex)) {
      throw new Error('checkpoint hash is not a sha256 hex digest');
    }
    const key = await this.keyFor(tenantId);
    return sign(
      null,
      Buffer.from(checkpointHashHex, 'hex'),
      key.privateKey,
    ).toString('base64');
  }

  async publicKey(tenantId: string): Promise<CheckpointPublicKey> {
    const { keyId, algorithm, publicKeyPem } = await this.keyFor(tenantId);
    return { keyId, algorithm, publicKeyPem };
  }

  static verify(
    checkpointHashHex: string,
    signatureB64: string,
    publicKeyPem: string,
  ): boolean {
    return verifyCheckpointSignature(
      checkpointHashHex,
      signatureB64,
      publicKeyPem,
    );
  }

  private keyFor(tenantId: string): Promise<TenantSigningKey> {
    let pending = this.keys.get(tenantId);
    if (!pending) {
      pending = this.load(tenantId);
      // A failed load (OpenBao down) is retried on the next call, not cached.
      pending.catch(() => this.keys.delete(tenantId));
      this.keys.set(tenantId, pending);
    }
    return pending;
  }

  private async load(tenantId: string): Promise<TenantSigningKey> {
    const path = CheckpointSigner.keyPath(tenantId);
    let secret = await this.kv.readSecretIfPresent(path);
    if (secret === null) {
      const pair = generateKeyPairSync('ed25519');
      try {
        await this.kv.writeSecretIfAbsent(path, {
          privateKeyPem: pair.privateKey.export({
            type: 'pkcs8',
            format: 'pem',
          }),
          publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),
        });
      } catch {
        // Another replica created it first (or the write failed): use what is there.
      }
      secret = await this.kv.readSecretIfPresent(path);
      if (secret === null) {
        throw new Error(
          `checkpoint signing key for tenant ${tenantId} could not be created`,
        );
      }
    }
    if (
      typeof secret.privateKeyPem !== 'string' ||
      typeof secret.publicKeyPem !== 'string'
    ) {
      throw new Error(
        `checkpoint signing key for tenant ${tenantId} is malformed`,
      );
    }
    const privateKey = createPrivateKey(secret.privateKeyPem);
    if (privateKey.asymmetricKeyType !== 'ed25519') {
      throw new Error(
        `checkpoint signing key for tenant ${tenantId} is not Ed25519`,
      );
    }
    return {
      privateKey,
      algorithm: 'Ed25519',
      publicKeyPem: secret.publicKeyPem,
      keyId: keyIdOf(secret.publicKeyPem),
    };
  }
}
