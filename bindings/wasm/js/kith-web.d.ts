/** Ask the browser to keep this origin's storage. Resolves to whether it is persistent now. */
export function requestPersistentStorage(): Promise<boolean>;

/** Storage use and quota in bytes, or `null` where the browser cannot say. */
export function storageEstimate(): Promise<{ usage?: number; quota?: number } | null>;

/**
 * The 32-byte device secret key of `name`, created with `generate` on first use and kept
 * in IndexedDB encrypted by a non-extractable AES-GCM CryptoKey.
 */
export function loadOrCreateDeviceKey(
  name: string,
  generate: () => Uint8Array,
): Promise<Uint8Array>;

/** Forget the stored device key of `name`. */
export function deleteDeviceKey(name: string): Promise<void>;
