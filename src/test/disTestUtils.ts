import { setCryptoProvider } from '../core/provider.js';
import { base64ToBytes, bytesToBase64 } from '../core/encoding.js';

/**
 * Flips one byte in a base64 payload, keeping it structurally valid base64.
 * `index` may be negative to address from the end.
 */
export function tamperBase64(value: string, index = 0, mask = 0xff): string {
    const bytes = base64ToBytes(value);
    if (bytes.length === 0) {
        throw new Error('cannot tamper an empty base64 value');
    }
    const at = index < 0 ? bytes.length + index : index;
    if (at < 0 || at >= bytes.length) {
        throw new Error(`base64 byte index ${index} is out of range`);
    }
    bytes[at] = bytes[at]! ^ mask;
    return bytesToBase64(bytes);
}

/**
 * Runs `run` with a deterministic CSPRNG. The real `subtle` implementation is
 * kept, so key generation and AEAD still work. Use this to prove that a module
 * really consumes the configured provider instead of the global `crypto`.
 */
export async function withFixedProvider<T>(
    bytes: Uint8Array,
    run: () => Promise<T>,
): Promise<T> {
    const original = globalThis.crypto;
    setCryptoProvider({
        getRandomValues: ((view: Uint8Array) => {
            view.set(bytes.subarray(0, view.length));
            return view;
        }) as typeof original.getRandomValues,
        subtle: original.subtle,
    });
    try {
        return await run();
    } finally {
        setCryptoProvider(null);
    }
}
