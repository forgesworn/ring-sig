/** Base error for ring signature operations */
export class RingSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RingSignatureError';
  }
}

/** Validation errors (malformed inputs, bounds exceeded) */
export class ValidationError extends RingSignatureError {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

/** Cryptographic errors (invalid keys, failed verification) */
export class CryptoError extends RingSignatureError {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoError';
  }
}
