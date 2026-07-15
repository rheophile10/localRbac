// Shared domain types.

/** A user's key material, derived deterministically from name + passphrase. */
export interface Identity {
  name: string;
  edPriv: Uint8Array; // Ed25519 signing private key (seed)
  xPriv: Uint8Array;  // X25519 box private key (scalar)
  edPub: string;      // hex — the public identity / author id
  xPub: string;       // hex — sealed-box recipient key
}

export type Role = 'admin' | 'writer' | 'reader' | 'none';

export interface KnownUser {
  pub: string;
  name: string;
  xpub: string;
  role: Role;
}
