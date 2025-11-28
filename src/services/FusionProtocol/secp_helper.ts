// secp_helper.ts
// Wrapper for noble secp256k1 operations.

/* eslint-disable @typescript-eslint/naming-convention */
/* eslint-disable no-plusplus */
/* eslint-disable prefer-template */
/* eslint-disable prefer-destructuring */

import * as _secp from "@noble/secp256k1";

// Export noble APIs
export const secp = {
  utils: _secp.utils,
  getPublicKey: _secp.getPublicKey,
  sign: _secp.sign,
  verify: _secp.verify,
  Point: _secp.Point,
};

// noble v2 point type
export const Point = _secp.Point;

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += b[i].toString(16).padStart(2, "0");
  }
  return s;
}

// Derive ephemeral pubkey = scalar * G
export function secp_ephemeral_pub(nonceScalar32: Uint8Array): Uint8Array {
  return secp.getPublicKey(nonceScalar32, true); // compressed
}

// Derive shared = nonce * receiver pubkey
export function secp_shared_from_receiver(
  receiverCompressed33: Uint8Array,
  nonceScalar32: Uint8Array
): Uint8Array {
  const recvPoint = Point.fromHex(bytesToHex(receiverCompressed33));
  const scalarBI = BigInt("0x" + bytesToHex(nonceScalar32));
  const sharedPoint = recvPoint.multiply(scalarBI);

  return sharedPoint.toBytes(true); // compressed
}

// Derive shared = ephemeral * privKey
export function secp_shared_from_ephemeral(
  ephemeralCompressed33: Uint8Array,
  priv32: Uint8Array
): Uint8Array {
  const ephemPoint = Point.fromHex(bytesToHex(ephemeralCompressed33));
  const privBI = BigInt("0x" + bytesToHex(priv32));
  const sharedPoint = ephemPoint.multiply(privBI);

  return sharedPoint.toBytes(true); // compressed
}
