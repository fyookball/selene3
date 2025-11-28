/* eslint-disable no-restricted-syntax */
/* eslint-disable @typescript-eslint/return-await */
/* eslint-disable @typescript-eslint/naming-convention */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-bitwise */
/* eslint-disable no-else-return*/
/* eslint-disable no-plusplus */
/* eslint-disable prefer-destructuring */
/* eslint-disable prefer-template */

import Ripemd160 from "ripemd160";
import Long from "long";
import { secp } from "./secp_helper";
import { Protocol } from "./protocol";
import LogService from "@/services/LogService";

const Log = LogService("FusionService");

/**
 * Generate a random secp256k1 keypair.
 * Returns:
 *  - privkey (32 bytes)
 *  - pubkeyUncompressed (65 bytes, 0x04 + x + y)
 *  - pubkeyCompressed (33 bytes, 0x02/0x03 + x)
 */

export function genKeypair(): [Uint8Array, Uint8Array, Uint8Array] {
  const privkey = randomPrivateKey();

  const pubkeyCompressed = secp.getPublicKey(privkey, true); // 33 bytes
  const pubkeyUncompressed = secp.getPublicKey(privkey, false); // 65 bytes

  return [privkey, pubkeyUncompressed, pubkeyCompressed];
}
export function randomPrivateKey(): Uint8Array {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return buf;
}

export function randomOutputsForTier(
  rng: { expovariate: (lambd: number) => number },
  inputAmount: number,
  scale: number,
  offset: number,
  maxCount: number,
  allowExtraChange = false
): number[] | null {
  if (inputAmount < offset) {
    return null;
  }

  const lambd = 1.0 / scale;
  let remaining = inputAmount;

  const values: number[] = [];

  for (let i = 0; i < maxCount + 1; i += 1) {
    const val = rng.expovariate(lambd);

    remaining -= Math.ceil(val) + offset;
    if (remaining < 0) {
      break;
    }
    values.push(val);
  }

  if (values.length > maxCount) {
    if (allowExtraChange) {
      const result = values.slice(0, -1).map((v) => Math.round(v) + offset);
      const change = inputAmount - result.reduce((a, b) => a + b, 0);
      result.push(change);
      return result;
    }
    return null;
  }

  if (values.length === 0) {
    return null;
  }

  const desiredRandomSum = inputAmount - values.length * offset;
  if (desiredRandomSum < 0) {
    return null;
  }

  const cumsum: number[] = [];
  values.reduce((acc, v) => {
    const next = acc + v;
    cumsum.push(next);
    return next;
  }, 0);

  const rescale = desiredRandomSum / cumsum[cumsum.length - 1];
  const normedCumsum = cumsum.map((v) => Math.round(rescale * v));

  const differences: number[] = [];
  let prev = 0;
  normedCumsum.forEach((a) => {
    differences.push(a - prev);
    prev = a;
  });

  const result = differences.map((d) => offset + d);

  const sum = result.reduce((a, b) => a + b, 0);
  if (sum !== inputAmount) {
    throw new Error("randomOutputsForTier: sum mismatch");
  }

  return result;
}

export function sizeOfInput(): number {
  return 141;
}

export function sizeOfOutput(): number {
  // assume standard P2PKH
  return 34;
}

function bigIntTo32Bytes(num: bigint): Uint8Array {
  return Uint8Array.from(
    num
      .toString(16)
      .padStart(64, "0")
      .match(/.{2}/g)!
      .map((b) => parseInt(b, 16))
  );
}

export async function hash160(pubkey: Uint8Array): Promise<Uint8Array> {
  const sha = await sha256(pubkey);
  const ripemd = new Ripemd160().update(sha).digest(); // Requires 'ripemd160' lib
  return ripemd;
}

export async function buildP2PKHScript(pubkeyHash: Uint8Array): Uint8Array {
  // OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
  return Uint8Array.from([
    0x76, // OP_DUP
    0xa9, // OP_HASH160
    0x14, // PUSH 20 bytes
    ...pubkeyHash,
    0x88, // OP_EQUALVERIFY
    0xac, // OP_CHECKSIG
  ]);
}

// Serialize elliptic curve point to byte array (compressed or uncompressed)
export function pointToSer(P: any, comp: boolean = true): Uint8Array {
  // Ensure affine form
  const affine = P.toAffine?.() ?? P; // fall back if already affine

  const x = affine.x ?? affine.X;
  const y = affine.y ?? affine.Y;

  const xBytes = bigIntTo32Bytes(x);
  const yBytes = bigIntTo32Bytes(y);

  if (comp) {
    const prefix = y % 2n === 0n ? 0x02 : 0x03;
    return new Uint8Array([prefix, ...xBytes]);
  } else {
    return new Uint8Array([0x04, ...xBytes, ...yBytes]);
  }
}

// Deserialize elliptic curve point from byte array (compressed or uncompressed)
export function serToPoint(Aser: Uint8Array): Uint8Array {
  const prefix = Aser[0]; // The first byte indicates whether the point is compressed or uncompressed

  if (prefix === 0x04) {
    // Uncompressed format: 0x04 + x + y
    const x = Aser.slice(1, 33); // Extract x-coordinate (32 bytes)
    const y = Aser.slice(33, 65); // Extract y-coordinate (32 bytes)

    // Combine x and y and deserialize using secp
    const combined = Uint8Array.from([0x04, ...x, ...y]);

    const point = secp.Point.fromHex(combined); // Deserialize the point using secp
    return point;
  } else if (prefix === 0x02 || prefix === 0x03) {
    // Compressed format: 0x02/0x03 + x
    const x = Aser.slice(1, 33); // Extract x-coordinate (32 bytes)

    // Simply deserialize using secp without needing to compute y manually
    // Deserialize the point using secp (secp handles the parity byte and computes y)
    const combined = Uint8Array.from([prefix, ...x]);

    const combined_string = Buffer.from(combined).toString("hex");

    const point = secp.Point.fromHex(combined_string);

    return point;
  } else {
    throw new Error("Invalid prefix in serialized point");
  }
}

// Helper function to compare two byte arrays to check if they are identical
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// probably deprecated. Todo: cleanup.
export type FusionPhase =
  | "starting"
  | "selecting_inputs"
  | "sending_greet"
  | "waiting_for_server_hello"
  | "allocating_outputs"
  | "done";

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

export function componentFee(size: number, feerate: number): number {
  return Math.floor((size * feerate + 999) / 1000);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function bytesToNumberBE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) + BigInt(b);
  }
  return result;
}

export function bytesToBigInt(b: Uint8Array): bigint {
  return BigInt(`0x${Buffer.from(b).toString("hex")}`);
}

export function intToBytesBE(value: bigint, length = 32): Uint8Array {
  if (value < 0n) {
    throw new Error("Cannot encode negative bigint as bytes");
  }
  const hex = value.toString(16).padStart(length * 2, "0");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

export async function listhash(pieces: Uint8Array[]): Uint8Array {
  const totalParts: Uint8Array[] = [];

  for (const piece of pieces) {
    // 4-byte big-endian length
    const lenBytes = new Uint8Array(4);
    new DataView(lenBytes.buffer).setUint32(0, piece.length, false);
    totalParts.push(lenBytes);
    totalParts.push(piece);
  }

  // Flatten all parts into one Uint8Array
  const totalLength = totalParts.reduce((sum, p) => sum + p.length, 0);
  const merged = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of totalParts) {
    merged.set(part, offset);
    offset += part.length;
  }

  return sha256(merged);
}

export async function calcInitialHash(
  tier: number,
  covertDomain: Uint8Array,
  covertPort: number,
  covertSsl: boolean,
  beginTime: number
): Promise<Uint8Array> {
  const pieces: Uint8Array[] = [];

  pieces.push(new TextEncoder().encode("Cash Fusion Session"));
  pieces.push(Protocol.VERSION);

  const tierBytes = new Uint8Array(8);
  new DataView(tierBytes.buffer).setBigUint64(0, BigInt(tier), false);
  pieces.push(tierBytes);

  pieces.push(covertDomain);

  const portBytes = new Uint8Array(4);
  new DataView(portBytes.buffer).setUint32(0, covertPort, false);
  pieces.push(portBytes);

  pieces.push(new Uint8Array([covertSsl ? 1 : 0]));

  const timeBytes = new Uint8Array(8);
  new DataView(timeBytes.buffer).setBigUint64(0, BigInt(beginTime), false);
  pieces.push(timeBytes);

  return await listhash(pieces);
}

export function toHex(u8: Uint8Array): string {
  return [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function fromHex(hex: string): Uint8Array {
  const bytes = hex.match(/.{1,2}/g);
  if (!bytes) throw new Error("Invalid hex");
  return new Uint8Array(bytes.map((b) => parseInt(b, 16)));
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

export function randomScalar(order: bigint): bigint {
  // rejection-sample in (0, order)
  while (true) {
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    const x = bytesToBigInt(b);
    if (x > 0n && x < order) return x;
  }
}

export function reverseBytes(u8: Uint8Array): Uint8Array {
  return new Uint8Array([...u8].reverse());
}

// Confusing name but follows EC.  Deterministic.
export async function randPosition(
  seed: Uint8Array, // 32 bytes random_number
  numPositions: number, // N
  counter: number // i
): number {
  // counter: 4-byte big-endian
  const ctr = new Uint8Array(4);
  ctr[0] = (counter >>> 24) & 0xff;
  ctr[1] = (counter >>> 16) & 0xff;
  ctr[2] = (counter >>> 8) & 0xff;
  ctr[3] = counter & 0xff;

  // hash = sha256(seed || ctr)
  const data = new Uint8Array(seed.length + 4);
  data.set(seed, 0);
  data.set(ctr, seed.length);

  const hash = await sha256(data); // 32 bytes

  // take first 8 bytes as big-endian uint64
  const int64 =
    (BigInt(hash[0]) << 56n) |
    (BigInt(hash[1]) << 48n) |
    (BigInt(hash[2]) << 40n) |
    (BigInt(hash[3]) << 32n) |
    (BigInt(hash[4]) << 24n) |
    (BigInt(hash[5]) << 16n) |
    (BigInt(hash[6]) << 8n) |
    BigInt(hash[7]);

  // return floor((int64 * N) / 2^64)
  return Number((int64 * BigInt(numPositions)) >> 64n);
}

/**
 * Create a framed message with MAGIC prefix + 4-byte big-endian length + payload.
 * Returns a Uint8Array ready to send with TCP.
 */
export function createFrameBytes(payload: Uint8Array): Uint8Array {
  const MAGIC = hexToBytes(Protocol.MAGIC);
  const len = payload.length;

  // Encode length as 4-byte big-endian
  const lengthBytes = new Uint8Array([
    (len >>> 24) & 0xff,
    (len >>> 16) & 0xff,
    (len >>> 8) & 0xff,
    len & 0xff,
  ]);

  // Allocate full frame: MAGIC + len + payload
  const frame = new Uint8Array(MAGIC.length + 4 + len);
  frame.set(MAGIC, 0);
  frame.set(lengthBytes, MAGIC.length);
  frame.set(payload, MAGIC.length + 4);

  return frame;
}

/**
 * Hash a list of byte arrays.
 * Equivalent to Python's listhash() in Electron Cash.
 */
export async function listHash(buffers: Uint8Array[]): Promise<Uint8Array> {
  // Precompute total length of all parts (length prefix + data)
  const totalLen = buffers.reduce((sum, buf) => sum + 4 + buf.length, 0);
  const merged = new Uint8Array(totalLen);
  let offset = 0;

  for (const buf of buffers) {
    // Write 4-byte big-endian length
    const lenBytes = new Uint8Array(4);
    new DataView(lenBytes.buffer).setUint32(0, buf.length, false); // false = big endian
    merged.set(lenBytes, offset);
    offset += 4;

    // Write data bytes
    merged.set(buf, offset);
    offset += buf.length;
  }

  return await sha256(merged);
}

/**
 * Equivalent to Python's calc_round_hash().
 */

/**
 * Equivalent to Python's calc_round_hash().
 */

export async function calcRoundHash(
  lastHash: Uint8Array,
  roundPubkey: Uint8Array,
  roundTime: number | Long,
  allCommitments: Uint8Array[],
  allComponents: Uint8Array[]
): Promise<Uint8Array> {
  let rtBig: bigint;
  if (typeof roundTime === "number") {
    rtBig = BigInt(roundTime);
  } else if (Long.isLong(roundTime)) {
    rtBig = BigInt(roundTime.toString());
  } else {
    throw new Error("roundTime invalid type");
  }

  const roundTimeBytes = new Uint8Array(8);
  const dv = new DataView(roundTimeBytes.buffer);
  dv.setBigUint64(0, rtBig, false);

  // detect any undefined holes in arrays
  for (let i = 0; i < allCommitments.length; i++) {
    if (!(allCommitments[i] instanceof Uint8Array)) {
      console.error(
        "[calcRoundHash] BAD allCommitments[" + i + "] type =",
        typeof allCommitments[i],
        allCommitments[i]
      );
      throw new Error("allCommitments invalid element type");
    }
  }

  for (let i = 0; i < allComponents.length; i++) {
    if (!(allComponents[i] instanceof Uint8Array)) {
      console.error(
        "[calcRoundHash] BAD allComponents[" + i + "] type =",
        typeof allComponents[i],
        allComponents[i]
      );
      throw new Error("allComponents invalid element type");
    }
  }

  const commitmentsHash = await listHash(allCommitments);

  const componentsHash = await listHash(allComponents);

  const label = new TextEncoder().encode("Cash Fusion Round");

  const final = await listHash([
    label,
    lastHash,
    roundPubkey,
    roundTimeBytes,
    commitmentsHash,
    componentsHash,
  ]);

  Log.log("[calcRoundHash] final session hash len =", final.length);

  return final;
}

export function encodeDataPush(data: Uint8Array): Uint8Array {
  const len = data.length; // Renamed to avoid triggering prefer-destructuring
  if (len < 0x4c) {
    return Uint8Array.from([len, ...data]);
  }
  if (len <= 0xff) {
    return Uint8Array.from([0x4c, len, ...data]); // OP_PUSHDATA1
  }
  if (len <= 0xffff) {
    return Uint8Array.from([0x4d, len & 0xff, (len >> 8) & 0xff, ...data]);
  }
  throw new Error("encodeDataPush: data too large");
}
