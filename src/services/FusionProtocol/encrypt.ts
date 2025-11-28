// python EC encrypt port (blame phase encryption)

/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-bitwise */
/* eslint-disable no-plusplus */
/* eslint-disable prefer-destructuring */
/* eslint-disable import/extensions */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable prefer-template */

import { cbc } from "@noble/ciphers/aes.js";

import { secp } from "./secp_helper";

import {
  bytesToNumberBE,
  hexToBytes,
  sha256,
  pointToSer,
  serToPoint,
} from "./util";

import LogService from "@/services/LogService";

const Log = LogService("FusionService");

function generateSafeScalar(): Uint8Array {
  while (true) {
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    // Check if in valid scalar range for secp256k1
    if (secp.utils.isValidPrivateKey?.(b)) return b;
    // fallback: compare against curve order if isValidPrivateKey missing
    const n = BigInt(
      "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
    );
    if (BigInt("0x" + Buffer.from(b).toString("hex")) < n) return b;
  }
}

export async function encrypt(
  message: Uint8Array,
  receiverCompressedPubkey33: Uint8Array,
  padToLength?: number
): Promise<Uint8Array> {
  //Random Nonce
  const nonceScalar = bytesToNumberBE(generateSafeScalar());

  // phemeral pubkey
  const noncePoint = secp.Point.BASE.multiply(nonceScalar).toAffine();

  const ephemeralCompressed = pointToSer(noncePoint);

  // shared secret
  const receiverPoint = serToPoint(receiverCompressedPubkey33);
  const sharedPoint = receiverPoint.multiply(nonceScalar).toAffine();

  const sharedCompressed = pointToSer(sharedPoint);

  // AES key
  const symmKey = await sha256(sharedCompressed);

  // Build plaintext
  const lenBytes = new Uint8Array(4);
  new DataView(lenBytes.buffer).setUint32(0, message.length, false);
  let plaintext = new Uint8Array([...lenBytes, ...message]);

  if (padToLength != null) {
    if (padToLength % 16 !== 0)
      throw new Error("padToLength must be multiple of 16");
    if (padToLength < plaintext.length)
      throw new Error("padToLength < message length");
    plaintext = new Uint8Array([
      ...plaintext,
      ...new Uint8Array(padToLength - plaintext.length),
    ]);
  } else {
    const mod = plaintext.length % 16;
    if (mod !== 0) {
      plaintext = new Uint8Array([...plaintext, ...new Uint8Array(16 - mod)]);
    }
  }

  // AES-CBC using noble WITH MANUAL ZERO PADDING ONLY ===
  const iv = new Uint8Array(16); // 16-byte zero IV, like Python

  // Manually pad plaintext to a multiple of 16 bytes (Python style zero-padding)
  const padLen = (16 - (plaintext.length % 16)) % 16;
  let paddedPlaintext = plaintext;
  if (padLen !== 0) {
    const pad = new Uint8Array(padLen); // already zero-filled
    const tmp = new Uint8Array(plaintext.length + padLen);
    tmp.set(plaintext);
    tmp.set(pad, plaintext.length);
    paddedPlaintext = tmp;
  }

  // AES-CBC using noble, with internal padding DISABLED
  const aes = cbc(symmKey, iv, { disablePadding: true });
  const ciphertext = aes.encrypt(paddedPlaintext);

  // HMAC truncated
  const macKey = await crypto.subtle.importKey(
    "raw",
    symmKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac16 = new Uint8Array(
    await crypto.subtle.sign("HMAC", macKey, ciphertext)
  ).slice(0, 16);

  // === STEP 7: final ===
  const out = new Uint8Array(
    ephemeralCompressed.length + ciphertext.length + mac16.length
  );
  out.set(ephemeralCompressed, 0);
  out.set(ciphertext, ephemeralCompressed.length);
  out.set(mac16, ephemeralCompressed.length + ciphertext.length);

  return out;
}

export async function decrypt(
  data: Uint8Array,
  privkey: Uint8Array
): Promise<{ plaintext: Uint8Array; symKey: Uint8Array }> {
  // Check that the data has at least the necessary parts: ephemeral public key (33 bytes), ciphertext (16 bytes), and MAC (16 bytes)
  if (data.length < 33 + 16 + 16) {
    throw new Error("DecryptFailed");
  }

  let noncePub;
  try {
    noncePub = serToPoint(data.slice(0, 33));

    // Convert to sec compressed format (Uint8Array)
    const noncePubBytes = noncePub.toBytes(true);
  } catch (e) {
    Log.log("decrypt failed with: ", e);
    throw new Error("DecryptFFFFailed");
  }

  // Format privkey as bigint
  const sec = BigInt("0x" + Buffer.from(privkey).toString("hex"));

  // Calculate the shared secret by multiplying the private key with the ephemeral public key
  const sharedPoint = noncePub.multiply(sec);
  const sharedBytes = sharedPoint.toBytes(true); // Compressed SEC format

  // Serialize the shared secret and compute the symmetric key
  const serializedSharedSecret = pointToSer(sharedPoint, true); //  serialized in compressed format

  const symKey = await sha256(serializedSharedSecret);

  // Step 5: Call `decryptWithSymmKey` to decrypt the message using the symmetric key
  const plaintext = await decryptWithSymmKey(data, symKey);

  // Return both the decrypted plaintext and the symmetric key
  return { plaintext, symKey };
}

export async function decryptWithSymmKey(
  encrypted: Uint8Array,
  symKey32: Uint8Array
): Promise<Uint8Array> {
  if (encrypted.length < 33 + 16 + 16)
    throw new Error("DecryptFailed: too short");

  // Slice and prep
  const ephemeralSkip = 33;
  const macLen = 16;
  const mac = encrypted.slice(encrypted.length - macLen);
  const ciphertext = encrypted.slice(ephemeralSkip, encrypted.length - macLen);

  // Import key and compute HMAC
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    symKey32,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const macCalcFull = new Uint8Array(
    await crypto.subtle.sign("HMAC", cryptoKey, ciphertext)
  );
  const macCalc = macCalcFull.slice(0, 16);

  if (!equal(macCalc, mac)) {
    Log.log("MAC validation failed");
    throw new Error("DecryptFailed: bad mac");
  }

  // setup AES key and IV
  const iv = new Uint8Array(16); // All-zero IV

  const aesKey = symKey32; // Noble uses raw Uint8Array directly

  let plaintextFull;

  try {
    const decrypted = cbc(aesKey, iv, { disablePadding: true }).decrypt(
      ciphertext
    );
    plaintextFull = decrypted;
  } catch (e) {
    Log.log("Decryption failed in AES-CBC step ");
    throw new Error(`DecryptFailed: AES-CBC error: ${(e as Error).message}`);
  }

  // Parse length-prefixed message
  if (plaintextFull.length < 4)
    throw new Error("DecryptFailed: too short plaintext");

  const msglen =
    (plaintextFull[0] << 24) |
    (plaintextFull[1] << 16) |
    (plaintextFull[2] << 8) |
    plaintextFull[3];

  if (4 + msglen > plaintextFull.length)
    throw new Error("DecryptFailed: bad msglen");

  return plaintextFull.slice(4, 4 + msglen);
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
