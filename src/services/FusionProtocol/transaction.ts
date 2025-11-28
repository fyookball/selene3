/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/naming-convention */
/* eslint-disable no-restricted-syntax */

//----

import {
  generateTransaction,
  generateSigningSerializationBCH,
  publicKeyToP2pkhLockingBytecode,
  hexToBin,
  cashAddressToLockingBytecode,
  encodeTransaction,
} from "@bitauth/libauth";
import type { ComponentInput, ComponentOutput } from "../FusionService";

import { sha256, toHex } from "./util";

import LogService from "@/services/LogService";

const Log = LogService("FusionService");

//---------------------------------------
//---------------------------------------

// Created for testing.
export function walletUtxoToComponentInput(
  w: any,
  pubkey: Uint8Array
): ComponentInput {
  return {
    prevTxid: Uint8Array.from(hexToBin(w.txid)).reverse(),
    prevIndex: Number(w.tx_pos),
    pubkey,
    amount: Number(w.amount),
  };
}

// Created for testing.
export function walletAddressToComponentOutput(
  address: string,
  amount: bigint
): ComponentOutput {
  const { bytecode } = cashAddressToLockingBytecode(address);
  return {
    scriptpubkey: bytecode,
    amount: Number(amount),
  };
}

//---------------------------------------
//---------------------------------------

export function encodeP2PKHUnlockingScript(
  sigWithType: Uint8Array,
  pubkey: Uint8Array
): Uint8Array {
  return Uint8Array.from([
    sigWithType.length,
    ...sigWithType,
    pubkey.length,
    ...pubkey,
  ]);
}

export function buildUnsignedTransaction(
  inputs: ComponentInput[],
  outputs: ComponentOutput[],
  locktime: number
) {
  const libauthInputs = inputs.map((inp) => {
    const obj = {
      outpointIndex: inp.prevIndex,
      outpointTransactionHash: Uint8Array.from(inp.prevTxid).reverse(),

      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array([]),
    };

    return obj;
  });

  const libauthOutputs = outputs.map((out) => {
    const obj = {
      lockingBytecode: out.scriptpubkey,
      valueSatoshis: BigInt(out.amount),
    };

    return obj;
  });

  const tx = generateTransaction({
    inputs: libauthInputs,
    outputs: libauthOutputs,
    locktime,
    version: 1,
  }).transaction;

  return tx;
}

export function computePreimage(
  tx: any,
  inputIndex: number,
  sourceOutputs: ComponentInput[],
  sighashType: number
): Uint8Array {
  // derive sourceOutputs in libauth shape
  const libauthSourceOutputs = sourceOutputs.map((inp) => {
    const lockingScript = publicKeyToP2pkhLockingBytecode({
      publicKey: inp.pubkey,
    });
    return {
      lockingBytecode: lockingScript,
      valueSatoshis: BigInt(inp.amount),
    };
  });

  // coveredBytecode is specifically the script of THIS input we are signing
  const coveredBytecode = libauthSourceOutputs[inputIndex].lockingBytecode;

  // libauth does full BCH sighash serialization
  return generateSigningSerializationBCH(
    { transaction: tx, inputIndex, sourceOutputs: libauthSourceOutputs },
    {
      coveredBytecode,
      signingSerializationType: new Uint8Array([sighashType]),
    }
  );
}

export function finalizeTransaction(
  signedInputs: any[],
  outputs: ComponentOutput[],
  locktime: number
): Uint8Array {
  return encodeTransaction({
    version: 1,
    locktime,
    inputs: signedInputs,
    outputs: outputs.map((o) => ({
      lockingBytecode: o.scriptpubkey,
      valueSatoshis: BigInt(o.amount),
    })),
  });
}

export async function signPreimageSchnorr(
  torboar: any,
  preimage: Uint8Array,
  privkey: Uint8Array
): Promise<Uint8Array> {
  Log.log("debug inside signpreimageschnorr. preimage is ", toHex(preimage));

  // double-SHA256 for the message digest
  const digest = await sha256(await sha256(preimage));

  // native schnorr signature (64 bytes)
  const sigResult = await torboar.secp256k1SchnorrSign32({
    msg: Array.from(digest),
    seckey: Array.from(privkey),
    aux: null,
  });

  // Return the 64-byte signature
  return Uint8Array.from(sigResult.sig ?? []);
}

export function buildSignedInput(
  inp: ComponentInput,
  signature: Uint8Array, //  64-byte schnorr signature
  pubkey: Uint8Array
) {
  // Always use SIGHASH_ALL (0x41)
  const SIGHASH_ALL = 0x41;

  // sig || 0x41
  const signatureWithSighash = Uint8Array.from([...signature, SIGHASH_ALL]);

  const unlockingBytecode = encodeP2PKHUnlockingScript(
    signatureWithSighash,
    pubkey
  );

  return {
    outpointIndex: inp.prevIndex,
    outpointTransactionHash: Uint8Array.from(inp.prevTxid).reverse(),
    sequenceNumber: 0xffffffff,
    unlockingBytecode,
  };
}

export function buildOpReturnOutput(
  payload: Uint8Array | Uint8Array[]
): ComponentOutput {
  const chunks = Array.isArray(payload) ? payload : [payload];

  const script: number[] = [0x6a]; // OP_RETURN

  for (const c of chunks) {
    // canonical small push , Fusion style
    script.push(c.length, ...c);
  }

  return {
    scriptpubkey: Uint8Array.from(script),
    amount: 0,
  };
}

export function generateFusionOpReturn(roundHash: Uint8Array): ComponentOutput {
  // EXACT EC definition
  const fuseId = Uint8Array.from([0x46, 0x55, 0x5a, 0x00]); // b'FUZ\x00'

  return buildOpReturnOutput([fuseId, roundHash]);
}
