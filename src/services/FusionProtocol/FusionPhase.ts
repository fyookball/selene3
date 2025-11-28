/* eslint-disable @typescript-eslint/naming-convention */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-param-reassign */ // Absolutely required for our architecture. We intentionally pass the service object through the stack.
/* eslint-disable no-bitwise */
/* eslint-disable @typescript-eslint/naming-convention */
/* eslint-disable no-promise-executor-return */
/* eslint-disable no-await-in-loop */
/* eslint-disable no-promise-executor-return */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-plusplus */
/* eslint-disable prefer-destructuring */
/* eslint-disable no-continue */
/* eslint-disable no-void */
/* eslint-disable @typescript-eslint/dot-notation */
/* eslint-disable no-restricted-syntax */
/* eslint-disable prefer-const */
/* eslint-disable prefer-template */
/* eslint-disable no-else-return*/
/* eslint-disable object-shorthand */

import {
  generateTransaction,
  encodeTransaction,
  decodeTransaction,
  cashAddressToLockingBytecode,
  hexToBin,
  binToHex,
  swapEndianness,
  sha256 as libauth256,
  generateSigningSerializationComponentsBCH,
  generateSigningSerializationBCH,
  encodeTransactionSigningResult,
  base64ToBin,
} from "@bitauth/libauth";

import { encrypt, decrypt } from "./encrypt"; //blame phase.

import { Commitment, PedersenSetup } from "./pedersen";
import { Protocol } from "./protocol";
import LogService from "@/services/LogService";
import { Config } from "./config";
import { block_checkpoints } from "@/util/block_checkpoints";
import { CovertSubmitter, submitCovertData } from "./covert";
import { BlindSignatureRequest } from "./schnorr";

import {
  buildUnsignedTransaction,
  walletUtxoToComponentInput,
  encodeP2PKHUnlockingScript,
  computePreimage,
  walletAddressToComponentOutput,
  finalizeTransaction,
  signPreimageSchnorr,
  buildSignedInput,
  buildOpReturnOutput,
  generateFusionOpReturn,
} from "./transaction";

import {
  sha256,
  toHex,
  fromHex,
  hexToBytes,
  componentFee,
  sizeOfInput,
  sizeOfOutput,
  randomOutputsForTier,
  calcInitialHash,
  intToBytesBE,
  createFrameBytes,
  calcRoundHash,
  encodeDataPush,
  equalBytes,
  reverseBytes,
  randPosition,
} from "./util";

import type { FusionService } from "@/services/FusionService";
import type { FusionPhase } from "./util";
import type { ComponentInput, ComponentOutput } from "../FusionService";

type ClientHelloType = import("@/proto/fusion").fusion.ClientHello;
type ClientMessageType = import("@/proto/fusion").fusion.ClientMessage;
type ServerHelloType = import("@/proto/fusion").fusion.ServerHello;
type ComponentType = import("@/proto/fusion").fusion.Component;
type InitialCommitmentType = import("@/proto/fusion").fusion.InitialCommitment;
type ProofType = import("@/proto/fusion").fusion.Proof;
type JoinPoolsType = import("@/proto/fusion").fusion.JoinPools;
type PoolTagType = import("@/proto/fusion").fusion.JoinPools.PoolTag;
type FusionBeginType = import("@/proto/fusion").fusion.FusionBegin;
type StartRoundType = import("@/proto/fusion").fusion.StartRound;
type PlayerCommitType = import("@/proto/fusion").fusion.PlayerCommit;
type restartRoundType = import("@/proto/fusion").fusion.restartRound;

type CovertTransactionSignatureType =
  import("@/proto/fusion").fusion.CovertTransactionSignature;

const Log = LogService("FusionService");
// Each phase returns the next FusionPhase string.
// All have access to the FusionService instance for shared state (tcp, utxos, etc.)

//----
//----
//----
//----

export async function phase_starting(
  service: FusionService
): Promise<FusionPhase> {
  Log.log("Fusion Phase: starting");
  await service._torboar.resetState();

  return "selecting_inputs"; // Specify next phase.  Each phase function directs the flow to where it goes next.
}

//----
//----
//----
//----

export async function phase_selectingInputs(
  service: FusionService
): Promise<FusionPhase> {
  Log.log("Fusion Phase: selecting_inputs");

  // Fetch all UTXOs and select a random subset
  service._inputs = service._selectRandomUtxos(
    await service._grabWalletUtxos(),
    0.5
  );

  //  Log all selected UTXOs for debugging
  Log.log("Selecting wallet UTXOs:");

  Log.log(` Total selected: ${service._inputs.length}`);

  return "sending_greet";
}

//----
//----
//----
//----

export async function phase_sendGreet(
  service: FusionService
): Promise<FusionPhase> {
  Log.log("Fusion Phase: sending_greet");

  const host = Config.FusionHost();
  const port = Config.FusionPort();

  await service._torboar.connectTcp({ host, port, ssl: true });

  const versionBytes = Protocol.VERSION;
  const genesisHash = hexToBytes(
    block_checkpoints.satoshiGenesis.blockhash
  ).reverse();

  if (!service._fusion) {
    Log.log("Fusion proto not loaded; call start() first");
    throw new Error("Fusion proto not loaded");
  }

  const clientHello = service._fusion.ClientHello.create({
    version: versionBytes,
    genesisHash,
  });

  const clientMessage = service._fusion.ClientMessage.create({
    clienthello: clientHello,
  });
  const payloadBytes =
    service._fusion.ClientMessage.encode(clientMessage).finish();

  const frameBytes = createFrameBytes(payloadBytes);

  await service._torboar.sendTcpDataPersistent({
    data: Buffer.from(frameBytes).toString("hex"),
  });

  return "waiting_for_server_hello";
}

//----
//----
//----
//----

export async function phase_waitForServerHello(
  service: FusionService
): Promise<FusionPhase> {
  Log.log("Fusion Phase: waiting_for_server_hello");

  let hexResponse: string;
  try {
    const TIMEOUT_MS = 9000; // 9-second timeout
    const result = await Promise.race([
      service._torboar.receiveTcpDataPersistent(),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error("Timed out waiting for ServerHello")),
          TIMEOUT_MS
        )
      ),
    ]);

    hexResponse = (result as { data: string }).data;
  } catch (err) {
    Log.log("Error during receiveTcpData:", err);
    throw err; // abort round
  }

  const responseBytes = fromHex(hexResponse);

  // Drop the first 12 bytes (8-byte magic + 4-byte length):
  const responsePayloadBytes = responseBytes.slice(12);

  let serverMsg;
  try {
    serverMsg = service._fusion.ServerMessage.decode(responsePayloadBytes);
  } catch (err) {
    Log.log(
      "Error decoding ServerMessage:",
      err,
      "hex:",
      toHex(responsePayloadBytes)
    );
    throw err;
  }

  const serverHello = serverMsg.serverhello as ServerHelloType | undefined;
  if (!serverHello) {
    Log.log("ServerMessage did not contain serverhello");
    throw new Error("Missing ServerHello in response");
  }

  const componentFeerate = Number(serverHello.componentFeerate);
  const minExcessFee = Number(serverHello.minExcessFee);
  const maxExcessFee = Number(serverHello.maxExcessFee);
  const numComponents = Number(serverHello.numComponents);
  const tiers = serverHello.tiers.map(Number);

  service._minExcessFee = minExcessFee;
  service._maxExcessFee = maxExcessFee;
  service._componentFeerate = componentFeerate;
  service._numComponents = numComponents;
  service._serverHello = serverHello;

  // Validations
  if (componentFeerate > Protocol.MAX_COMPONENT_FEERATE) {
    throw new Error("Excessive component feerate from server");
  }
  if (minExcessFee > Protocol.MIN_EXCESS_FEE_CLIENT) {
    throw new Error("Excessive min excess fee from server");
  }
  if (minExcessFee > maxExcessFee) {
    throw new Error("Bad server config: minExcessFee > maxExcessFee");
  }
  if (numComponents < Protocol.MIN_TX_COMPONENTS * 1.5) {
    throw new Error("Bad server config: too few components");
  }

  return "allocating_outputs";
}

//----
//----
//----
//----

export async function phase_allocateOutputs(
  service: FusionService
): Promise<FusionPhase> {
  Log.log("Fusion Phase: allocating_outputs");

  // Set available tiers from ServerHello
  const serverHello = service._serverHello;
  if (!serverHello) {
    throw new Error("No ServerHello found in service");
  }

  const tiers = serverHello.tiers.map(Number);
  service.availableTiers = tiers;

  const numInputs = service._inputs.length;
  const maxComponents = Math.min(
    service._numComponents,
    Protocol.MAX_COMPONENTS
  );
  const maxOutputs = maxComponents - numInputs;

  const uniqueAddresses = new Set(service._inputs.map((u) => u.address));
  const numDistinct = uniqueAddresses.size;
  const minOutputs = Math.max(Protocol.MIN_TX_COMPONENTS - numDistinct, 1);

  if (maxOutputs < minOutputs) {
    throw new Error(
      `Too few distinct inputs selected (${numDistinct}); cannot satisfy output count constraint (>=${minOutputs}, <=${maxOutputs})`
    );
  }

  const sumInputsValue = service._inputs
    .map((u) => Number(u.amount))
    .reduce((a, b) => a + b, 0);

  const inputFees = service._inputs
    .map((u) => componentFee(sizeOfInput(u), service._componentFeerate))
    .reduce((a, b) => a + b, 0);

  const availForOutputs = sumInputsValue - inputFees - service._minExcessFee;
  const feePerOutput = componentFee(34, service._componentFeerate);
  const offsetPerOutput = Protocol.MIN_OUTPUT + feePerOutput;

  if (availForOutputs < offsetPerOutput) {
    throw new Error("Selected inputs had too little value");
  }

  const rng = {
    expovariate: (lambd: number) => -Math.log(1 - Math.random()) / lambd,
  };

  const tierOutputs: Record<number, number[]> = {};
  const excessFees: Record<number, number> = {};

  tiers.forEach((scale) => {
    const fuzzFeeMax = Math.floor(scale / 1_000_000);
    const fuzzFeeMaxReduced = Math.min(
      fuzzFeeMax,
      Protocol.MAX_EXCESS_FEE - service._minExcessFee,
      service._maxExcessFee - service._minExcessFee
    );

    if (fuzzFeeMaxReduced < 0) return;

    const fuzzFee = Math.floor(Math.random() * (fuzzFeeMaxReduced + 1));
    const reducedAvail = availForOutputs - fuzzFee;
    if (reducedAvail < offsetPerOutput) return;

    const outputs = randomOutputsForTier(
      rng,
      reducedAvail,
      scale,
      offsetPerOutput,
      maxOutputs
    );
    if (!outputs || outputs.length < minOutputs) return;

    const adjustedOutputs = outputs.map((o) => o - feePerOutput);
    if (numInputs + adjustedOutputs.length > Protocol.MAX_COMPONENTS) return;

    excessFees[scale] = sumInputsValue - inputFees - reducedAvail;
    tierOutputs[scale] = adjustedOutputs;
  });

  // Persist into class
  service._tierOutputs = tierOutputs;
  service._safetyExcessFees = excessFees;
  service._safetySumIn = sumInputsValue;

  return "join_pools";
}

//----
//----
//----
//----

export async function phase_joinPools(
  service: FusionService
): Promise<FusionPhase> {
  Log.log("Fusion Phase: JoinPools...");

  const tiersSorted = Object.keys(service._tierOutputs)
    .map(Number)
    .sort((a, b) => a - b);

  const randomTag = crypto.getRandomValues(new Uint8Array(20));
  const tags = [
    service._fusion.JoinPools.PoolTag.create({
      id: randomTag,
      limit: 1,
    }),
  ];

  const joinPoolsMsg = service._fusion.JoinPools.create({
    tiers: tiersSorted,
    tags,
  });

  const clientMessage = service._fusion.ClientMessage.create({
    joinpools: joinPoolsMsg,
  });

  const payloadBytes =
    service._fusion.ClientMessage.encode(clientMessage).finish();

  const frameBytes = createFrameBytes(payloadBytes);

  await service._torboar.sendTcpDataPersistent({ data: toHex(frameBytes) });

  return "wait_for_fusion_begin";
}

//----
//----
//----
//----

export async function phase_waitForFusionBegin(
  service: FusionService
): Promise<FusionPhase> {
  Log.log("Fusion Phase: waiting_for_fusion_begin");

  let gotFusionBegin = false;
  let noMessageCounter = 0;

  //probably deprecated
  const MAX_EMPTY_MESSAGES = 20;

  while (true) {
    try {
      const tcpStatus = await service._torboar.checkTcpStatusPersistent();
      const alive = tcpStatus.alive;

      if (!alive) {
        Log.log(" TCP socket died — aborting round");
        return "done";
      }
    } catch (err) {
      Log.log(" Failed to check TCP status", err);
      return "done";
    }

    let result;
    try {
      const pluginCall = service._torboar.receiveTcpDataPersistent({
        timeoutMs: 5000,
      });

      const fallback = new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error("Timed out waiting for server")),
          10000
        )
      );

      result = await Promise.race([pluginCall, fallback]);
    } catch (err) {
      const msg = err?.message || err.toString();
      Log.log(" receiveTcpData error:", msg);
      return "done";

      //possibly unnceesaary if returning
      noMessageCounter++;
      if (!gotFusionBegin && noMessageCounter >= MAX_EMPTY_MESSAGES) {
        Log.log("Took too long waiting for fusionbegin. exiting.");
        throw new Error("Timed out waiting for FusionBegin");
      }
      continue;
    }

    const hexResponse = (result as { data: string }).data;
    const responseBytes = fromHex(hexResponse);
    const payload = responseBytes.slice(12);

    let serverMsg;
    try {
      serverMsg = service._fusion.ServerMessage.decode(payload);
    } catch (err) {
      Log.log(" Failed to decode ServerMessage:", err);
      continue;
    }

    const keys = Object.keys(serverMsg).filter(
      (k) => serverMsg[k] !== null && serverMsg[k] !== undefined
    );

    noMessageCounter = 0;

    // Handle tierstatusupdate
    if (serverMsg.tierstatusupdate) {
      Log.log(" Received TierStatusUpdate");

      Object.entries(serverMsg.tierstatusupdate.statuses).forEach(
        ([tier, status]) => {
          const p = status.players ?? "?";
          const min = status.minPlayers ?? "?";
          const max = status.maxPlayers ?? "?";
          const t = status.timeRemaining ?? "?";

          Log.log(`  Tier ${tier}: ${p}/${min} players, ${t}s`);
        }
      );
    }

    // Handle fusionbegin
    if (serverMsg.fusionbegin) {
      Log.log("  Received FusionBegin");
      service._fusionBegin = serverMsg.fusionbegin;
      gotFusionBegin = true;
      break;
    }
  }

  return "prepare_covert";
}

//----
//----
//----
//----

export async function phase_prepareCovert(
  service: FusionService
): Promise<FusionPhase> {
  Log.log(" Covert prepare phase.");
  const fb = service._fusionBegin!;
  Log.log(" Received FusionBegin");

  // Clock mismatch check
  const localTimeSec = Date.now() / 1000;
  const serverTime = fb.serverTime!;
  const clockMismatch = serverTime - localTimeSec;

  if (Math.abs(clockMismatch) > Protocol.MAX_CLOCK_DISCREPANCY) {
    Log.log(`  Clock mismatch too large: ${clockMismatch.toFixed(3)}s`);
    throw new Error(
      `Clock mismatch too large: ${clockMismatch.toFixed(3)} seconds`
    );
  }

  // Store fusionbegin parameters into class ---
  service._tier = fb.tier!;
  service._covertDomain = fb.covertDomain!;
  service._covertPort = fb.covertPort!;
  service._covertSsl = fb.covertSsl!;
  service._beginTime = serverTime;
  service._tFusionBegin = performance.now() / 1000;

  // Decode the covert domain bytes into a string ---
  const covertDomainStr = new TextDecoder().decode(service._covertDomain);

  // Compute initial hash ---
  const hash = await calcInitialHash(
    service._tier,
    service._covertDomain,
    service._covertPort,
    service._covertSsl,
    service._beginTime
  );

  service._lastHash = hash;

  // Prepare output addresses ---
  const outAmounts = service._tierOutputs[service._tier] ?? [];
  const outAddrs = await service._grabChangeAddresses(outAmounts);
  service._reservedAddresses = outAddrs;
  service._outputs = outAmounts.map((amt, i) => [amt, outAddrs[i]]);

  service._safetyExcessFee = service._safetyExcessFees[service._tier] ?? 0;

  const covert = new CovertSubmitter(
    covertDomainStr, //  decode before passing
    service._covertPort,
    service._covertSsl,
    service._numComponents,
    Protocol.COVERT_SUBMIT_WINDOW,
    Protocol.COVERT_SUBMIT_TIMEOUT,
    service._torboar,
    service._circuitLedger
  );

  service._covertSubmitter = covert;

  // Debug + circuit scheduling ---
  try {
    const tFusionBegin = service._tFusionBegin;

    // Fire-and-forget circuit scheduling (non-blocking)
    // eslint-disable-next-line no-void
    void covert
      .scheduleConnections(
        tFusionBegin,
        Protocol.COVERT_CONNECT_WINDOW,
        Protocol.COVERT_CONNECT_SPARES,
        Protocol.COVERT_CONNECT_TIMEOUT
      )
      .catch((err) => {
        Log.log("scheduleConnections threw:", err);
      });
  } catch (outerErr) {
    Log.log("scheduleConnections hit an error:", outerErr);
  }

  if (!service._circuitLedger || service._circuitLedger.size === 0) {
    Log.log(" Ledger is EMPTY or undefined");
  } else {
    Log.log(` Ledger has ${service._circuitLedger.size} entries`);
  }

  // Optional warmup loop before StartRound ---
  const tend =
    service._tFusionBegin + (Protocol.WARMUP_TIME - Protocol.WARMUP_SLOP - 1);

  while (Date.now() / 1000 < tend) {
    const numConnected = covert.connectedCount;
    const numSpareConnected = covert.spareCount;
    Log.log(
      `Setting up Tor connections (${numConnected}+${numSpareConnected} out of ${service._numComponents})`
    );
    await new Promise<void>((r) => setTimeout(r, 1000));
  }

  Log.log("Covert setup complete.");
  return "wait_for_start_round";
}

//----
//----
//----
//----

export async function phase_waitForStartRound(
  service: FusionService
): Promise<string> {
  const start = Date.now();
  const timeoutMs = 50000;
  const maxEndTime = start + timeoutMs;
  Log.log("PHASE WAITING FOR STARTROUND");

  service._allCommitments = undefined;
  service._shareCovertComponents = undefined;
  service._generatedComponents = undefined;
  service._fusionResult = undefined;

  // Main poll loop ---
  while (Date.now() < maxEndTime) {
    try {
      //  Check socket status before polling
      const status = await service._torboar.checkTcpStatusPersistent();

      if (!status.alive) {
        Log.log("Persistent socket not alive.  Exiting round.");
        await new Promise((r) => setTimeout(r, 1000));
        return "done";
      }

      //  Poll persistent socket
      Log.log("Waiting for Start Round Message...");
      const res = await service._torboar.receiveTcpDataPersistent({
        timeoutMs: 5000,
      });

      Log.log("  Received data from persistent socket");

      // Frame handling: strip MAGIC + length (12 bytes) ---
      const hexResponse = res.data;
      const responseBytes = Buffer.from(hexResponse, "hex");
      if (responseBytes.length <= 12) {
        Log.log(
          "  Response too short to contain a payload:",
          responseBytes.length
        );
        continue;
      }

      const payload = responseBytes.slice(12);

      // Decode protobuf
      try {
        const serverMsg = service._fusion.ServerMessage.decode(payload);
        const keys = Object.keys(serverMsg);
        Log.log("  Decoded ServerMessage keys:", keys);

        if (serverMsg.startround) {
          Log.log("Got StartRound:", serverMsg.startround);
          service._startRound = serverMsg.startround;
          const covert_T0 = performance.now();
          Log.log("covert T0 ", covert_T0);
          service._covertT0 = covert_T0;
          return "pedersen_setup";
        }
      } catch (decodeErr) {
        Log.log("Failed to decode ServerMessage:", decodeErr);
      }
    } catch (err) {
      Log.log("Nothing yet (this is normal).  Next update in 5 seconds... ");
    }

    await new Promise((r) => setTimeout(r, 500));
  }

  throw new Error("Timeout waiting for StartRound message from server.");
}

//----
//----
//----
//----

export async function phase_pedersenSetup(
  service: FusionService
): Promise<string> {
  Log.log("Phase: pedersen_setup");

  // Initialize Pedersen setup ---
  const pedersenSetup = new PedersenSetup(service._torboar);
  await pedersenSetup.init();
  service._pedersenSetup = pedersenSetup;

  Log.log("PedersenSetup complete");

  // Timing Check

  const serverTime = service._startRound.serverTime;
  const localUnixTime = Date.now() / 1000;
  const clockMismatch = serverTime - localUnixTime;

  if (Math.abs(clockMismatch) > Protocol.MAX_CLOCK_DISCREPANCY) {
    throw new Error(
      `Clock mismatch too large: ${clockMismatch.toFixed(
        3
      )}s (server=${serverTime}, local=${localUnixTime})`
    );
  }

  // Fee calculations ---
  const compFeeIn = componentFee(sizeOfInput(), service._componentFeerate);
  const compFeeOut = componentFee(sizeOfOutput(), service._componentFeerate);

  const inputFees = service._inputs.length * compFeeIn;

  const outputFees = service._outputs.length * compFeeOut;

  // Sum inputs and outputs ---
  let sumIn = 0n;
  try {
    sumIn = service._inputs.reduce(
      (sum, input: any) => sum + BigInt(input.amount),
      0n
    );
    Log.log("sumIn:", sumIn.toString());
  } catch (e) {
    Log.log("Error during sumIn reduce:", e);
  }

  let sumOut = 0n;
  sumOut = service._outputs.reduce((sum, [amt]) => sum + BigInt(amt), 0n);

  let totalFee = 0n;
  let excessFee = 0n;
  try {
    totalFee = sumIn - sumOut;
    excessFee = totalFee - BigInt(inputFees + outputFees);
    Log.log("totalFee:", totalFee.toString());
    Log.log("excessFee:", excessFee.toString());
  } catch (e) {
    Log.log("Error computing fees:", e);
  }

  // Safety checks ---

  const safeties = [
    Number(sumIn) === Number(service._safetySumIn),
    Number(excessFee) === Number(service._safetyExcessFee),
    Number(excessFee) <= Protocol.MAX_EXCESS_FEE,
    Number(totalFee) <= Protocol.MAX_FEE,
  ];

  if (safeties.includes(false)) {
    Log.log("Saftey checks failed.");
    throw new Error("Safety checks failed.");
  }

  Log.log("  PedersenSetup complete and safety checks passed.");
  return "generate_components";
}

//----
//----
//----
//----

export async function phase_generateComponents(
  service: FusionService
): Promise<string> {
  Log.log("Phase: generate_components");

  // Extract round data

  try {
    service._roundPubKey = service._startRound.roundPubkey;
    service._blindNoncePoints = service._startRound.blindNoncePoints;

    if (!service._blindNoncePoints) {
      Log.log(" blindNoncePoints is undefined or null.");
      throw new Error("Missing blindNoncePoints in serverMsg.startround");
    }

    if (service._blindNoncePoints.length !== service._numComponents) {
      throw new Error(
        `blindNoncePoints length mismatch: got ${service._blindNoncePoints.length}, expected ${service._numComponents}`
      );
    }
  } catch (e) {
    Log.log(" Error while extracting round data:", e);
    throw e;
  }

  Log.log("Sanity checks passed.");

  // Build Component Inputs

  const utxos: Utxo[] = Array.isArray(service._inputs[0])
    ? service._inputs.map(([utxo]) => utxo)
    : service._inputs;

  let inputComponents: ComponentInput[] = [];

  try {
    inputComponents = await service.createInputComponents(utxos);

    service._inputComponents = inputComponents;
  } catch (err) {
    Log.log(" error with createInputComponents:", err);
    await Haptic.error?.();
    throw err;
  }

  if (inputComponents && inputComponents.length > 0) {
    Log.log(` ComponentInputs ready: count=${inputComponents.length}`);
  } else {
    Log.log(" No ComponentInputs were created.");
  }

  // Build Component Outputs
  const outputComponents = await service.createOutputComponents(
    service._outputs
  );

  // Determine Blank Component Count
  const numBlanks =
    service._numComponents - inputComponents.length - outputComponents.length;

  if (numBlanks < 0) {
    throw new Error(
      ` Component overflow: have ${
        inputComponents.length + outputComponents.length
      }, but only ${service._numComponents} slots`
    );
  }

  // Pre-generate salts for all components
  const totalComponents =
    inputComponents.length + outputComponents.length + numBlanks;
  const randomSalts = Array.from({ length: totalComponents }, () =>
    crypto.getRandomValues(new Uint8Array(32))
  );

  Log.log("Calling genComponents...");

  const generatedComponents = await service.genComponents(
    service._pedersenSetup,
    numBlanks,
    inputComponents,
    outputComponents,
    service._componentFeerate,
    randomSalts
  );

  service._generatedComponents = generatedComponents;

  //  End of phase
  return "blind_signatures";
}

//----
//----
//----
//----

export async function phase_blindSignatures(
  service: FusionService
): Promise<string> {
  Log.log("  Phase: blind_signatures");

  const generatedComponents = service._generatedComponents;
  if (!generatedComponents) {
    throw new Error("Missing generatedComponents from previous phase.");
  }

  Log.log(
    ` InitialCommitments count: ${generatedComponents.initialCommitments.length}`
  );
  Log.log(
    ` Total commitment amount: ${generatedComponents.totalAmount.toString()}`
  );
  Log.log(
    ` Pedersen nonce: ${Buffer.from(
      generatedComponents.pedersenTotalNonce
    ).toString("hex")}`
  );

  Log.log(" Starting blind signature request generation...");

  const roundPubkey: Uint8Array = service._roundPubKey;
  const Torboar = service._torboar;

  // Sanity check: number of nonce points must match number of components
  if (
    service._blindNoncePoints.length !==
    generatedComponents.serializedComponents.length
  ) {
    throw new Error(
      `Blind nonce count mismatch: expected ${generatedComponents.serializedComponents.length}, got ${service._blindNoncePoints.length}`
    );
  }

  const blindSigRequests: BlindSignatureRequest[] = [];

  Log.log(" Building blind signature requests...");

  for (let i = 0; i < generatedComponents.serializedComponents.length; i++) {
    const component = generatedComponents.serializedComponents[i];
    const noncePoint = service._blindNoncePoints[i];
    const messageHash = await sha256(component);

    const request = new BlindSignatureRequest({
      pubkey: roundPubkey,
      R: noncePoint,
      messageHash,
      torboar: Torboar,
    });
    await request.init();
    blindSigRequests.push(request);
  }

  Log.log(` Built ${blindSigRequests.length} BlindSignatureRequest objects.`);
  Log.log("  Finished blind signature setup.");

  // Persist for later phases
  service._blindSigRequests = blindSigRequests;

  //  Transition to next phase
  return "send_player_commit";
}

//----
//----
//-----
//----
//----
//-----

export async function phase_sendPlayerCommit(
  service: FusionService
): Promise<string> {
  Log.log(" Phase: player_commit");

  const gen = service._generatedComponents;
  const blindSigRequests = service._blindSigRequests;

  if (!gen) throw new Error("Missing generatedComponents");
  if (!blindSigRequests || blindSigRequests.length === 0)
    throw new Error("Missing blindSigRequests");
  if (!service._fusion?.PlayerCommit || !service._fusion?.ClientMessage)
    throw new Error("Protobuf bindings missing (PlayerCommit/ClientMessage)");

  const isUint8 = (v: any): v is Uint8Array => v instanceof Uint8Array;

  const hexToBytesSafe = (hex: string): Uint8Array => {
    const h = hex.startsWith("0x") ? hex.slice(2) : hex;
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < h.length; i += 2)
      out[i / 2] = parseInt(h.slice(i, i + 2), 16);
    return out;
  };

  const normalizeBytes = (v: any, ctx: string): Uint8Array => {
    if (isUint8(v)) return v;
    if (Array.isArray(v)) return new Uint8Array(v);
    if (typeof v === "string") return hexToBytesSafe(v);
    throw new Error(`${ctx}: expected bytes, got ${typeof v}`);
  };

  // Encode each InitialCommitment as serialized bytes
  if (!Array.isArray(gen.initialCommitments))
    throw new Error("initialCommitments missing or not array");

  const initialCommitments: Uint8Array[] = [];
  for (let i = 0; i < gen.initialCommitments.length; i++) {
    const ic = gen.initialCommitments[i];
    const msg = service._fusion.InitialCommitment.create(ic);
    const encoded = service._fusion.InitialCommitment.encode(msg).finish();
    initialCommitments.push(encoded);
  }

  // Fee + Nonce
  let excessFee: number | string;
  if (typeof gen.totalAmount === "bigint") {
    const n = Number(gen.totalAmount);
    excessFee = Number.isSafeInteger(n) ? n : gen.totalAmount.toString();
  } else {
    excessFee = gen.totalAmount as any;
  }

  const pedersenTotalNonce = normalizeBytes(
    gen.pedersenTotalNonce,
    "pedersenTotalNonce"
  );

  const randomNumber = crypto.getRandomValues(new Uint8Array(32));
  const randomNumberCommitment = await sha256(randomNumber);
  service._randomNumber = randomNumber;
  // blind_sig_requests
  const blindSigBytes = blindSigRequests.map((r, i) => {
    const { e, enew } = r.getRequest();
    const eBytes = intToBytesBE(e, 32);
    const enewBytes = intToBytesBE(enew, 32);

    // send only the 32 bytes.

    const combined = eBytes;

    return combined;
  });

  // Build PlayerCommit
  const playerCommitMsg = {
    initialCommitments,
    excessFee,
    pedersenTotalNonce,
    randomNumberCommitment,
    blindSigRequests: blindSigBytes,
  };

  let payloadBytes: Uint8Array;
  try {
    const commitMsg = service._fusion.PlayerCommit.create(playerCommitMsg);
    const clientMsg = service._fusion.ClientMessage.create({
      playercommit: commitMsg,
    });
    payloadBytes = service._fusion.ClientMessage.encode(clientMsg).finish();
  } catch (err) {
    Log.log(" Encode failed:", err);
    throw err;
  }

  const frame = createFrameBytes(payloadBytes);

  try {
    await service._torboar.sendTcpDataPersistent({ data: toHex(frame) });
    Log.log(" Sent PlayerCommit successfully!");
    Log.log(
      `PlayerCommit sent at ${(performance.now() - service._covertT0).toFixed(
        0
      )} ms after covertT0`
    );
  } catch (err) {
    Log.log(" TCP send failed:", err);
    throw err;
  }

  return "receive_blind_sig_responses";
}

//----
//----
//-----
//----
//----
//-----

export async function phase_receiveBlindSigResponses(
  service: FusionService
): Promise<FusionPhase> {
  Log.log(" PHASE: RECEIVE BLIND SIG RESPONSES");

  try {
    Log.log(" Waiting up to 15 s for blindsigresponses…");

    //  Wait for TCP payload
    const msg = await service._torboar.receiveTcpDataPersistent({
      timeoutMs: 15000,
    });
    if (!msg?.data) throw new Error("No TCP payload received");

    const responseBytes = hexToBytes(msg.data);

    // Strip MAGIC + 4-byte length prefix (12 bytes total)
    const payload = responseBytes.slice(12);

    // Decode protobuf ---
    let serverMsg: any;
    try {
      if (service._fusion.ServerMessage) {
        serverMsg = service._fusion.ServerMessage.decode(payload);
      } else if (service._fusion.ServerReply) {
        serverMsg = service._fusion.ServerReply.decode(payload);
      } else {
        throw new Error("No ServerMessage/ServerReply type in proto");
      }
      Log.log("  Successfully decoded ServerMessage.");
    } catch (err) {
      throw new Error(`Failed to decode ServerMessage protobuf: ${err}`);
    }

    // Interpret server response
    if (serverMsg.error) {
      const errMsg = serverMsg.error.message || "Unknown server error";
      Log.log(`Server error: ${errMsg}`);
      throw new Error(errMsg);
    }

    const responses = serverMsg.blindsigresponses;
    if (!responses || !responses.scalars?.length)
      throw new Error("Server returned empty or invalid blindsigresponses");

    Log.log(`  Received ${responses.scalars.length} blind signature scalars.`);

    // Finalize
    const reqs = service._blindSigRequests as BlindSignatureRequest[];
    if (!reqs?.length)
      throw new Error("No BlindSignatureRequest objects available");
    if (responses.scalars.length !== reqs.length)
      throw new Error(
        `Count mismatch: got ${responses.scalars.length}, expected ${reqs.length}`
      );

    const blindSigs: Uint8Array[] = [];

    for (let i = 0; i < responses.scalars.length; i++) {
      const scalar = responses.scalars[i];
      const req = reqs[i];

      if (!req || typeof req.finalize !== "function") {
        continue;
      }

      try {
        const sig = await req.finalize(scalar, true);
        if (sig instanceof Uint8Array && sig.length === 64) {
          blindSigs.push(sig);
        }
      } catch {
        continue;
      }
    }

    service._blindSignatures = blindSigs;
    Log.log(`Finalized ${blindSigs.length} blind signatures.`);

    return "covert_components";
  } catch (err: any) {
    Log.log("  Error in phase_receiveBlindSigResponses:", err);
    service.status = ["error", "blind sig response phase failed"];
    throw err;
  }
}

//----
//----
//-----

export async function phase_covertComponents(
  service: FusionService
): Promise<FusionPhase> {
  Log.log("Phase: covertComponents");
  const gen = service._generatedComponents;
  const fusion = service._fusion;
  if (!gen || !fusion)
    throw new Error("Missing fusion proto or generated components");

  const { components } = gen;

  // TIMING
  const T0 = service._covertT0 ?? Date.now();
  const START_DELAY_MS = 5000;
  const SOCKET_TIMEOUT_MS = 7000;
  const HARD_CUTOFF_MS = 15000;

  const now = Date.now();
  if (now < T0 + START_DELAY_MS)
    await new Promise((r) => setTimeout(r, T0 + START_DELAY_MS - now));

  Log.log(`  Begin covert component phase (${components.length} total)`);

  // Build CovertMessages
  const sigs = (service as any)._blindSignatures;
  if (!sigs || sigs.length !== components.length)
    throw new Error(
      `Blind signature count mismatch: ${sigs?.length ?? 0} vs ${
        components.length
      }`
    );

  const covertMessages: Uint8Array[] = [];
  for (let i = 0; i < components.length; i++) {
    const comp = components[i];
    const sig = sigs[i];
    const compBytes = fusion.Component.encode(comp).finish();
    const covertComponent = fusion.CovertComponent.create({
      roundPubkey: service._startRound.roundPubkey,
      signature: sig,
      component: compBytes,
    });
    const covertMsg = fusion.CovertMessage.create({
      component: covertComponent,
    });
    covertMessages.push(fusion.CovertMessage.encode(covertMsg).finish());
  }
  Log.log(`Built ${covertMessages.length} CovertMessages`);

  //  BACKGROUND FETCH OF ALLCOMMITMENTS (main persistent channel)
  let allCommitmentsFetched = false;
  const allCommitmentsTask = (async () => {
    try {
      const msg = await service._torboar.receiveTcpDataPersistent({
        timeoutMs: SOCKET_TIMEOUT_MS,
      });
      if (!msg?.data) {
        Log.log("  No TCP data received");
        return;
      }

      const raw = hexToBytes(msg.data);
      const payload = raw.slice(12); //  strip 12-byte frame header

      let serverMsg;
      try {
        serverMsg = fusion.ServerMessage.decode(payload);
      } catch (e) {
        Log.log(` Failed to decode ServerMessage: ${e}`);
        return;
      }

      const typeKey = Object.keys(serverMsg).find((k) => serverMsg[k] != null);
      Log.log(` ServerMessage type=${typeKey ?? "<unknown>"}`);

      if (!serverMsg.allcommitments) {
        Log.log("  Not an allcommitments message, skipping.");
        return;
      }

      //  Decode AllCommitments
      let allCommit: any;
      if (serverMsg.allcommitments instanceof Uint8Array) {
        try {
          allCommit = fusion.AllCommitments.decode(serverMsg.allcommitments);
        } catch (err) {
          Log.log(`  Failed to decode raw AllCommitments bytes: ${err}`);
          return;
        }
      } else {
        allCommit = serverMsg.allcommitments;
      }

      const commits = allCommit.initialCommitments ?? [];
      Log.log(`allcommitments count=${commits.length}`);

      if (commits.length === 0) {
        Log.log(
          `  allcommitments empty — first 64B:\n${Buffer.from(
            payload.slice(0, 64)
          ).toString("hex")}`
        );
      }

      //  Decode each InitialCommitment
      for (let i = 0; i < commits.length; i++) {
        const entry = commits[i];
        try {
          let ic;
          if (entry instanceof Uint8Array) {
            ic = fusion.InitialCommitment.decode(entry);
          } else if (entry && typeof entry === "object") {
            ic = fusion.InitialCommitment.fromObject(entry);
          } else {
            Log.log(
              `    InitialCommitment #${i} invalid type: ${typeof entry}`
            );
            continue;
          }
        } catch (e) {
          Log.log(`    Failed to decode InitialCommitment #${i}: ${e}`);
        }
      }

      //  Persist raw protobuf for later phases (e.g. blame)
      service._allCommitments = allCommit;

      allCommitmentsFetched = true;
      Log.log("  Stored allcommitments successfully");
    } catch (err) {
      Log.log(`  allcommitments receive timeout/failure: ${err}`);
    }
  })();

  //  Submit covert components
  if (!service._torboar) throw new Error("Torboar not initialized");
  if (!service._circuitLedger?.size) throw new Error("No circuits available");

  await submitCovertData({
    torboar: service._torboar,
    payloads: covertMessages,
    circuitLedger: service._circuitLedger,
    t0: T0,
    task: "submit_components",
  });

  Log.log(`Covert component submissions complete`);

  //  Wait for commitments or cutoff
  const hardCutoff = T0 + HARD_CUTOFF_MS;
  while (Date.now() < hardCutoff && !allCommitmentsFetched) {
    await new Promise((r) => setTimeout(r, 500));
  }

  if (allCommitmentsFetched) Log.log(" allcommitments ready before cutoff");
  else Log.log("  allcommitments not received by cutoff");

  Log.log(" Covert phase complete — proceeding to next phase");
  return "download_all_components";
}

//----
//----
//----
//----

export async function phase_downloadAllComponents(
  service: FusionService
): Promise<FusionPhase> {
  Log.log("  Phase: download_all_components  ");

  const fusion = service._fusion;
  if (!service._torboar) {
    Log.log("  Torboar not initialized — cannot download");
    return "done";
  }

  const MAX_DURATION_MS = 60_000;
  const INTERVAL_MS = 5_000;
  const start = performance.now();

  let gotAllCommitments = false;
  let gotShareComponents = false;

  Log.log(
    `  Waiting for up to ${
      MAX_DURATION_MS / 1000
    }s to receive AllCommitments and/or ShareCovertComponents`
  );

  while (performance.now() - start < MAX_DURATION_MS && !gotShareComponents) {
    try {
      const res = await service._torboar.receiveTcpDataPersistent({
        timeoutMs: INTERVAL_MS,
      });
      if (!res?.data) continue;

      const raw = Buffer.from(res.data, "hex");
      let offset = 0;

      // Each TCP chunk may contain multiple protobuf messages; we only care about two total.
      while (offset + 12 <= raw.length) {
        const magic = raw.readUInt32BE(offset);
        const msgType = raw.readUInt32BE(offset + 4);
        const length = raw.readUInt32BE(offset + 8);
        const totalLen = 12 + length;
        if (offset + totalLen > raw.length) break;

        const payload = raw.subarray(offset + 12, offset + totalLen);
        offset += totalLen;

        let msg;
        try {
          msg = fusion.ServerMessage.decode(payload);
        } catch (e) {
          Log.log(`Failed to decode ServerMessage: ${e}`);
          continue;
        }

        const type = Object.keys(msg).find((k) => (msg as any)[k] != null);
        Log.log(
          `  Received ServerMessage type=${
            type ?? "unknown"
          } (magic=${magic}, type=${msgType}, len=${length})`
        );

        // Message 1 Here: AllCommitments
        if (msg.allcommitments && !gotAllCommitments) {
          service._allCommitments = msg.allcommitments as AllCommitmentsType;
          gotAllCommitments = true;

          continue;
        }

        // Message 2 Here: ShareCovertComponents (second or only message)
        if (msg.sharecovertcomponents) {
          const sc = msg.sharecovertcomponents as ShareCovertComponentsType;
          gotShareComponents = true;

          const skip = !!sc.skipSignatures;
          const hashHex = sc.sessionHash
            ? Buffer.from(sc.sessionHash).toString("hex")
            : "(none)";

          Log.log(
            `  ShareCovertComponents received: components=${
              sc.components?.length ?? 0
            }, skip_signatures=${skip}, session_hash=${hashHex}`
          );

          service._shareCovertComponents = sc;

          if (skip) {
            Log.log(
              " Server requested to skip signatures — entering blame phase"
            );
            return "blame1";
          }

          Log.log(" Stored ShareCovertComponents for next phase");
          return "get_round_hash";
        }
      }
    } catch (err) {
      Log.log(` Expected timeout while periodically fetching buffer: ${err}`);
    }

    await new Promise((r) => setTimeout(r, INTERVAL_MS));
  }

  Log.log(" Phase ended without receiving ShareCovertComponents");
  return "done";
}

//-----
//----
//----
//-----

export async function phase_getRoundHash(
  service: FusionService
): Promise<FusionPhase> {
  Log.log(" Phase: get_round_hash");

  const shareCovert = service._shareCovertComponents;

  // server skip route (no signatures phase at all)
  if (shareCovert?.skipSignatures === true) {
    Log.log("skipSignatures=TRUE — jumping to blame phase");
    return "blame1";
  }

  const startRound = service._startRound;
  const allCommitments = service._allCommitments;

  if (!startRound || !allCommitments || !shareCovert) {
    Log.log("Missing required round data");
    return "done";
  }

  if (!service._lastHash) {
    Log.log("Missing lastHash (calcInitialHash must run first)");
    return "done";
  }

  const roundTime = Number(startRound.serverTime);
  const commitments = allCommitments.initialCommitments ?? [];
  const components = shareCovert.components ?? [];

  Log.log(
    ` Computing session hash: commitments=${commitments.length}, components=${components.length}`
  );

  const sessionHash = await calcRoundHash(
    service._lastHash,
    startRound.roundPubkey,
    roundTime,
    commitments,
    components
  );

  // important to set the newest session hash into the "lasthash" so when the round restarts the new hash utilizes the old hash
  service._lastHash = sessionHash;

  const localHex = toHex(sessionHash);

  const serverHashBytes = shareCovert.sessionHash as Uint8Array | undefined;
  const serverHex = serverHashBytes ? toHex(serverHashBytes) : null;

  // strict verify
  if (!serverHex || serverHex !== localHex) {
    Log.log(
      `sessionHash mismatch (server=${
        serverHex ?? "missing"
      }, local=${localHex})`
    );
    return "done";
  }

  // match good
  service._sessionHash = sessionHash;
  Log.log("sessionHash verified and stored");

  return "covert_signatures";
}

//----
//----
//-----
//----
//----
//-----

export async function phase_covertSignatures(
  service: FusionService
): Promise<FusionPhase> {
  Log.log("Phase: covert signatures");

  const fusion = service._fusion;
  if (!fusion) throw new Error("fusion proto not loaded");

  // Helper: TS port of Python tx_from_components
  function txFromComponents_TS(allComps: Uint8Array[]) {
    const fusionInputs: any[] = [];
    const fusionOutputs: any[] = [];
    const inputIndices: number[] = [];

    for (let i = 0; i < allComps.length; i++) {
      let comp;
      try {
        comp = fusion.Component.decode(allComps[i]);
      } catch (e) {
        Log.log("[covertSignatures] decode failed at component", i, e);
        continue;
      }

      if (comp.input) {
        fusionInputs.push(comp.input);
        inputIndices.push(i); // global component index for this *tx input index*
      } else if (comp.output) {
        fusionOutputs.push(comp.output);
      }
      // blanks ignored
    }

    return { fusionInputs, fusionOutputs, inputIndices };
  }

  // Load canonical shuffled component list from server
  const comps: Uint8Array[] = service._shareCovertComponents?.components ?? [];
  if (!comps.length) {
    throw new Error("ShareCovertComponents is empty or missing");
  }

  const gen = service._generatedComponents;
  if (!gen) throw new Error("no generated components data");

  const myComps: Uint8Array[] = gen.serializedComponents ?? [];

  // Map my components to global component indices
  const myComponentIndices = myComps.map((c, localIdx) => {
    const idx = comps.findIndex((x) => Buffer.compare(x, c) === 0);
    if (idx === -1) {
      throw new Error(`Missing my component (local index ${localIdx})`);
    }
    return idx;
  });

  Log.log(
    "[covertSignatures] myComponentIndices:",
    myComponentIndices.join(", ")
  );

  // Build tx + inputIndices (Python: tx, input_indices)
  const { fusionInputs, fusionOutputs, inputIndices } =
    txFromComponents_TS(comps);

  Log.log(
    `[covertSignatures] fusionInputs=${fusionInputs.length}, fusionOutputs=${fusionOutputs.length}`
  );

  // Determine which of my components are inputs

  // Which of MY components correspond to TX inputs?
  const myInputComponentIndices = myComponentIndices.filter((ci) =>
    inputIndices.includes(ci)
  );

  Log.log(
    "[covertSignatures] myInputComponentIndices:",
    myInputComponentIndices.join(", ")
  );

  if (myInputComponentIndices.length === 0) {
    Log.log("[covertSignatures] No input components to sign; skipping.");
    return "fusion_result";
  }

  // Determine which of my components are outputs

  const myOutputComponentIndices = myComponentIndices.filter((ci) => {
    const comp = fusion.Component.decode(comps[ci]);
    return !!comp.output;
  });

  Log.log(
    "[covertSignatures] myOutputComponentIndices:",
    myOutputComponentIndices.join(", ")
  );

  // SAFETY CHECK: Ensure my outputs do not exceed my inputs

  let myTotalInputs = 0;
  let myTotalOutputs = 0;

  // sum my input amounts
  for (let i = 0; i < fusionInputs.length; i++) {
    const globalIdx = inputIndices[i]; // global component index for this tx input

    if (myInputComponentIndices.includes(globalIdx)) {
      const inp = fusionInputs[i];
      myTotalInputs += Number(inp.amount);
    }
  }

  // sum my output amounts
  for (const globalIdx of myOutputComponentIndices) {
    // global outputs correspond to fusionOutputs in order of appearance
    let runningIdx = 0;
    let found = false;

    // loop through comps in original order, counting only outputs
    for (let i = 0; i < comps.length; i++) {
      const comp = (() => {
        try {
          return fusion.Component.decode(comps[i]);
        } catch {
          return null;
        }
      })();

      if (comp?.output) {
        if (i === globalIdx) {
          myTotalOutputs += Number(comp.output.amount);
          found = true;
          break;
        }
      }
    }

    if (!found) {
      Log.log(
        `[covertSignatures] Could not locate my output component at global index ${globalIdx}`
      );
    }
  }

  Log.log(
    `[covertSignatures] SAFETY CHECK: myTotalInputs=${myTotalInputs}, myTotalOutputs=${myTotalOutputs}`
  );

  const max_outflow_safety_check = Protocol.MAX_FEE;

  if (myTotalInputs > myTotalOutputs) {
    const diff = myTotalInputs - myTotalOutputs;

    if (diff > max_outflow_safety_check) {
      Log.log(
        `[covertSignatures] SAFETY FAIL: outputs exceed inputs by ${diff} sats (> ${max_outflow_safety_check}). Aborting fusion.`
      );
      throw new Error(
        `CovertSignature safety violation: outputs exceed inputs by ${diff} sats`
      );
    }
  }

  // Build the unsigned fusion transaction
  const opRet = generateFusionOpReturn(service._sessionHash);
  const orderedOutputs = [opRet, ...fusionOutputs];

  const unsignedTx = buildUnsignedTransaction(
    fusionInputs,
    orderedOutputs,
    0 // locktime
  );

  service._unsignedTx = unsignedTx;

  // Signing loop
  const SIGHASH_ALL = 0x41;
  const sigMessages: Uint8Array[] = [];

  for (let i = 0; i < inputIndices.length; i++) {
    const cidx = inputIndices[i]; // global component index for tx input i

    if (!myInputComponentIndices.includes(cidx)) {
      continue; // not my input
    }

    const inp = fusionInputs[i];

    // Wallet UTXO privkey lookup
    const walletUtxo = service._inputs.find(
      (u) =>
        Number(u.tx_pos) === Number(inp.prevIndex) &&
        (equalBytes(hexToBin(u.txid), inp.prevTxid) ||
          equalBytes(hexToBin(u.txid), Uint8Array.from(inp.prevTxid).reverse()))
    );

    if (!walletUtxo) {
      throw new Error(
        `[covertSignatures] Privkey lookup failed for component index ${cidx}`
      );
    }

    const priv = service._hdNode.deriveAddressPrivateKey(walletUtxo.address);

    // Preimage + Schnorr signature
    const preimage = computePreimage(unsignedTx, i, fusionInputs, SIGHASH_ALL);

    const sig = await signPreimageSchnorr(service._torboar, preimage, priv);

    const inner = fusion.CovertTransactionSignature.create({
      roundPubkey: service._roundPubKey,
      whichInput: i,
      txsignature: sig,
    });

    const outer = fusion.CovertMessage.create({ signature: inner });
    const encoded = fusion.CovertMessage.encode(outer).finish();

    sigMessages.push(encoded);

    Log.log(
      `[covertSignatures] Signed component cidx=${cidx} ... tx input i=${i}`
    );
  }

  // Submit covert signatures

  const T0 = service._covertT0 ?? Date.now();

  await submitCovertData({
    torboar: service._torboar,
    payloads: sigMessages,
    circuitLedger: service._circuitLedger,
    t0: T0,
    task: "submit_signatures",
  });

  Log.log("covert signature submission complete");
  return "fusion_result";
}

//----
//----
//-----
//----
//----
//-----

export async function phase_fusionResult(
  service: FusionService
): Promise<FusionPhase> {
  const fusion = service._fusion;
  if (!fusion) throw new Error("Fusion proto not loaded");

  Log.log("Phase: fusion_result — waiting for FusionResult");

  const torboar = service._torboar;

  const start = Date.now();
  const timeoutMs = 60000;
  const maxEndTime = start + timeoutMs;

  while (Date.now() < maxEndTime) {
    // Optional heartbeat
    const alive = await torboar.checkTcpStatusPersistent();
    Log.log(
      ` fusion_result: alive=${alive?.alive} elapsed=${(
        (Date.now() - start) /
        1000
      ).toFixed(1)}s`
    );

    // Read buffer
    let res;
    try {
      res = await torboar.receiveTcpDataPersistent({ timeoutMs: 5000 });
    } catch (err) {
      Log.log(` fusion_result: nothing yet (normal). Retrying...`);
      continue;
    }

    if (!res?.data) {
      Log.log(" fusion_result: empty read, retry...");

      continue;
    }

    // Parse response
    let responseBytes: Uint8Array;
    try {
      responseBytes = fromHex(res.data);
    } catch (hexErr) {
      Log.log(" fusion_result: bad hex:", hexErr);
      continue;
    }

    if (responseBytes.length <= 12) {
      Log.log(" fusion_result: header only, retry...");
      continue;
    }

    const payload = responseBytes.slice(12);

    // Decode proto
    let serverMsg: any;
    try {
      serverMsg = fusion.ServerMessage.decode(payload);
    } catch (decodeErr) {
      Log.log(" fusion_result decode error:", decodeErr);
      continue;
    }

    const keys = Object.keys(serverMsg).filter(
      (k) => serverMsg[k] !== null && serverMsg[k] !== undefined
    );
    Log.log(" fusion_result ServerMessage keys:", keys);

    // If server sent error
    if (serverMsg.error) {
      Log.log(`SERVER ERROR: ${serverMsg.error.message}`);
      return "done";
    }

    // Did we get FusionResult?
    const fusionResult = serverMsg.fusionresult;
    service._fusionResult = fusionResult;

    if (!fusionResult) {
      Log.log(" fusion_result: not FusionResult, still waiting...");
      continue;
    }

    //  GOT THE MESSAGE
    Log.log(" FusionResult received!");

    if (fusionResult.ok === false) {
      Log.log(" FusionResult.ok = false — entering blame1 phase");
      service._fusionResult = fusionResult; // store if needed later
      return "blame1";
    }

    if (fusionResult.ok === true) {
      Log.log("FUSION TRANSACTION COMPLETED!");
      return "broadcast";
    }
  }

  Log.log("  fusion_result TIMED OUT after 50 seconds");
  return "done";
}

//----
//----
//----

export async function phase_broadcast(
  service: FusionService
): Promise<FusionPhase> {
  Log.log(" Phase: broadcast");

  const fusionResult = service._fusionResult;
  if (!fusionResult) {
    throw new Error("phase_broadcast: missing fusionResult");
  }

  const { ok, txsignatures, bad_components } = fusionResult;

  if (!ok) {
    Log.log("[broadcast] Fusion failed. bad_components =", bad_components);
    return "done";
  }

  //  Pull the unsignedTx
  const unsignedTx = service._unsignedTx;
  if (!unsignedTx) {
    throw new Error("phase_broadcast: unsignedTx missing");
  }

  // Extract componentInputs from shareCovertComponents
  const covert = service._shareCovertComponents;
  if (!covert?.components) {
    throw new Error(
      "phase_broadcast: missing shareCovertComponents.components"
    );
  }

  const allComps = covert.components; // array of serialized Component bytes
  const componentInputs: ComponentInput[] = [];

  for (let i = 0; i < allComps.length; i++) {
    const comp = service._fusion.Component.decode(allComps[i]);

    if (comp.input) {
      componentInputs.push({
        prevTxid: comp.input.prevTxid,
        prevIndex: comp.input.prevIndex,
        pubkey: comp.input.pubkey,
        amount: comp.input.amount,
      });
    }
  }

  if (txsignatures.length !== componentInputs.length) {
    throw new Error(
      `Signature count mismatch: server=${txsignatures.length}, inputs=${componentInputs.length}`
    );
  }

  // Build signed inputs from schnorr sigs
  const signedInputs: any[] = [];

  for (let i = 0; i < txsignatures.length; i++) {
    const sigRaw = new Uint8Array(txsignatures[i]); // raw 64-byte signature

    if (sigRaw.length !== 64) {
      Log.log(
        `[broadcast] Signature ${i} unexpected length ${sigRaw.length}, expected 64`
      );
    }

    const inp = componentInputs[i];
    const signedInput = buildSignedInput(inp, sigRaw, inp.pubkey);
    signedInputs.push(signedInput);
  }

  //  Extract outputs directly from unsignedTx
  const componentOutputs: ComponentOutput[] = unsignedTx.outputs.map(
    (o: any) => ({
      scriptpubkey: o.lockingBytecode,
      amount: Number(o.valueSatoshis),
    })
  );

  Log.log("[broadcast] componentOutputs:", componentOutputs.length);

  // Final transaction assembly
  const finalTx = finalizeTransaction(
    signedInputs,
    componentOutputs,
    unsignedTx.locktime ?? 0
  );

  const finalHex = toHex(finalTx);

  //--------------------------------------------
  // Here we can insert a call to broadcast this.
  //
  // TODO: ACTUALLY BROADCAST THIS RAW HEX
  // --------------------------------------------

  try {
    Log.log("FULL FINAL TX HEX (length =", finalHex.length, ")");

    const chunkSize = 1000;
    for (let i = 0; i < finalHex.length; i += chunkSize) {
      const chunk = finalHex.slice(i, i + chunkSize);
      Log.log(`  [${i} - ${i + chunk.length}] ${chunk}`);
    }
  } catch (e) {
    Log.log("  Failed to encode final tx:", e);
  }

  return "done";
}

//----
//----
//----
//----

export async function phase_blame1(
  service: FusionService
): Promise<FusionPhase> {
  Log.log("  Phase: blame1 (sending proofs)");

  const fusion = service._fusion;
  if (!fusion) throw new Error("fusion proto not loaded");

  const gen = service._generatedComponents;
  if (!gen) throw new Error("no generated components data");

  const allCommitmentsPB = service._allCommitments;
  if (!allCommitmentsPB) throw new Error("Missing allCommitments");

  const torboar = service._torboar;
  if (!torboar) throw new Error("torboar not available");

  const myCommitments = gen.initialCommitments;
  const myProofs = gen.proofs;

  const randomNumber = service._randomNumber;
  if (!randomNumber) throw new Error("missing randomNumber commit");

  // Decode all commitments (used only for choosing dest commitments)
  const allPB = allCommitmentsPB.initialCommitments;
  const decodedAll: any[] = allPB.map((b) =>
    fusion.InitialCommitment.decode(b)
  );

  // CANONICAL MAPPING: component bytes to global COMPONENT indices
  const share = service._shareCovertComponents;
  if (!share) throw new Error("Missing ShareCovertComponents at blame1");

  const globalComponents = share.components ?? []; // Uint8Array[]
  const mySerializedComponents = gen.serializedComponents ?? []; // Uint8Array[]

  const myComponentIndicesFromComponents: number[] = mySerializedComponents.map(
    (cSer, localIdx) => {
      const cObj = gen.components?.[localIdx];

      let kind = "UNKNOWN";
      if (cObj?.input) kind = "INPUT";
      if (cObj?.output) kind = "OUTPUT";
      if (cObj?.blank) kind = "BLANK";

      const serLen = cSer.length;

      const idx = globalComponents.findIndex((gSer, gi) => {
        const match = Buffer.compare(gSer, cSer) === 0;

        return match;
      });

      return idx;
    }
  );

  // Choose destination commitments
  const allIdxes = decodedAll.map((_, i) => i);

  // Identify our commitments by salted hash:
  const myCommitmentIdxes = decodedAll
    .map((c, i) => ({
      i,
      h: Buffer.from(c.saltedComponentHash).toString("hex"),
    }))
    .filter((obj) =>
      myCommitments.some(
        (mine) =>
          Buffer.from(mine.saltedComponentHash).toString("hex") === obj.h
      )
    )
    .map((obj) => obj.i);

  const otherIdxes = allIdxes.filter((i) => !myCommitmentIdxes.includes(i));
  if (otherIdxes.length === 0)
    throw new Error("Fusion failed with only me as player");

  const dstCommits: any[] = [];
  for (let i = 0; i < myCommitments.length; i++) {
    const pos = await randPosition(randomNumber, otherIdxes.length, i);
    dstCommits.push(decodedAll[otherIdxes[pos]]);
  }

  // ENCRYPT PROOFS
  const encProofs: Uint8Array[] = [];

  for (let i = 0; i < myProofs.length; i++) {
    const proof = myProofs[i];
    const commitPB = dstCommits[i];

    proof.componentIdx = myComponentIndicesFromComponents[i];

    const serialized = fusion.Proof.encode(proof).finish();

    let encrypted: Uint8Array = new Uint8Array();
    try {
      encrypted = await encrypt(serialized, commitPB.communicationKey, 80);
      encProofs.push(encrypted);
    } catch (e) {
      Log.log(" encrypt failure on proof", e);
      encProofs.push(encrypted);
    }
  }

  // SEND MyProofsList
  const msg = fusion.MyProofsList.create({
    encryptedProofs: encProofs,
    randomNumber,
  });

  const clientMsg = fusion.ClientMessage.create({
    myproofslist: msg,
  });

  const payloadBytes = fusion.ClientMessage.encode(clientMsg).finish();
  const frame = createFrameBytes(payloadBytes);

  await torboar.sendTcpDataPersistent({ data: toHex(frame) });

  Log.log("  Sent MyProofsList to server");

  return "blame2";
}

//-----
//----
//----
//-----

export async function phase_blame2(
  service: FusionService
): Promise<FusionPhase> {
  Log.log(" Phase: blame2 (waiting for TheirProofsList)");

  const res = await service._torboar.receiveTcpDataPersistent({
    timeoutMs: 5000,
  });

  const raw = Buffer.from(res.data, "hex");
  const buf = new Uint8Array(raw.slice(12));

  let msg: any;
  try {
    msg = service._fusion!.ServerMessage.decode(buf);
  } catch (e) {
    Log.log(`blame phase decode failure, bufLen=${buf.length}`);

    throw new Error("blame2 decode failed: " + (e as Error).message);
  }

  if (!msg.theirproofslist) {
    throw new Error("Expected TheirProofsList");
  }

  service._theirProofsList = msg.theirproofslist;

  return "blame3";
}

//----
//----
//-----
//----
//----
//-----

export async function phase_blame3(
  service: FusionService
): Promise<FusionPhase> {
  const blames: any[] = [];
  const theirProofsList = service._theirProofsList?.proofs ?? [];
  Log.log(`        total proofs: ${theirProofsList.length}`);

  for (let i = 0; i < theirProofsList.length; i++) {
    const p = theirProofsList[i];
    const enc = Buffer.from(p.encryptedProof ?? []).toString("hex");
    const encBytes = p.encryptedProof;
    const src = p.srcCommitmentIdx;
    const dst = p.dstKeyIdx;

    const privkey = service._generatedComponents.commPrivKeys[dst];

    let proofBlob: Uint8Array;
    let sessionKey: Uint8Array;

    try {
      // Try decrypting with the current key
      const dec = await decrypt(encBytes, privkey);
      proofBlob = dec.plaintext;
      sessionKey = dec.symKey;
    } catch (e) {
      Log.log(` Decrypt attempt failed with key #${i}: ${e}`);

      blames.push(
        service._fusion.Blames.BlameProof.create({
          whichProof: i,
          privkey, // 32-byte commPrivKey scalar for this dst
          blameReason: `undecryptable: ${String(e)}`,
        })
      );

      continue; //skip validation entirely for this proof since it can't be decrypted.
    }

    // prepare for validation
    const allComponents = service._shareCovertComponents?.components ?? [];
    const allCommitments = service._allCommitments?.initialCommitments ?? [];
    const commitmentBlob = allCommitments[src];
    const commitmentPB =
      service._fusion.InitialCommitment.decode(commitmentBlob);

    try {
      const badComponents: number[] = [];
      const componentFeerate = Number(service._componentFeerate ?? 0);

      const inpComp = await service.validateProofInternal(
        proofBlob,
        commitmentPB,
        allComponents,
        badComponents,
        componentFeerate
      );
    } catch (e) {
      Log.log(`Proof #${i} failed validation: ${e}`);
      blames.push(
        service._fusion.Blames.BlameProof.create({
          whichProof: i,
          sessionKey, // 32-byte AES key derived from decrypt()
          blameReason: String(e),
        })
      );
    }
  } //end for loop.

  // Wrap and send Blames to server
  const fusion = service._fusion!;
  const blamesMsg = fusion.Blames.create({ blames });

  const clientMessage = fusion.ClientMessage.create({
    blames: blamesMsg,
  });

  const payloadBytes = fusion.ClientMessage.encode(clientMessage).finish();
  const frameBytes = createFrameBytes(payloadBytes);

  Log.log(`Sending Blames (${blames.length}) to server...`);

  await service._torboar.sendTcpDataPersistent({
    data: Buffer.from(frameBytes).toString("hex"),
  });

  Log.log(" Blames sent, moving to blame4 (awaiting RestartRound)");

  return "blame4";
}

//----
//----
//-----
//----
//----
//-----

export async function phase_blame4(
  service: FusionService
): Promise<FusionPhase> {
  const fusion = service._fusion;
  const torboar = service._torboar;
  const start = Date.now();
  const timeoutMs = 50000;
  const maxEndTime = start + timeoutMs;

  while (Date.now() < maxEndTime) {
    //  Check buffer
    const status = await torboar.checkTcpStatusPersistent().catch(() => null);
    if (!status?.alive) {
      Log.log(" blame4: socket dead");
      return "done";
    }

    //  Attempt read
    const res = await torboar
      .receiveTcpDataPersistent({ timeoutMs: 5000 })
      .catch(() => null);

    if (!res?.data) continue;

    // Frame the payload
    const frame = fromHex(res.data);
    if (frame.length <= 12) continue;
    const payload = frame.slice(12);

    // Decode ServerMessage
    let msg;
    try {
      msg = fusion.ServerMessage.decode(payload);
    } catch {
      continue;
    }

    //  Server error
    if (msg.error) {
      Log.log(`SERVER ERROR: ${msg.error.message}`);
      return "done";
    }

    // RestartRound
    if (msg.restartround) {
      Log.log(" RestartRound received");
      return "wait_for_start_round";
    }
  }

  throw new Error("Timeout waiting for RestartRound");
}
