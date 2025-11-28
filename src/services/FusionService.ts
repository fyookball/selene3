// Manages a persistent FusionService that continuously checks
// whether a new fusion round loop should start.
// The main loop manages flow in the fusion protocol
// and passes control from one phase to the next,
// with the phase functionality living in FusionPhase.ts.
// This main file also contains some major helper
// functions as well as functions that deal more
// with the wallet layer.

/* eslint-disable @typescript-eslint/naming-convention */
/* eslint-disable prefer-destructuring */
/* eslint-disable no-restricted-syntax */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable prefer-const */
/* eslint-disable no-await-in-loop */
/* eslint-disable no-promise-executor-return */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-plusplus */
/* eslint-disable no-else-return*/
/* eslint-disable no-undef-init */
/* eslint-disable no-empty */
/* eslint-disable prefer-template */
/* eslint-disable class-methods-use-this */
/* eslint-disable no-continue */
/* eslint-disable no-bitwise */

import Long from "long";
import { Plugins } from "@capacitor/core";
import LogService from "@/services/LogService";
import UtxoManagerService from "@/services/UtxoManagerService";
import { Protocol } from "./FusionProtocol/protocol";
import { block_checkpoints } from "@/util/block_checkpoints";
import AddressManagerService from "@/services/AddressManagerService";
import { WalletEntity } from "@/services/WalletManagerService";
import { CovertSubmitter } from "./FusionProtocol/covert";
import { Commitment, PedersenSetup } from "./FusionProtocol/pedersen";
import HdNodeService from "@/services/HdNodeService";
import { convertCashAddress } from "../util/cashaddr";
import { BlindSignatureRequest } from "./FusionProtocol/schnorr";
import { encrypt, decrypt } from "./FusionProtocol/encrypt"; //blame phase.
import { secp } from "./FusionProtocol/secp_helper";

import {
  genKeypair,
  calcInitialHash,
  randomOutputsForTier,
  componentFee,
  sizeOfInput,
  sizeOfOutput,
  sha256,
  toHex,
  hexToBytes,
  bytesToHex,
  hash160,
  buildP2PKHScript,
  randomScalar,
  intToBytesBE,
  equalBytes,
} from "./FusionProtocol/util";

import {
  phase_starting,
  phase_selectingInputs,
  phase_sendGreet,
  phase_waitForServerHello,
  phase_allocateOutputs,
  phase_joinPools,
  phase_waitForFusionBegin,
  phase_prepareCovert,
  phase_waitForStartRound,
  phase_generateComponents,
  phase_sendPlayerCommit,
  phase_blindSignatures,
  phase_pedersenSetup,
  phase_receiveBlindSigResponses,
  phase_covertComponents,
  phase_downloadAllComponents,
  phase_getRoundHash,
  phase_covertSignatures,
  phase_fusionResult,
  phase_broadcast,
  phase_blame1,
  phase_blame2,
  phase_blame3,
  phase_blame4,
} from "@/services/FusionProtocol/FusionPhase";

import type { FusionPhase } from "@/services/FusionProtocol/util";

const Log = LogService("FusionService");

const { Torboar } = Plugins;

type Utxo = {
  address: string;
  txid: string;
  tx_pos: number;
  amount: bigint;
  memo: string | null;
};

type ServerHelloType = import("@/proto/fusion").fusion.ServerHello;
type ComponentType = import("@/proto/fusion").fusion.Component;
type InitialCommitmentType = import("@/proto/fusion").fusion.InitialCommitment;
type ProofType = import("@/proto/fusion").fusion.Proof;
type FusionBeginType = import("@/proto/fusion").fusion.FusionBegin;
type InputComponentType = import("@/proto/fusion").fusion.InputComponent;
type OutputComponentType = import("@/proto/fusion").fusion.OutputComponent;
type AllCommitmentsType = import("@/proto/fusion").fusion.AllCommitments;
type ShareCovertComponentsType =
  import("@/proto/fusion").fusion.ShareCovertComponents;
type fusionResultType = import("@/proto/fusion").fusion.fusionResult;

export interface GenComponentsResult {
  initialCommitments: InitialCommitmentData[];
  componentIndices: number[];
  serializedComponents: Uint8Array[];
  proofs: ProofType[];
  commPrivKeys: Uint8Array[];
  totalAmount: bigint;
  pedersenTotalNonce: Uint8Array;
  components: ComponentType[];
}

// Fusion Protocol Components (from fusion.proto)

export interface InitialCommitmentData {
  saltedComponentHash: Uint8Array;
  amountCommitment: Uint8Array;
  communicationKey: Uint8Array;
}

export type ComponentInput = {
  prevTxid: Uint8Array;
  prevIndex: number; // uint32
  pubkey: Uint8Array; // compressed pubkey
  amount: number; // uint64
};

export type ComponentOutput = {
  scriptpubkey: Uint8Array;
  amount: number; // uint64
};

//  ----------------------------------------------------

export class FusionService {
  private _isRunning = false;

  private _shouldStopRequested = false;

  private _currentRound: Promise<void> | null = null;

  private _wallet: WalletEntity;

  private _walletHash: string;

  private _utxoManager: ReturnType<typeof UtxoManagerService>;

  private static _defaultMaxCoins = 10;

  private _fusion?: typeof import("@/proto/fusion").fusion;

  private _tier?: number;

  private _covertDomain?: string;

  private _covertPort?: number;

  private _covertSsl?: boolean;

  private _beginTime?: number;

  private _tFusionBegin?: number;

  private _lastHash?: Uint8Array;

  private _tierOutputs: Record<number, number[]> = {};

  private _safetyExcessFees: Record<number, number> = {};

  private _safetySumIn = 0;

  private _minExcessFee = 0;

  private _maxExcessFee = 0;

  private _numComponents = 0;

  private _componentFeerate = 0;

  private _reservedAddresses: string[] = [];

  private _inputs: Utxo[] = [];

  private _outputs: Array<[number, string]> = [];

  private _hdNode: ReturnType<typeof HdNodeService>;

  private _torboar: typeof Torboar;

  private _serverHello?: ServerHelloType;

  private _fusionBegin?: FusionBeginType;

  private _startRound?: StartRoundType;

  private _covertSubmitter?: CovertSubmitter;

  private _roundInputs: InputComponentType[] = [];

  private _roundOutputs: OutputComponentType[] = [];

  private _generatedComponents: GenComponentsResult | null = null;

  private _covertT0: number = 0; // unix timestamp for critical schedule from startround.

  private _circuitLedger: Map<string, CircuitRecord> = new Map();

  private _randomSalts: Uint8Array[] = [];

  private _allCommitments?: AllCommitmentsType;

  private _shareCovertComponents?: ShareCovertComponentsType;

  private _randomNumber?: Uint8Array;

  private _fusionResult: fusionResultType[] = [];

  private _unsignedTx: any = null;

  constructor(wallet: WalletEntity) {
    this._wallet = wallet;
    this._walletHash = wallet.walletHash;
    this._utxoManager = UtxoManagerService(this._walletHash);
    this._hdNode = HdNodeService(wallet);
    this._torboar = Torboar;
    Log.log("FusionService initialized with wallet:", this._walletHash);
  }

  public async start(): Promise<void> {
    if (this._isRunning) {
      Log.log("FusionService already running");
      return;
    }

    try {
      await Torboar.startTor();
      Log.log("Torboar.startTor() succeeded");
    } catch (e) {
      Log.log("Torboar.startTor() failed", e);
      throw e;
    }

    this._isRunning = true;
    this._shouldStopRequested = false;
    if (!this._fusion) {
      try {
        // Get the Protobuf Object.
        const { fusion } = await import("@/proto/fusion");
        this._fusion = fusion;
      } catch (err) {
        Log.log("Failed to import fusion proto:", err);
      }
    }
    this._scheduleNextRound();
  }

  public stop(): void {
    this._shouldStopRequested = true;
  }

  // This function keeps the fusions rolling along,
  // from one round to the next.  When a round
  // ends, start the next one.
  private _scheduleNextRound(): void {
    const formatError = (err: any): string => {
      try {
        if (!err) return "<no error>";
        if (err instanceof Error)
          return `${err.name}: ${err.message}\n${err.stack ?? ""}`;
        if (
          typeof err.toString === "function" &&
          err.toString !== Object.prototype.toString
        )
          return err.toString();
        return JSON.stringify(err, Object.getOwnPropertyNames(err));
      } catch {
        return String(err);
      }
    };

    setTimeout(() => {
      if (this._shouldStopRequested) {
        this._isRunning = false;
        Log.log("FusionService stopped");
        return;
      }

      if (!this._currentRound) {
        this._currentRound = this._runFusionRoundLoop()
          .catch((err) => {
            Log.log(`[FusionService] Fusion round failed: ${formatError(err)}`);
          })
          .finally(() => {
            this._currentRound = null;
            this._scheduleNextRound(); // COMMENT OUT if you want to debug and run only single round at a time.
          });
      } else {
        Log.log(
          "Fusion round in progress. Scheduler is waiting for round to finish..."
        );
      }
    }, 10000);
  }

  // get all UTXOs available in the wallet.
  private async _grabWalletUtxos(): Promise<Utxo[]> {
    Log.log(`Grabbing wallet UTXOs for walletHash: ${this._walletHash}`);

    const coins = this._utxoManager.getWalletCoins() as Utxo[];
    const utxos = coins ?? [];

    return utxos;
  }

  // Select some UTXOs for our fusion round.
  private _selectRandomUtxos(
    allUtxos: Utxo[],
    inclusionProbability = 0.5
  ): Utxo[] {
    const addressMap = new Map<string, Utxo[]>();
    allUtxos.forEach((utxo) => {
      if (!addressMap.has(utxo.address)) {
        addressMap.set(utxo.address, []);
      }
      addressMap.get(utxo.address)!.push(utxo);
    });

    const addressEntries = Array.from(addressMap.entries());
    // Shuffle addresses to randomize selection
    addressEntries.sort(() => Math.random() - 0.5);

    let selected: Utxo[] = [];
    selected = addressEntries.reduce((acc, [address, utxos]) => {
      // Skip addresses with too many UTXOs
      if (utxos.length > 5) {
        Log.log(
          `Skipping address ${address} with ${utxos.length} UTXOs (too many)`
        );
        return acc;
      }

      // Skip addresses that do not meet the inclusion probability
      if (Math.random() > inclusionProbability) {
        return acc;
      }

      // Skip if selecting these UTXOs would exceed max coins
      if (acc.length + utxos.length > FusionService._defaultMaxCoins) {
        Log.log(`Skipping address ${address} due to exceeding MAX_COINS`);
        return acc;
      }

      // Add the UTXOs to the selected list

      return [...acc, ...utxos];
    }, [] as Utxo[]);

    Log.log(
      `fusion Selected ${selected.length} UTXOs out of ${allUtxos.length}`
    );

    return selected;
  }

  // Allocate outputs for the fusion round.
  public allocateOutputs(): void {
    const numInputs = this._inputs.length;

    // Compute maximum outputs allowed
    const maxComponents = Math.min(
      this._numComponents,
      Protocol.MAX_COMPONENTS
    );
    const maxOutputs = maxComponents - numInputs;
    // This is where we could add logic to force MaxOutputs to be a different value based on "consolidation mode" (not implemented yet)

    // Enforce minimum outputs
    const uniqueAddresses = new Set(this._inputs.map((u) => u.address));
    const numDistinct = uniqueAddresses.size;

    const minOutputs = Math.max(Protocol.MIN_TX_COMPONENTS - numDistinct, 1);

    if (maxOutputs < minOutputs) {
      throw new Error(
        `Too few distinct inputs selected (${numDistinct}); cannot satisfy output count constraint (>=${minOutputs}, <=${maxOutputs})`
      );
    }

    // Compute available value
    const sumInputsValue = (this._inputs || [])
      .map((u) => Number(u.amount))
      .reduce((a, b) => a + b, 0);

    // compute per-input fee using sizeOfInput and componentFee
    const inputFees = (this._inputs || [])
      .map((u) => componentFee(sizeOfInput(u), this._componentFeerate))
      .reduce((a, b) => a + b, 0);

    const availForOutputs = sumInputsValue - inputFees - this._minExcessFee;

    // Compute per-output cost
    const feePerOutput = componentFee(34, this._componentFeerate);
    const offsetPerOutput = Protocol.MIN_OUTPUT + feePerOutput;

    if (availForOutputs < offsetPerOutput) {
      throw new Error("Selected inputs had too little value");
    }

    // RNG setup — expovariate random number generator
    const rng = {
      expovariate: (lambd: number) => -Math.log(1 - Math.random()) / lambd,
    };

    // Iterate over available tiers
    const tierOutputs: Record<number, number[]> = {};
    const excessFees: Record<number, number> = {};

    this.availableTiers.forEach((scale) => {
      const fuzzFeeMax = Math.floor(scale / 1_000_000);
      const fuzzFeeMaxReduced = Math.min(
        fuzzFeeMax,
        Protocol.MAX_EXCESS_FEE - this._minExcessFee,
        this._maxExcessFee - this._minExcessFee
      );

      if (fuzzFeeMaxReduced < 0) {
        return;
      }

      const fuzzFee = Math.floor(Math.random() * (fuzzFeeMaxReduced + 1));
      const reducedAvailForOutputs = availForOutputs - fuzzFee;

      if (reducedAvailForOutputs < offsetPerOutput) {
        //double check this logic.
        return;
      }

      const outputs = randomOutputsForTier(
        rng,
        reducedAvailForOutputs,
        scale,
        offsetPerOutput,
        maxOutputs
      );

      if (!outputs || outputs.length < minOutputs) {
        //double chcek this logic
        return;
      }

      const adjustedOutputs = outputs.map((o) => o - feePerOutput);

      if (
        this._inputs.length + adjustedOutputs.length >
        Protocol.MAX_COMPONENTS
      ) {
        Log.log("probelm with inputs and outputs length.");
        return;
      }

      excessFees[scale] = sumInputsValue - inputFees - reducedAvailForOutputs;
      tierOutputs[scale] = adjustedOutputs;
    });

    //  Safety values
    this._tierOutputs = tierOutputs;
    this._safetyExcessFees = excessFees;
    this._safetySumIn = sumInputsValue;
  }

  private async _grabChangeAddresses(outAmounts: number[]) {
    const addrMgr = AddressManagerService(this._wallet.walletHash);
    const outAddrs = addrMgr.getUnusedAddresses(outAmounts.length, 1);
    return outAddrs;
  }

  // This function takes wallet structure UTXO and
  // forges them into fusion Input Components.
  private async createInputComponents(
    selectedUtxos: Utxo[]
  ): Promise<ComponentInput[]> {
    if (!Array.isArray(selectedUtxos)) {
      throw new Error("selectedUtxos is not an array");
    }

    return Promise.all(
      selectedUtxos.map(async (utxo, idx) => {
        if (!utxo || typeof utxo !== "object") {
          throw new Error(
            `Invalid utxo at index ${idx}: ${JSON.stringify(utxo)}`
          );
        }

        const requiredFields = ["txid", "tx_pos", "address", "amount"];
        for (const field of requiredFields) {
          if (!(field in utxo)) {
            throw new Error(`Missing field '${field}' in UTXO at index ${idx}`);
          }
        }

        const publicKeyHex = this._hdNode.getAddressPublicKey(utxo.address);
        const pubkey = Uint8Array.from(Buffer.from(publicKeyHex, "hex"));
        const prevTxid = Uint8Array.from(
          Buffer.from(utxo.txid, "hex")
        ).reverse();

        const prevIndex = Long.fromValue(utxo.tx_pos);
        const amount = Long.fromValue(utxo.amount);

        if (!Long.isLong(prevIndex) || !Long.isLong(amount)) {
          throw new Error(
            `Long conversion failed at index ${idx}: prevIndex=${utxo.tx_pos}, amount=${utxo.amount}`
          );
        }

        return {
          prevTxid,
          prevIndex,
          pubkey,
          amount,
        };
      })
    );
  }

  // This function takes wallet structure UTXO and
  // forges them into fusion Output Components.
  private async createOutputComponents(
    outputs: Array<[number, AddressEntity]>
  ): Promise<ComponentOutput[]> {
    return Promise.all(
      outputs.map(async ([amount, addressObj]) => {
        const publicKeyHex = this._hdNode.getAddressPublicKey(
          addressObj.address
        );
        const pubkey = Uint8Array.from(Buffer.from(publicKeyHex, "hex"));

        const pubkeyHash = await hash160(pubkey);
        const scriptPubKey = await buildP2PKHScript(pubkeyHash);

        return {
          scriptpubkey: scriptPubKey,
          amount,
        };
      })
    );
  }

  //------------------------------
  // This is a major helper function to generate
  // commitments, indices, serialized components, proofs,
  // comunication keys, and pedersen nonces.
  //------------------------------------

  private async genComponents(
    setup: PedersenSetup,
    numBlanks: number,
    inputs: ComponentInput[],
    outputs: ComponentOutput[],
    feerate: number,
    randomSalts: Uint8Array[]
  ): Promise<GenComponentsResult> {
    const t0 = performance.now();

    this._roundInputs = inputs;

    this._roundOutputs = outputs;
    this._randomSalts = randomSalts;

    if (numBlanks < 0) throw new Error("numBlanks < 0");
    if (!this._fusion)
      throw new Error("Fusion proto not loaded; call start() first");

    const fusion = this._fusion;
    const toU8 = (x: any) => (x instanceof Uint8Array ? x : new Uint8Array(x));

    Log.log("[genComponents]   Begin component construction...");

    // ------------------ Build raw components in fixed order ------------------
    const components: Array<[ComponentType, bigint]> = [];

    // Inputs
    for (const input of inputs) {
      const fee = componentFee(sizeOfInput(), feerate);
      const safeAmount = BigInt(input.amount);

      const debugfoo1 = toU8(input.prevTxid).slice().reverse();

      const inputMsg = fusion.InputComponent.create({
        prevTxid: toU8(input.prevTxid).slice(),
        prevIndex: Number(input.prevIndex),
        pubkey: toU8(input.pubkey),
        amount: Number(input.amount),
      });

      const comp = fusion.Component.create({
        saltCommitment: new Uint8Array(32),
        input: inputMsg,
      });

      components.push([comp, safeAmount - BigInt(fee)]);
    }

    // Outputs
    for (const output of outputs) {
      const fee = componentFee(sizeOfOutput(), feerate);
      const safeAmount = BigInt(output.amount);

      const outputMsg = fusion.OutputComponent.create({
        scriptpubkey: output.scriptpubkey,
        amount: Number(output.amount),
      });

      const comp = fusion.Component.create({
        saltCommitment: new Uint8Array(32),
        output: outputMsg,
      });

      components.push([comp, -(safeAmount + BigInt(fee))]);
    }

    // Blanks
    for (let i = 0; i < numBlanks; i++) {
      const comp = fusion.Component.create({
        saltCommitment: new Uint8Array(32),
        blank: {},
      });
      components.push([comp, 0n]);
    }

    Log.log(`[genComponents]   Built ${components.length} raw components`);

    // ------------------ Encode + Pedersen Commitments ------------------
    let sumNonce = 0n;
    let sumAmounts = 0n;

    const initialCommitments: InitialCommitmentData[] = [];
    const componentIndices: number[] = [];
    const serializedComponents: Uint8Array[] = [];
    const proofs: ProofType[] = [];
    const commPrivKeys: Uint8Array[] = [];

    for (let cnum = 0; cnum < components.length; cnum++) {
      const tuple = components[cnum];
      if (!tuple) continue;

      const [comp, commitAmount] = tuple;

      // Salt & salt_commitment
      const salt = randomSalts[cnum];
      const saltCommit = await sha256(salt);
      (comp as any).saltCommitment = saltCommit;

      // Create a flat oneof-safe Component for encoding
      const flatComp = fusion.Component.create({
        saltCommitment: saltCommit,
        input: (comp as any).input,
        output: (comp as any).output,
        blank: (comp as any).blank,
      });

      const compser = fusion.Component.encode(flatComp).finish();

      // Pedersen for amount
      const pedersen = await Commitment.create(setup, commitAmount);
      sumNonce += pedersen.nonce;
      sumAmounts += commitAmount;

      // Fresh comm keypair for this commitment
      const [privkey, , pubkeyCompressed] = genKeypair(secp);

      // saltedComponentHash = sha256(salt || serialized_component)
      const saltedHash = await sha256(new Uint8Array([...salt, ...compser]));

      const icData: InitialCommitmentData = {
        saltedComponentHash: new Uint8Array(saltedHash),
        amountCommitment: new Uint8Array(pedersen.P_uncompressed),
        communicationKey: new Uint8Array(pubkeyCompressed),
      };

      const proof = fusion.Proof.create({
        componentIdx: cnum,
        salt,
        pedersenNonce: intToBytesBE(pedersen.nonce, 32),
      });

      initialCommitments.push(icData);
      componentIndices.push(cnum);
      serializedComponents.push(compser);
      proofs.push(proof);
      commPrivKeys.push(privkey);
    }

    // Mod the nonce sum and serialize
    sumNonce %= Protocol.SECP256K1_ORDER;
    const pedersenTotalNonce = intToBytesBE(sumNonce, 32);

    const elapsed = (performance.now() - t0).toFixed(1);

    try {
      const comp0 = fusion.Component.decode(serializedComponents[0]);
      const ic0 = initialCommitments[0];
      const proof0 = proofs[0];
    } catch (err) {
      Log.log("[genComponents] Could not decode or dump component[0]:", err);
    }

    return {
      initialCommitments,
      componentIndices, // [0..n-1], unchanged
      serializedComponents, // in original build order
      proofs, // in original build order
      commPrivKeys, // aligned with proofs/components
      totalAmount: sumAmounts,
      pedersenTotalNonce,
      components: components.map(([c]) => c), // original order, no sorting
    };
  }

  //--------
  //--------
  //--------
  //--------
  //--------
  //--------

  //-----------------------------
  // Another major helper function to decrypt other player's proofs.
  // Validate proofs. Returns the component if valid, otherwise, null.
  //-------------

  async validateProofInternal(
    proofBlob: Uint8Array,
    commitmentPB: fusion.InitialCommitment,
    allComponents: Uint8Array[],
    badComponents: number[],
    componentFeerate: number
  ): Promise<fusion.InputComponent | null> {
    // Decode proof message
    const fusion = this._fusion;

    const msg = fusion.Proof.decode(proofBlob);

    const compIdx = msg.componentIdx;

    if (compIdx >= allComponents.length) {
      Log.log("ERROR: component index out of range");
      throw new Error("component index out of range");
    }

    if (badComponents.includes(compIdx)) {
      Log.log("ERROR: component in bad list");
      throw new Error("component in bad list");
    }

    // Decode the referenced component

    const componentBlob = allComponents[compIdx];
    const comp = fusion.Component.decode(componentBlob);

    // Validate salt & salted component hash
    if (msg.salt.length !== 32) {
      Log.log("ERROR: salt wrong length =", msg.salt.length);
      throw new Error("salt wrong length");
    }

    const saltHash = await sha256(msg.salt);

    if (!equalBytes(saltHash, comp.saltCommitment)) {
      throw new Error("salt commitment mismatch");
    }

    const salted = new Uint8Array([...msg.salt, ...componentBlob]);
    const saltedHash = await sha256(salted);

    if (!equalBytes(saltedHash, commitmentPB.saltedComponentHash)) {
      throw new Error("salted component hash mismatch");
    }

    // Compute component contribution inline
    const fee = (size: number) =>
      BigInt(Math.floor((size * componentFeerate + 999) / 1000));

    let contrib = 0n;

    if (comp.input) {
      const amt = BigInt(comp.input.amount);
      contrib = amt - fee(sizeOfInput());
    } else if (comp.output) {
      const amt = BigInt(comp.output.amount);
      contrib = -(amt + fee(sizeOfOutput()));
    } else {
      contrib = 0n;
    }

    // Pedersen check
    const pedersenNonce = BigInt(
      "0x" + Buffer.from(msg.pedersenNonce).toString("hex")
    );

    const pedersenSetup = new PedersenSetup(this._torboar);
    await pedersenSetup.init();
    const claimed = await Commitment.create(
      pedersenSetup,
      contrib,
      pedersenNonce
    );

    if (!equalBytes(claimed.P_uncompressed, commitmentPB.amountCommitment)) {
      throw new Error("pedersen commitment mismatch");
    }

    // Return the input component if applicable
    if (comp.input) {
      return comp.input;
    }

    return null;
  }

  //--------
  //--------
  //--------
  //--------
  //--------
  //--------

  // This function fires off the main sequence of events for a fusion round.
  private async _runFusionRoundLoop(): Promise<void> {
    let phase: FusionPhase = "starting";

    while (true) {
      if (this._shouldStopRequested) {
        Log.log("Fusion round loop stopped early due to shutdown request.");
        break;
      }

      // The following phases are modularized and (mostly) sequential chunks of code
      // that roughly mirror the protocol specifications phases,
      // but do not correspond 1-to-1 with the spec's description of phases.

      try {
        switch (phase) {
          case "starting":
            phase = await phase_starting(this);

            break;

          case "selecting_inputs":
            phase = await phase_selectingInputs(this);
            break;

          case "sending_greet":
            phase = await phase_sendGreet(this);
            break;

          case "waiting_for_server_hello":
            phase = await phase_waitForServerHello(this);
            break;

          case "allocating_outputs":
            phase = await phase_allocateOutputs(this);
            break;

          case "join_pools":
            phase = await phase_joinPools(this);
            break;

          case "wait_for_fusion_begin":
            phase = await phase_waitForFusionBegin(this);
            break;

          case "prepare_covert":
            phase = await phase_prepareCovert(this);
            break;

          case "wait_for_start_round":
            phase = await phase_waitForStartRound(this);
            break;

          case "pedersen_setup":
            phase = await phase_pedersenSetup(this);
            break;

          case "generate_components":
            phase = await phase_generateComponents(this);
            break;

          case "blind_signatures":
            phase = await phase_blindSignatures(this);
            break;

          case "send_player_commit":
            phase = await phase_sendPlayerCommit(this);
            break;

          case "receive_blind_sig_responses":
            phase = await phase_receiveBlindSigResponses(this);
            break;

          case "covert_components":
            phase = await phase_covertComponents(this);
            break;

          case "download_all_components":
            phase = await phase_downloadAllComponents(this);
            break;

          case "get_round_hash":
            phase = await phase_getRoundHash(this);
            break;

          case "covert_signatures":
            phase = await phase_covertSignatures(this);
            break;

          case "fusion_result":
            phase = await phase_fusionResult(this);
            break;

          case "broadcast":
            phase = await phase_broadcast(this);
            break;

          case "blame1":
            phase = await phase_blame1(this);
            break;

          case "blame2":
            phase = await phase_blame2(this);
            break;

          case "blame3":
            phase = await phase_blame3(this);
            break;

          case "blame4":
            phase = await phase_blame4(this);
            break;

          case "done":
            Log.log("Fusion round completed.  May or may not be a success.");
            return; // exit out of the function.  Round is over.

          default:
            Log.log("unknown phase ", phase);
            throw new Error(`Unknown phase: ${phase}`);
        }
      } catch (err) {
        Log.log(`Error in phase '${phase}':`, err);
        throw err;
      }
    } //end while
  }
} // END OF CLASS.
