/* eslint-disable max-classes-per-file */
/* eslint-disable @typescript-eslint/naming-convention */
/* eslint-disable no-param-reassign */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-plusplus */
/* eslint-disable no-promise-executor-return */
/* eslint-disable prefer-destructuring */
/* eslint-disable @typescript-eslint/lines-between-class-members */
/* eslint-disable no-bitwise */
/* eslint-disable no-await-in-loop */
/* eslint-disable no-restricted-syntax */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-loop-func */
/* eslint-disable @typescript-eslint/no-this-alias */
/* eslint-disable no-empty */
/* eslint-disable no-continue */
/* eslint-disable prefer-const */

import PQueue from "p-queue";
import { Protocol } from "./protocol";
import LogService from "@/services/LogService";

import { hexToBytes, createFrameBytes } from "./util";

import { fusion } from "@/proto/fusion";

type PingType = import("@/proto/fusion").fusion.Ping;
type OKType = import("@/proto/fusion").fusion.OK;
type ErrorType = import("@/proto/fusion").fusion.Error;
type CovertMessageType = import("@/proto/fusion").fusion.CovertMessage;
type CovertResponseType = import("@/proto/fusion").fusion.CovertResponse;
type CovertComponentType = import("@/proto/fusion").fusion.CovertComponent;
type CovertTransactionSignatureType =
  import("@/proto/fusion").fusion.CovertTransactionSignature;

const Log = LogService("FusionService");

//---------------
//---------------
//--------------------
//-----------------

export async function submitCovertData(opts: {
  torboar: any;
  payloads: Uint8Array[];
  circuitLedger: Map<string, CircuitRecord>;
  t0: number;
  task: string;
}) {
  const { torboar, payloads, circuitLedger, t0, task } = opts;

  if (task !== "submit_components" && task !== "submit_signatures") {
    throw new Error(
      "invalid task for submitCovertData. Expecting submit_components or submit_signatures"
    );
  }

  let START_DELAY_MS: number;
  let CUTOFF_MS: number;

  if (task === "submit_components") {
    START_DELAY_MS = 5000;
    CUTOFF_MS = 15000;
  } else if (task === "submit_signatures") {
    START_DELAY_MS = 20000;
    CUTOFF_MS = 30000;
  }

  // Make a mutable working list with indexes preserved
  let workList = payloads.map((p, i) => ({
    componentIndex: i,
    payload: p,
  }));

  const TOTAL = workList.length;

  const startTime = t0 + START_DELAY_MS;
  const cutoffTime = t0 + CUTOFF_MS;

  Log.log("TASK: ", task);
  Log.log(`[submitData] Waiting until timing window opens...`);
  const waitMs = Math.max(0, startTime - performance.now());
  if (waitMs > 0) await new Promise((r) => setTimeout(r, waitMs));

  Log.log(` [submitData] BEGIN (${TOTAL} total payloads)`);

  // All usable circuit keys
  const circuits: string[] = Array.from(circuitLedger.values())
    .filter((r) => r.circuitId)
    .map((r) => r.key);

  Log.log(` Circuits available: ${circuits.length}`);

  if (circuits.length === 0) {
    throw new Error("submitData: no circuits available");
  }

  let sent = 0;
  let batchNumber = 0;

  // MAIN LOOP — continue until all components succeed or cutoff reached
  while (workList.length > 0) {
    const now = performance.now();
    if (now >= cutoffTime) {
      Log.log(` [submitData] cutoff reached at ${(now - t0).toFixed(0)}ms`);
      break;
    }

    batchNumber++;

    // Take N components, where N = number of circuits
    const slice = workList.splice(0, circuits.length);

    const items = slice.map((entry, idx) => {
      const { componentIndex, payload } = entry;
      const frame = createFrameBytes(payload);
      const frameHex = Buffer.from(frame).toString("hex");

      const fresh = batchNumber > 1; // first batch = normal send, rest = fresh

      Log.log(
        ` Batch #${batchNumber} — comp=${componentIndex}, circuit=${circuits[idx]}, fresh=${fresh}`
      );

      return {
        componentIndex,
        circuitKey: circuits[idx],
        data: frameHex,
        fresh,
      };
    });

    // SEND BATCH
    let response;
    try {
      response = await torboar.sendTcpDataPayloads({ items });
    } catch (err) {
      Log.log(` sendTcpDataPayloads failed: ${err}`);
      throw err;
    }

    const results = response?.results || [];

    Log.log(`Batch #${batchNumber} returned ${results.length} results`);

    // PROCESS RESULTS — determine which succeeded or failed
    const failed: number[] = [];
    const succeeded: number[] = [];

    for (const r of results) {
      const compIndex = r.componentIndex;

      if (r.status === "ok") {
        succeeded.push(compIndex);
        sent++;
        Log.log(` OK comp=${compIndex} via ${r.circuitKey}`);
      } else {
        Log.log(
          `    FAIL comp=${compIndex} via ${r.circuitKey} — reason=${r.message}`
        );
        failed.push(compIndex);
      }
    }

    if (failed.length > 0) {
      const failedSet = new Set(failed);

      for (const entry of slice) {
        if (failedSet.has(entry.componentIndex)) {
          workList.push(entry); // retry this one
        }
      }
    }

    Log.log(`workList now contains ${workList.length} components`);

    // tiny spacing delay
    await new Promise((r) => setTimeout(r, 20));
  }

  // FINAL RESULT
  const elapsed = (performance.now() - t0).toFixed(0);

  Log.log(`submitData complete — sent=${sent}/${TOTAL}, elapsed=${elapsed}ms`);

  if (sent < TOTAL) {
    throw new Error(
      `submitData failed: only sent ${sent} of ${TOTAL} components`
    );
  }
}

//---------
//---------

// rate limiter: remembers when connections were opened and how many are still inside the lifetime window.
class TorLimiter {
  private _expiries: number[] = [];

  constructor(private _lifetime: number) {}

  private _cleanup() {
    const now = Date.now() / 1000;
    while (this._expiries.length && this._expiries[0] < now) {
      this._expiries.shift();
    }
  }

  get count(): number {
    this._cleanup();
    return this._expiries.length;
  }

  bump() {
    const now = Date.now() / 1000 + this._lifetime;
    this._expiries.push(now);
  }
}

class CovertCircuit {
  private _circuitKey: string;
  private _circuitId: string | null = null;
  private _torboar: any;
  private _covertDomain: string;
  private _covertPort: number;
  private _covertSsl: boolean;
  private _socksUser: string;
  private _covertSubmitter: CovertSubmitter;

  constructor(
    circuitKey: string,
    torboar: any,
    covertDomain: string,
    covertPort: number,
    covertSsl: boolean,
    covertSubmitter: CovertSubmitter,
    socksUser = `CF${Math.random().toString(36).substring(2, 8)}_${circuitKey}`
  ) {
    this._circuitKey = circuitKey;
    this._torboar = torboar;
    this._covertDomain = covertDomain;
    this._covertPort = covertPort;
    this._covertSsl = covertSsl;
    this._covertSubmitter = covertSubmitter;
    this._socksUser = socksUser;
  }

  private static _timeout<T>(promise: Promise<T>, ms = 5000): Promise<T> {
    return new Promise((resolve, reject) => {
      const id = setTimeout(() => reject(new Error("Timeout")), ms);
      promise
        .then((res) => {
          clearTimeout(id);
          resolve(res);
        })
        .catch((err) => {
          clearTimeout(id);
          reject(err);
        });
    });
  }

  public get socksUser(): string {
    return this._socksUser;
  }

  get circuitKey(): string {
    return this._circuitKey;
  }

  get circuitId(): string | null {
    return this._circuitId;
  }

  async create() {
    const result = await this._torboar.createNewCircuit({ timeoutMs: 30000 });
    const circuitId = result.circuitId;

    await this._torboar.openConnectionThroughCircuit({
      host: this._covertDomain,
      port: this._covertPort,
      ssl: this._covertSsl,
      circuitKey: this._circuitKey,
      socksUser: this._socksUser, // this is what Tor uses to isolate the circuit
    });

    return { circuitId };
  }

  async makeRequest(url: string): Promise<string> {
    if (!this._circuitId) throw new Error("Circuit not created yet");
    const res = await this._torboar.makeRequestThroughCircuit({
      circuitKey: this._circuitKey,
      url,
    });
    return res.response as string;
  }
} //end class

type CircuitStatus = "pending" | "built" | "failed" | "late";

interface CircuitRecord {
  key: string;
  socksUser: string;
  startTime: number;
  endTime?: number;
  durationMs?: number;
  circuitId?: string;
  status: CircuitStatus;
  circuit?: CovertCircuit;
}

/**
 * Manages a pool of covert circuits and spares.
 */
export class CovertSubmitter {
  private _circuits: CovertCircuit[] = [];
  private _spareCircuits: CovertCircuit[] = [];
  private _limiter: TorLimiter;
  private _covertDomain: string;
  private _covertPort: number;
  private _covertSsl: boolean;
  private _numComponents: number;
  private _submitWindow: number;
  private _submitTimeout: number;
  private _torboar: any;
  private _circuitLedger: Map<string, CircuitRecord> = new Map();

  constructor(
    covertDomain: string,
    covertPort: number,
    covertSsl: boolean,
    numComponents: number,
    submitWindow: number,
    submitTimeout: number,
    torboar: any,
    circuitLedger: Map<string, CircuitRecord>
  ) {
    this._covertDomain = covertDomain;
    this._covertPort = covertPort;
    this._covertSsl = covertSsl;
    this._numComponents = numComponents;
    this._submitWindow = submitWindow;
    this._submitTimeout = submitTimeout;
    this._torboar = torboar;
    this._limiter = new TorLimiter(Protocol.TOR_COOLDOWN_TIME || 5);
    this._circuitLedger = circuitLedger;

    if (!torboar) {
      Log.log("[CovertSubmitter] torboar instance is undefined!");
    } else {
      try {
        //cleanup debug
        const keys = Object.keys(torboar);
        const funcNames = keys.filter(
          (k) => typeof (torboar as any)[k] === "function"
        );
      } catch (e) {
        Log.log("[CovertSubmitter] Error inspecting torboar:", e);
      }
    }
  }

  private async pingSend(circuitKey: string): Promise<void> {
    // Build protobuf payload
    const pingMsg = this._fusion.CovertMessage.create({
      ping: this._fusion.Ping.create({}),
    });
    const payload = this._fusion.CovertMessage.encode(pingMsg).finish();

    // TODO: can remove and use util helper to do the frame.

    // Add framing: MAGIC + 4-byte big-endian length
    const MAGIC = hexToBytes(Protocol.MAGIC); // cleanup. call util.
    const len = payload.length;
    const lengthBytes = new Uint8Array([
      (len >>> 24) & 0xff,
      (len >>> 16) & 0xff,
      (len >>> 8) & 0xff,
      len & 0xff,
    ]);

    const frame = new Uint8Array(MAGIC.length + lengthBytes.length + len);
    frame.set(MAGIC, 0);
    frame.set(lengthBytes, MAGIC.length);
    frame.set(payload, MAGIC.length + lengthBytes.length);

    // Send through the circuit socket
    await this._torboar.sendTcpData({
      circuitKey,
      data: Buffer.from(frame).toString("hex"),
    });
  }

  private async pingReceive(
    circuitKey: string,
    timeoutMs = 5000
  ): Promise<boolean> {
    try {
      const res = await this._torboar.receiveTcpData({ circuitKey, timeoutMs });
      const raw = Buffer.from(res.data, "hex");

      const msgObj = this._fusion.CovertResponse.decode(raw);

      if (msgObj.error) {
        Log.log(
          `[CovertSubmitter] Error from ${circuitKey}:`,
          msgObj.error.message
        );
        return false;
      }

      return false;
    } catch (err) {
      Log.log(`[CovertSubmitter] pingReceive failed for ${circuitKey}:`, err);
      return false;
    }
  }

  /**
   * Launches a single circuit, with timeout and ledger tracking (diagnostic version).
   * Handles "late" completions gracefully — circuits that finish after the soft
   * timeout but before the hard cutoff will backfill their IDs.
   */
  async launchSingleCircuit(circuitKey: string, timeoutMs: number) {
    const socksUser = `CF${Math.random()
      .toString(36)
      .substring(2, 8)}_${circuitKey}`;

    const circuit = new CovertCircuit(
      circuitKey,
      this._torboar,
      this._covertDomain,
      this._covertPort,
      this._covertSsl,
      this,
      socksUser
    );

    const startTime = performance.now();

    // Initialize ledger entry
    const record: CircuitRecord = {
      key: circuitKey,
      socksUser,
      startTime,
      status: "pending",
      circuit,
    };
    this._circuitLedger.set(circuitKey, record);

    // Sanity check
    const hasRecord = this._circuitLedger.has(circuitKey);
    if (!hasRecord) {
      Log.log(
        `[CovertSubmitter] Ledger failed to store record for ${circuitKey}`
      );
    }

    // Timeout promise
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("timeout")), timeoutMs)
    );

    try {
      // Try building the circuit with timeout
      const result = await Promise.race([circuit.create(), timeout]);

      const endTime = performance.now();
      Object.assign(record, {
        status: "built" as CircuitStatus,
        circuitId: result.circuitId,
        endTime,
        durationMs: endTime - startTime,
      });

      this._circuits.push(circuit);

      return result;
    } catch (err: any) {
      const endTime = performance.now();
      const status = err.message?.includes("timeout") ? "late" : "failed";

      Object.assign(record, {
        status: status as CircuitStatus,
        endTime,
        durationMs: endTime - startTime,
      });

      // Handle backfill for circuits that finish after soft cutoff
      if (status === "late") {
        circuit
          .create()
          .then((lateResult) => {
            Object.assign(record, {
              status: "built" as CircuitStatus,
              circuitId: lateResult.circuitId,
            });
            Log.log(
              `[CovertSubmitter] (late) ${circuitKey} completed after timeout — id=${lateResult.circuitId} `
            );
          })
          .catch((lateErr) => {
            Log.log("circuitkey lifecylce ended.  This is normal.");
          });
      }

      throw err;
    } finally {
      /* Log.log(` [CovertSubmitter] launchSingleCircuit END for ${circuitKey}`);*/
    }
  }

  async scheduleCircuits() {
    const CIRCUIT_TIMEOUT_MS = 29000;
    const SOFT_CUTOFF = 29000; // return to next phase at 29s
    const HARD_CUTOFF = 38000; // absolute stop at 38s
    const PHASE_DELAY = 200; // 200ms between phases

    // ---- manual schedule (total = 40) ----
    const schedule = [
      { count: 10 }, // phase 1
      { count: 10 }, // phase 2
      { count: 10 }, // phase 3
      { count: 10 }, // phase 4
    ];

    let built = 0;
    let failed = 0;
    let timeouts = 0;
    let late = 0;
    let launched = 0;

    return new Promise<void>((resolve) => {
      const start = performance.now();
      const launchSingle = this.launchSingleCircuit.bind(this);
      const allPromises: Promise<void>[] = [];

      // ---- recursive phase launcher ----
      const launchPhase = (phaseIndex: number) => {
        const elapsed = (performance.now() - start) / 1000;
        const phase = schedule[phaseIndex];
        if (!phase) return;

        for (let i = 0; i < phase.count; i++) {
          const key = `slot-${phaseIndex + 1}-${i}`;
          launched++;
          const launchStart = performance.now();

          const p = launchSingle(key, CIRCUIT_TIMEOUT_MS)
            .then((result: any) => {
              built++;
              const dur = ((performance.now() - launchStart) / 1000).toFixed(2);
              const now = performance.now() - start;
              if (now > SOFT_CUTOFF) late++;
            })
            .catch((err: any) => {
              const dur = ((performance.now() - launchStart) / 1000).toFixed(2);
              if (err.message?.includes("timeout")) timeouts++;
              else failed++;
            });

          allPromises.push(p);
        }

        // schedule next phase
        if (phaseIndex + 1 < schedule.length) {
          setTimeout(() => launchPhase(phaseIndex + 1), PHASE_DELAY);
        }
      };

      //  start first phase
      launchPhase(0);

      // SOFT cutoff: report early status
      setTimeout(() => {
        Log.log(
          `Soft cutoff ${(SOFT_CUTOFF / 1000).toFixed(
            1
          )}s — built=${built},   failed=${failed}, timeouts=${timeouts}, launched=${launched}`
        );
      }, SOFT_CUTOFF);

      // HARD cutoff: finalize and resolve
      setTimeout(async () => {
        await Promise.allSettled(allPromises);
        const total = built + failed + timeouts;
        Log.log(
          `Hard cutoff ${(HARD_CUTOFF / 1000).toFixed(
            1
          )}s — built=${built},   failed=${failed}, timeouts=${timeouts}, late=${late}, launched=${launched}, total=${total}`
        );
        resolve();
      }, HARD_CUTOFF);
    });
  }

  // A little bit of leftover code.  No real such thing as "spares".
  async scheduleConnections(
    tFusionBegin: number,
    connectWindow: number,
    connectSpares: number,
    connectTimeout: number
  ) {
    // For now just reuse scheduleCircuits

    await this.scheduleCircuits(connectSpares);
  }

  // Send requests over all slots in parallel immediately.

  async submitAll(urls: string[]) {
    return Promise.all(urls.map((url, idx) => this.submitRequest(idx, url)));
  }

  get connectedCount() {
    return this._circuits.filter(Boolean).length;
  }

  get spareCount() {
    return this._spareCircuits.length;
  }
}
