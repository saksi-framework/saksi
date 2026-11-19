// @saksi/wasm: the typed wrapper the phone app imports.
//
// Each function takes the wire-format input as a plain object, passes it to
// the WebAssembly export as one JSON string, and parses the JSON string it
// returns. Errors are the export's own: a thrown Error whose message is
// {"error": "..."}; errorOf(e) extracts the message.
//
//   import init, { begin_issuance, build_ballot } from "@saksi/wasm";
//   await init();                       // fetches saksi_wasm_bg.wasm once
//
// Never log the inputs or outputs of the voter ops: they hold the voter's
// secrets (see docs/live/wire-format.md, "WebAssembly (phone)").
import * as raw from "./saksi_wasm.js";

export { default, initSync } from "./saksi_wasm.js";
export { raw };

const viaJson = (f) => (input) => JSON.parse(f(JSON.stringify(input)));

export const version = () => JSON.parse(raw.version());
export const begin_issuance = () => JSON.parse(raw.begin_issuance());
export const blind_challenge = viaJson(raw.blind_challenge);
export const finalize_issuance = viaJson(raw.finalize_issuance);
export const check_credential = viaJson(raw.check_credential);
export const election_info = viaJson(raw.election_info);
export const build_ballot = viaJson(raw.build_ballot);
export const benaloh_open = viaJson(raw.benaloh_open);
export const benaloh_check = viaJson(raw.benaloh_check);
export const tracking_code = viaJson(raw.tracking_code);

/** The message of an error thrown by an export (its {"error": ...} text). */
export function errorOf(e) {
  const text = e && typeof e.message === "string" ? e.message : String(e);
  try {
    const body = JSON.parse(text);
    if (body && typeof body.error === "string") return body.error;
  } catch {
    // not one of ours
  }
  return text;
}
