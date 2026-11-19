// Types of the typed wrapper (index.js). The shapes are in wire.d.ts.
import type * as W from "./wire";
export type * from "./wire";
export { default, initSync } from "./saksi_wasm.js";
export * as raw from "./saksi_wasm.js";

export declare function version(): W.VersionOutput;
export declare function begin_issuance(): W.BeginIssuanceOutput;
export declare function blind_challenge(input: W.BlindChallengeInput): W.BlindChallengeOutput;
export declare function finalize_issuance(input: W.FinalizeIssuanceInput): W.FinalizeIssuanceOutput;
export declare function check_credential(input: W.CheckCredentialInput): W.CheckCredentialOutput;
export declare function election_info(input: W.ElectionInfoInput): W.ElectionInfoOutput;
export declare function build_ballot(input: W.BuildBallotInput): W.BuildBallotOutput;
export declare function benaloh_open(input: W.BenalohOpenInput): W.BenalohOpened;
export declare function benaloh_check(input: W.BenalohCheckInput): W.BenalohCheckOutput;
export declare function tracking_code(input: W.TrackingCodeInput): W.TrackingCodeOutput;
/** The message of an error thrown by an export (its {"error": ...} text). */
export declare function errorOf(e: unknown): string;
