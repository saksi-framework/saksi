// Every input and output shape of the @saksi/wasm exports, as in
// docs/live/wire-format.md ("Voter (phone)" and "WebAssembly (phone)").
// One field per line: tools/live/test-wasm.sh reads this file and checks
// every output's keys against its interface.

/** 32-byte compressed ristretto255 point, lowercase hex (64 chars). */
export type PointHex = string;
/** 32-byte canonical little-endian scalar, lowercase hex (64 chars). Secret where noted. */
export type ScalarHex = string;
/** Canonical protobuf encoding of a saksi.protocol.v1 message, lowercase hex. */
export type MessageHex = string;
/** Bytes, lowercase hex. */
export type Hex = string;

/** The body of every thrown error's message. */
export interface ErrorBody {
  error: string;
}

export interface VersionOutput {
  name: string;
  version: string;
  wire_format: string;
  protocol_wire_version: number;
  git_rev: string | null;
}

/** Secret. Drop after blind_challenge. */
export interface BlindState {
  s_cred: ScalarHex;
  b: ScalarHex;
}

export interface BeginIssuanceOutput {
  blinded_commitment: PointHex;
  state: BlindState;
}

export interface BlindChallengeInput {
  state: BlindState;
  r: PointHex;
  issuer_public_key: PointHex;
}

/** Secret. Drop after finalize_issuance. */
export interface FinalizeState {
  s_cred: ScalarHex;
  r_prime: PointHex;
  alpha: ScalarHex;
  beta: ScalarHex;
}

export interface BlindChallengeOutput {
  e_prime: ScalarHex;
  state: FinalizeState;
}

export interface FinalizeIssuanceInput {
  state: FinalizeState;
  s_iss: ScalarHex;
  issuer_public_key: PointHex;
}

/** Secret: it votes. The one value the app stores (IndexedDB); never sent to the console. */
export interface Credential {
  s_cred: ScalarHex;
  signature_r: PointHex;
  signature_s: ScalarHex;
}

export interface FinalizeIssuanceOutput {
  credential: Credential;
  commitment: PointHex;
}

export interface CheckCredentialInput {
  params: MessageHex;
  credential: Credential;
}

export interface CheckCredentialOutput {
  usable: true;
  election_id: string;
  issuer_public_key: PointHex;
  commitment: PointHex;
}

export interface ElectionInfoInput {
  params: MessageHex;
  dkg: MessageHex;
}

export interface Position {
  id: string;
  candidates: string[];
}

export interface ElectionInfoOutput {
  election_id: string;
  positions: Position[];
  trustees: number;
  threshold: number;
  issuer_public_key: PointHex;
  joint_public_key: PointHex;
  joint_key_fingerprint: string;
}

export interface BuildBallotInput {
  params: MessageHex;
  dkg: MessageHex;
  credential: Credential;
  position_id: string;
  choice: number;
}

/** Secret: reveals the ballot's vote. Memory only; drop once the ballot is cast. Opaque to the app. */
export interface BallotOpening {
  kind: "saksi-live-ballot-opening-v1";
  ballot_digest: Hex;
  contest_ids: string[];
  choice: number;
  randomness: ScalarHex[];
}

export interface BuildBallotOutput {
  ballot: MessageHex;
  election_id: string;
  position_id: string;
  contest_ids: string[];
  nullifier: Hex;
  tracking_code: string;
  opening: BallotOpening;
}

export interface BenalohOpenInput {
  ballot: MessageHex;
  opening: BallotOpening;
}

export interface OpenedSlot {
  contest_id: string;
  plaintext: number;
  randomness: ScalarHex;
}

/** A challenged ballot's opened values. Reveals that ballot's vote; keep on the phone. */
export interface BenalohOpened {
  election_id: string;
  position_id: string;
  nullifier: Hex;
  tracking_code: string;
  slots: OpenedSlot[];
}

export interface BenalohCheckInput {
  params: MessageHex;
  dkg: MessageHex;
  ballot: MessageHex;
  opened: BenalohOpened;
}

export interface SlotCheck {
  contest_id: string;
  plaintext: number;
  reproduces: boolean;
}

export interface BenalohCheckOutput {
  valid: boolean;
  position_id: string;
  tracking_code: string;
  slots: SlotCheck[];
  encoded_choice: number | null;
  encoded_candidate: string | null;
}

export interface TrackingCodeInput {
  nullifier: Hex;
}

export interface TrackingCodeOutput {
  tracking_code: string;
}
