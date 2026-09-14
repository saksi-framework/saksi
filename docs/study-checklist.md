# Study checklist — Chapter 4 from `/wizard`

Tick sheet for [runbook §10](research-election-console-runbook.md#10-running-the-study-from-the-wizard).
Section numbers point there. Bold is what the wizard shows.

Study tag: ________  saksi commit (`git log -1 --oneline`): ____________  Date started: ________

## Once, before the study (§10.1)

- [ ] Docker's data disk on the NVMe; `.wslconfig` has `memory=24GB` and `swap=0`
- [ ] `/etc/fstab` network mounts carry `noauto,x-systemd.automount`
- [ ] Sleep and hibernate off (`powercfg /change standby-timeout-ac 0`, `hibernate-timeout-ac 0`)
- [ ] Games, video, builds and other heavy programs closed, and kept closed

## Each session (§10.2, §10.3)

- [ ] `wsl -d Ubuntu -e true` and `wsl -d Ubuntu -e docker info` answer within seconds
- [ ] tmux `console`: `cd ~/Code/saksi && SAKSI_PHASE_TIMEOUT=5h ./tools/up.sh`; `./tools/up.sh status` says on-chain ENABLED
- [ ] Browser at `http://127.0.0.1:8090/wizard` (signed in, if an auth file is used)
- [ ] Same saksi commit as the line above (no pull, no rebuild mid-study)
- [ ] **Ladder** row green (once per build: **Run the validation ladder**) · `ladder.json` copied

## Per tier (§10.4) — in this order

For each row: **Measurement campaign** → preset → tag in **Election name** →
**Reset network** (type `RESET`) → **Check again**, every row green, **Host** included →
**Start campaign →** → **done**, no **contended**, `n` = measured → **Export bundle (.zip)** →
unzip to balotachain `docs/desktop-runs/<date>-<tier>/`. Export before the next reset.

| Row | Preset | W + M | Reset | Preflight green | Campaign done | No contended | Exported | Copied |
|---|---|---|---|---|---|---|---|---|
| 2 | SP-1K | 2 + 10 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| 2 | MP-1K | 2 + 10 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| 3 | SP-10K | 2 + 10 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| 3 | MP-10K | 2 + 10 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| 4 | SP-50K | 2 + 5 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| 4 | MP-50K | 2 + 5 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| 5 | SP-483K | 1 + 3 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| 6 | SP-1M | 1 + 3 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| 7 | SP-1.92M | 1 + 1 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| 7 | SP-3.5M ¹ | 1 + 1 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| 8 | MP-483K offline ² | 0 + 1 | — | ☐ | ☐ | ☐ | ☐ | ☐ |
| 8 | MP-1M offline ² | 0 + 1 | — | ☐ | ☐ | ☐ | ☐ | ☐ |
| 8 | MP-1.92M offline ² | 0 + 1 | — | ☐ | ☐ | ☐ | ☐ | ☐ |
| 8 | MP-3.5M offline ² | 0 + 1 | — | ☐ | ☐ | ☐ | ☐ | ☐ |
| 9 | MP-3.5M on-chain ¹ | 0 + 1 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |

¹ Needs the console started with `SAKSI_PHASE_TIMEOUT=5h`; the **Phase timeout** preflight row must be green (§10.7).
² Offline: no network reset. Disk and memory preflight rows must be green (§10.7).

Row 5: set **Rate sweep**, **Sweep step window**, **Peak burst** and **Send rate** before **Start campaign →** (§10.4). ☐ Sweep ☐ Burst

## Security runs (§10.5) — after the tier's campaign, before its reset

**Single election** → preset → tag → on-chain → **Skip all attacks** unticked, stages ticked →
**Generate ballots →** → **Check the data →** → **Encrypt →** → decide each **Paused at** stage →
trustees → **Publish tally** → **Verify →** (**E = 0 · PASS**) → export from **Runs**.

| Tier | Stages ticked | E = 0 | Verdicts read (PASS / INCONCLUSIVE / FAIL / SKIPPED) | Exported | Copied |
|---|---|---|---|---|---|
| ________ | ☐ DKG ☐ ballots ☐ close ☐ ceremony | ☐ | ☐ | ☐ | ☐ |
| ________ | ☐ DKG ☐ ballots ☐ close ☐ ceremony | ☐ | ☐ | ☐ | ☐ |

- [ ] Security-run throughput kept out of RQ3
- [ ] On-chain limitations stated beside the verdicts (DKG, partial-decryption proofs, reordering, front-running)

## T3 — restart the peer mid-submission (§10.6)

Tier: ________  Stop after: ____  Down for: ____ s  Send rate: ____ (0 = closed loop)

- [ ] **Single election**, on-chain, **Skip all attacks** ticked; send rate set if measuring outage loss
- [ ] **Generate ballots →** done; stop before **Check the data →**
- [ ] **Arm the fault** (type `RESTART`); status reads "Armed on …"
- [ ] **Check the data →**, **Encrypt →**; run ends "N of M ballots did not commit", list shows **interrupted**
- [ ] **Resume** → "Done: now run Verify-only …, then Open the run …" (press **Resume** again if offered)
- [ ] **Verify-only** → list shows "verify-only reconciled"
- [ ] **Open** on the run (lands on the trustees), **Submit share** ×3, **Publish tally**, **Verify →**: E = 0, ledger matches local
- [ ] Exported `run.json`, `perf.csv`, `correctness.csv`, `journal.ndjson`; copied
- [ ] Peer up afterwards (`./tools/up.sh status`; `docker start peer0.org1.example.com` if not)

## During every run (§10.8)

No sleep · no `wsl --shutdown` · no Docker Desktop restart · no heavy programs ·
WSL terminal left open · no pull, rebuild or `SAKSI_CONFIGTX` change.

## After the study (§10.9)

- [ ] Every tier's note written in balotachain `docs/desktop-runs/`
- [ ] `docs/CLAIMS.md` rows moved from pending/predicted to measured where an artifact now backs them
- [ ] Cost model refitted to a new file: `cost_model.py --runs ~/.saksi/campaign/runs --match '*-<tag>-*' --fit-concurrency 128 --out docs/desktop-runs/cost-model-<tag>.md`
- [ ] Run folders kept in WSL (`~/.saksi/campaign/runs/`)
