# Saksi demo — setup & run (Windows + macOS)

Run a complete cryptographic election end-to-end against a real Hyperledger
Fabric network: DKG → encrypted ballots (with on-chain credential-signature
checks) → close → threshold decryption → tally → independent audit, all from one
menu (`tools/saksi-demo.sh`).

> **Permissioned & free.** No cryptocurrency, no gas, no wallets, no third-party
> service. Everything is local and open-source (Apache/MIT/BSD). Identity is
> Fabric X.509 MSP.

---

## 1. What you need

| Dependency | Version | Windows | macOS |
| --- | --- | --- | --- |
| **Docker Desktop** | latest | + **WSL integration ON** (see §2) | runs natively |
| **WSL2 + Ubuntu** | Ubuntu 22.04/24.04 | **required** (run everything inside it) | not needed |
| **Go** | ≥ 1.23 | in WSL: `/usr/local/go` | `brew install go` |
| **Rust + cargo** | stable | in WSL or on the host | `brew install rust` (or rustup) |
| **Fabric samples + binaries + images** | 2.5.x | via `install-fabric.sh` | via `install-fabric.sh` |
| **git, bash, curl, jq** | — | in WSL (`sudo apt install jq`) | `brew install jq` (bash 3.2 is fine) |

Disk: ~3 GB for Fabric images. Ports used: `7050` (orderer), `7051`/`9051`
(peers).

> ⚠️ **Path must have NO SPACES.** Fabric's scripts break on paths like
> `C:\Code - LAPTOP\…`. On Windows, clone into the WSL filesystem (e.g.
> `~/saksi`). On macOS, anywhere without spaces (e.g. `~/saksi`).

---

## 2. Windows: the one thing that always bites — Docker ↔ WSL

The Fabric network runs **inside your Ubuntu WSL distro**, so Docker must be
reachable from there.

1. Install **Docker Desktop** and **WSL2** with an Ubuntu distro
   (`wsl --install -d Ubuntu`).
2. Docker Desktop → **Settings → Resources → WSL Integration** → toggle your
   Ubuntu distro **ON** → **Apply & Restart**.
3. Verify *inside Ubuntu* (not PowerShell):
   ```bash
   docker info        # must print a Server version, not "command could not be found"
   ```
   If it says *"The command 'docker' could not be found in this WSL 2 distro"*,
   integration is still off — repeat step 2.

Do all the remaining steps **inside the Ubuntu shell**.

---

## 3. Install the toolchains

### Windows (inside Ubuntu WSL)

```bash
sudo apt update && sudo apt install -y git curl jq build-essential
# Go (if not already at /usr/local/go):
curl -sSL https://go.dev/dl/go1.23.4.linux-amd64.tar.gz | sudo tar -C /usr/local -xz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
# Rust:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### macOS

```bash
brew install go rust jq git
# Docker Desktop for Mac (or OrbStack/colima) — start it, then: docker info
```

---

## 4. Get the code + Fabric

Clone the repo and the Fabric samples **as siblings** in a space-free directory:

```bash
cd ~                                   # space-free home
git clone https://github.com/saksi-framework/saksi.git
cd saksi
# Fabric samples + Linux/macOS binaries + 2.5.x Docker images (downloads ~2 GB):
curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh \
  | bash -s -- docker samples binary
# This creates ./fabric-samples next to the repo (a sibling). If it lands
# elsewhere, set FABRIC_SAMPLES=/path/to/fabric-samples when running the demo.
```

Layout the demo expects:

```
~/saksi/                 # this repo
~/saksi/fabric-samples/  # OR a sibling ../fabric-samples  (override with FABRIC_SAMPLES)
```

One-time: vendor the chaincode dependencies so Fabric can package the Go
chaincode (it has a local module replace + ristretto/merlin deps):

```bash
cd ~/saksi/packages/saksi-bulletin/chaincode && go mod vendor && cd ~/saksi
```

---

## 5. Run the demo

```bash
cd ~/saksi
bash tools/saksi-demo.sh
```

Menu:

```
 1) Network: up + deploy          bring up Fabric + create channel + deploy chaincode
 2) Generate election bundle      cargo: build a complete valid election (hex artifacts)
 3) Run FULL election cycle       create → DKG → ballots → close → decrypt → tally (live)
 4) Open interactive console      drive each transaction yourself
 5) Audit the bundle (off-chain)  re-verify the published election → AUDIT: PASS
 6) Run tests (cargo + go)
 7) Network: down                 tear everything down
 9) Everything                    up → deploy → gen → cycle → audit, end to end
 0) Exit
```

**Fastest path:** pick `9` (or `bash tools/saksi-demo.sh all`). Expected finish:

```
✓ Full election cycle committed on the bulletin board.
AUDIT: PASS
```

Non-interactive subcommands: `up`, `gen`, `cycle`, `audit`, `down`,
e.g. `bash tools/saksi-demo.sh all`.

### The interactive console (menu option 4)

Connects as the `Org1 User1` identity and lets you run each transaction:
create election, publish DKG, submit ballots, election status, close, submit
partial decryptions, publish tally, get tally, or the whole cycle. For the demo
this identity has **full lifecycle control** (the chaincode does no per-role
authorization — only ballots are cryptographically gated by credential signature
+ nullifier uniqueness).

---

## 6. Environment overrides

| Variable | Default | Meaning |
| --- | --- | --- |
| `FABRIC_SAMPLES` | sibling `../fabric-samples` | path to your fabric-samples checkout |
| `SAKSI_CHANNEL` | `saksi` | Fabric channel name |
| `SAKSI_CC_NAME` | `saksi-bulletin` | deployed chaincode name |
| `SAKSI_BUNDLE` | `/tmp/saksi-bundle.json` | where the election bundle is written/read |
| `SAKSI_CC_POLICY` | `OR('Org1MSP.peer')` | dev endorsement policy (single org) |

> **Windows note:** if you generate the bundle with Rust on the *Windows* host
> (not WSL), point the console at it via the `/mnt/c/...` path, e.g.
> `SAKSI_BUNDLE=/mnt/c/Temp/saksi-bundle.json`.

---

## 7. Troubleshooting

| Symptom | Fix |
| --- | --- |
| `docker: command could not be found in this WSL 2 distro` | Enable Docker Desktop **WSL integration** for your distro (§2). |
| Fabric scripts fail with path errors | Your path has spaces. Clone into a space-free dir (Windows: inside WSL). |
| `fabric-samples test-network not found` | Run `install-fabric.sh … samples binary`, or set `FABRIC_SAMPLES`. |
| `jq: command not found` | `sudo apt install jq` (WSL) / `brew install jq` (macOS). |
| chaincode deploy build fails | Run `go mod vendor` in `packages/saksi-bulletin/chaincode` (§4). |
| `CreateElection: election already exists` | The election ran already. `7) Network: down`, then start fresh. |
| ports already in use | Stop other Fabric/test networks, or `7) Network: down`. |

Tear down when done: `bash tools/saksi-demo.sh down`.

---

## 8. What "pass" proves

- **Recorded-as-cast** — every ballot was accepted on-chain only after its
  issuer **credential signature verified on the chaincode** (ristretto255 +
  Merlin, byte-identical to the Rust signer) and its nullifier was unique.
- **Counted-as-recorded** — `AUDIT: PASS` means the off-chain auditor
  re-verified every proof and confirmed the homomorphic sum of the ciphertexts
  decrypts to the published tally.

See [`spec/protocol.md`](spec/protocol.md) and
[`spec/threat-model.md`](spec/threat-model.md) for the full protocol and its
guarantees.
