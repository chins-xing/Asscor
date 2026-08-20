# ASSCOR ACL Experiment Manual

**Experiment campaign**: Attacker Cognitive Loop (ACL) closed-loop validation
against automated adversarial simulation on a 24-node Containerlab topology.

**Date**: 2026-08-20 | **Environment**: WSL2 + Docker 27.5.1 + containerlab +
MITRE Caldera v5 + Atomic Red Team

---

## 1. Overview

This manual documents the reproduction of the experiment campaign reported in
*"Attacker Cognitive Loop: An Interpretable Rule-Based Engine for Estimating,
Predicting, and Engaging Adaptive Attackers"* (lunwen/paper/). All data in
this package comes from **real experiments** run on a live 24-node
containerized topology; no value is simulated beyond the attack-step
execution (docker exec of ATT&CK-style TTP commands).

### 1.1 What the experiment demonstrates

| Claim | Evidence |
|-------|----------|
| ACL tracks attacker intent across attack stages | E1-E5, E9: 100% intent-tracking accuracy (28/28 rounds) |
| Defensive fallback (contain) fires on unknown TTPs | E6: unmapped technique -> intent=unknown, strategy=contain |
| Repeated identical attacks converge the predicted distribution | E7: sharpness 0.695->0.752 plateau, entropy 0.547->0.444, KL->3e-4 |
| Decoys provide attack visibility (no-ACL baseline blind) | CR comparison: C1 hits=0 vs C2/C3 hits=6 |
| Prediction-driven decoy deployment (dynamic vs static) | CR: C3 ports follow the prediction |

## 2. Environment

### 2.1 Host requirements

- Windows with WSL2, `Containerlab` distro
- Docker 27.5.1 (inside WSL), containerlab CLI
- Go 1.19+ (for sandcat agent compile), Python 3.11 (for Caldera)
- VPN/HTTP proxy for fetching Caldera plugins and Atomic Red Team (optional if
  assets pre-fetched)

### 2.2 Topology: 24 nodes (18 hosts + 5 routers + 1 kernel edge)

```
s5720 ── 82580 ── r1 (NAT+OSPF) ── edge0 (ASSCOR-kernel :50051)
                   │  10.10.0.0/24
     r2 ─ r3 ─ r4 ─ r5   (aggregation ring, ECMP)
     r2: host1 host2 host9  host13 host14
     r3: host3 host4 host10 host15 host16
     r4: host5 host6 host11 host17 host18
     r5: host7 host8 host12
```

- 18 hosts each in its own /24 (10.10.1.0/24 .. 10.10.18.0/24)
- FRR OSPF with `redistribute connected` (required for host13-18 routes)
- Kernel on edge0 (10.10.0.10:50051); 18 agents (host1..host18) mTLS-bound

## 3. Reproduction procedure

### 3.1 Deploy the 24-node topology

```bash
cd ~/clab/asscor
sudo clab destroy -t asscor.clab.yml   # clean slate (veth reset required)
sudo clab deploy -t asscor.clab.yml    # 24 nodes
# wait ~30s for OSPF, then add redistribute for the new subnets:
for r in r2 r3 r4 r5; do
  docker exec asc-asscor-$r vtysh -c 'conf t' -c 'router ospf' -c 'redistribute connected'
done
# verify
docker exec asc-asscor-r1 vtysh -c 'show ip route ospf' | grep -c 'O>*'   # >= 30
docker exec asc-asscor-host1 ping -c2 10.10.9.10                          # OK
```

> **Known pitfall**: `clab deploy --reconfigure` does NOT rebuild veth links.
> After a WSL/docker restart the internal eth1+ interfaces vanish. Always
> `destroy + deploy` to restore them.

### 3.2 Deploy the ASSCOR stack (kernel + 18 agents)

```bash
# copy binaries into WSL first (scripts/exp_deploy_all.sh expects them at /tmp)
cp /mnt/f/Argus/build/ASSCOR-kernel-v0.2.3-linux-amd64 /tmp/ASSCOR-kernel
cp /mnt/f/Argus/build/ASSCOR-agent-v0.2.3-linux-amd64 /tmp/ASSCOR-agent
cp lunwen/clab-lab/kernel-config.ini /tmp/kernel-config.ini
bash scripts/exp_deploy_all.sh   # kernel -> CA -> certs -> 18 agents
# verify
docker exec asc-asscor-edge0 grep -c 'agent registered' /var/log/asscor-kernel.log  # 18
```

Real configs (as used in the experiment):
- `configs/kernel-config.ini` — kernel weights/edge-factors/threshold
- `configs/agent.ini-real.txt` — agent config extracted from host1

### 3.3 (Optional) Caldera + Atomic Red Team

The attacker steps in this campaign were executed via `docker exec` of
ATT&CK-style commands (the "attack surface" the decoys cover). The full
Caldera orchestration path is also provided:

```bash
# Caldera v5 (see lunwen/caldera-master.zip):
cd /opt/caldera
python3 -m venv venv && venv/bin/pip install -r requirements.txt
git clone --depth 1 https://github.com/mitre/sandcat.git plugins/sandcat   # etc.
venv/bin/python server.py --fresh --insecure -P sandcat,stockpile,atomic
# API key: ADMIN123 (default argon2 in conf/default.yml)
```

## 4. Running the experiments

### 4.1 Build the harness

```bash
GOOS=linux go build -tags decoyd -o decoyd   cmd/decoyd/
GOOS=linux go build -tags expr   -o exprunner cmd/exprunner/
```

### 4.2 Run E1-E9 (ACL dynamic mode, C3)

```bash
bash scripts/exp_rerun_all.sh   # E1 E2 E3 E4 E5 E6 E7 E9, mode C3
```

### 4.3 Run the comparison campaign (CR: C1/C2/C3)

```bash
bash scripts/exp_cr_final.sh    # same 3-round credential campaign,
                                # C1=no decoys, C2=static ports, C3=ACL dynamic
```

### 4.4 Output

- JSONL per experiment: `data/E1.jsonl ... E9.jsonl, CR-C1/C2/C3.jsonl`
- Each record: round, timestamp, mode, evidence, intent, sharpness,
  strategy, deployed_ports, decoy_hits, ground_truth, latency_ms

## 5. Results (24-node, final campaign)

### 5.1 E1-E9: intent tracking

| Exp | Rounds | Intent acc | Strategy | Decoy hits |
|-----|--------|-----------|----------|-----------|
| E1 (scanner) | 2 | 2/2 | collect | 6 |
| E2 (credential) | 2 | 2/2 | engage | 5 |
| E3 (lateral) | 2 | 2/2 | engage | 3 |
| E4 (exfil) | 2 | 2/2 | engage | 2 |
| E5 (mixed campaign) | 3 | 3/3 | engage | 6 |
| E6 (unknown TTP) | 1 | 1/1 | **contain** | 0 |
| E7 (convergence x10) | 10 | 10/10 | engage | 30 |
| E9 (multi-target) | 6 | 6/6 | engage | 11 |
| **Total** | **28** | **28/28 (100%)** | | **63** |

### 5.2 E7 convergence (Q7 evidence)

| Round | Sharpness | P(credential) | Entropy |
|-------|-----------|---------------|---------|
| 1 | 0.695 | 0.879 | 0.547 |
| 2 | 0.713 | 0.887 | 0.514 |
| 3 | 0.729 | 0.894 | 0.486 |
| 4 | 0.743 | 0.899 | 0.461 |
| 5-10 | 0.752 | 0.903 | 0.444 |

Mean KL between consecutive rounds: 3e-4 (converged).

### 5.3 Comparison CR (3-round credential campaign)

| Mode | Total hits | Total deployed ports | Efficiency (hits/port) | Intent acc |
|------|-----------|---------------------|------------------------|------------|
| C1 (no ACL) | 0 | 0 | 0.00 | 100%* |
| C2 (static decoys) | 6 | 6 | 1.00 | 100% |
| C3 (ACL dynamic) | 6 | 11 | 0.55 | 100% |

\* C1 intent is inferred from the observed TTP even without decoys; the key
difference is visibility: with no decoys the loop collects **zero**
intelligence from the attack surface.

**Interpretation**: decoys provide the intelligence channel (C1 vs C2/C3).
ACL-dynamic deployment (C3) follows the prediction each round; in this
single-target credential scenario its footprint was larger than the static
set (a documented trade-off we analyze in the paper), while multi-round
campaigns (E5/E9) show prediction-driven deployment following intent
transitions.

## 6. Asset inventory

| Path (lunwen/attachment/) | Contents |
|---------------------------|----------|
| bin/ASSCOR-kernel-linux-amd64 | kernel binary used in the experiment (v0.2.3) |
| bin/ASSCOR-agent-linux-amd64 | agent binary used (v0.2.3) |
| bin/decoyd-linux-amd64 | decoy daemon deployed inside target containers |
| bin/exprunner-linux-amd64 | experiment orchestration harness |
| configs/kernel-config.ini | kernel configuration (real) |
| configs/agent.ini-real.txt | agent configuration (extracted from host1) |
| configs/asscor.clab.yml | 24-node topology definition |
| scripts/exp_deploy_all.sh | kernel+18 agents deployment |
| scripts/exp_redeploy_clean.sh | clean redeploy (fresh CA) |
| scripts/exp_rerun_all.sh | run E1-E9 |
| scripts/exp_cr_final.sh | run comparison C1/C2/C3 |
| scripts/exp_analyze.py | per-experiment analysis |
| scripts/exp_final_summary.py | aggregate summary |
| scripts/exprunner-main.go | harness source |
| scripts/decoyd-main.go | decoy daemon source |
| data/*.jsonl | raw per-round records (E1-E9, CR-C1/C2/C3) |

## 7. Data provenance

- All JSONL produced by `exprunner` against the live topology (timestamps in
  records).
- Attacker commands are ATT&CK technique executions (T1046/T1595 scan,
  T1110 brute force, T1003 credential dump, T1021 lateral, T1567/T1048
  exfiltration, T1190 web exploit, T9999 unknown).
- Decoy hits are TCP connections recorded by `decoyd` listening on the decoy
  ports inside the target containers.
