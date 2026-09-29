# bench/ — SSH2 vs SSH3 benchmarks (TESTPLAN R3)

Run inside WSL from the repo root. Scenarios and methodology: [../docs/TESTPLAN.md](../docs/TESTPLAN.md).

## Setup

```bash
cp bench/config.env.example bench/config.env   # then fill real targets (gitignored)
SIZE_MB=512 bash bench/genfile.sh              # payload in /dev/shm
```

## Run

```bash
# full matrix on a stand (B1-B6; B7 with explicit netem flags)
bash bench/run_all.sh --stand S1 --profile quick          # smoke/full dry pass
bash bench/run_all.sh --stand S2 --profile full           # main LAN matrix
bash bench/run_all.sh --stand S2 --netem-loss 2 --netem-delay 50 --netem-iface IFACE  # B7

# single scenarios
bash bench/handshake.sh --stand S1 --transport ssh3 --runs 30 --out hs.csv
bash bench/throughput.sh --stand S1 --transport ssh2 --dir push --runs 10 --out tp.csv
CLIENT_CMD="$(bash -c 'source bench/lib.sh; bench::stand S1; bench::ssh3_cmd')" \
    python3 bench/pty_rtt.py --label ssh3 --iters 100
bash bench/cpu_sample.sh --pid-cmd 'systemctl show -p MainPID --value ssh3-server' --secs 30
```

## Files

| File | Purpose |
|------|---------|
| `lib.sh` | shared config/transport/ssh/stats helpers |
| `genfile.sh` | idempotent tmpfs payload (512 MiB urandom + sha) |
| `throughput.sh` | B1-B3: bulk push/pull, pipe and file mech, k parallel streams |
| `handshake.sh` | B4: full connect+auth+exec cycle |
| `pty_rtt.py` | B5: interactive PTY echo RTT (stdlib only, no pexpect) |
| `cpu_sample.sh` | B6: server process-tree CPU%/RSS sampler |
| `run_all.sh` | orchestrator: matrix -> `results/<ts>-<stand>/` + env.txt |

## Notes

- `mech=pipe` is the parity baseline (identical stdin-pipe for both transports);
  `mech=file` (ssh3 `-f` vs scp) is a reference scenario, push only.
- All outputs go to tmpfs (`/dev/shm`) — the disk is excluded from measurements.
- `config.env` and `results/` are gitignored: real addresses must not reach the public repo.
