#!/usr/bin/env python3
"""
exp.sh — automates the flexio_packet_processor + pktgen experiment workflow.
Run from the project root:  ./exp/exp.sh
"""

import pexpect
import sys
import os
import re
import time
import subprocess

# ── Configuration ──────────────────────────────────────────────────────────────
PASSWORD      = "1151"
REMOTE_USER   = "dwhwang"
REMOTE_HOST   = "147.46.66.229"
REMOTE_PORT   = "7778"
NUM_THREADS   = 176

EXP_NUM_FILE    = sys.argv[1] if len(sys.argv) > 1 else "exp/exp_num.txt"
EXP_RESULT_FILE = "exp/exp_result.txt"

PKTGEN_CMD = (
    "sudo ~/myh/Pktgen-DPDK/builddir/app/pktgen "
    "-l 0,1-15 -n 8 -a 0000:17:00.0 -- -v -T -P -m \"[1:2-15].0\""
)

LOCAL_CMD = (
    f"numactl --membind=0 taskset -c 4 sudo "
    f"./build/packet_processor/host/flexio_packet_processor "
    f"mlx5_0 --nic-mode --threads {NUM_THREADS}"
)

# ── Helpers ────────────────────────────────────────────────────────────────────
def log(msg):
    print(f"\n[exp.sh] {msg}", flush=True)

def die(msg):
    print(f"\n[exp.sh] FATAL: {msg}", flush=True)
    sys.exit(1)

def expect_prompt(child, patterns, timeout=10, context=""):
    """Wait for one of the patterns; die on timeout or EOF."""
    idx = child.expect(patterns + [pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
    if idx >= len(patterns):
        kind = "timeout" if idx == len(patterns) else "EOF"
        die(f"{kind} while waiting for {patterns!r}{' (' + context + ')' if context else ''}")
    return idx

open(EXP_RESULT_FILE, "w").close()

# ── Step 1: Build ──────────────────────────────────────────────────────────────
log("Step 1: Rebuilding (rm -rf build && ./build.sh) ...")
result = subprocess.run(
    "rm -rf build && ./build.sh 1>/dev/null",
    shell=True
)
if result.returncode != 0:
    die(f"Build failed (exit code {result.returncode}).")
log("Build successful.")

# ── Step 1 (cont.): Start local process ───────────────────────────────────────
log(f"Launching flexio_packet_processor (threads={NUM_THREADS}) ...")
local = pexpect.spawn(LOCAL_CMD, encoding="utf-8", timeout=60)
local.logfile_read = sys.stdout  # echo local output to terminal

idx = local.expect(
    [r"(?i)password.*:", "Ready to receive messages", pexpect.TIMEOUT, pexpect.EOF],
    timeout=60
)
if idx == 0:
    local.sendline(PASSWORD)
    expect_prompt(local, ["Ready to receive messages"], timeout=60,
                  context="waiting for local process ready after sudo password")
elif idx == 2:
    die("Timed out waiting for 'Ready to receive messages'.")
elif idx == 3:
    die("Local process exited unexpectedly during startup.")

log("Local process is ready.")

# ── Step 2: SSH to remote ─────────────────────────────────────────────────────
log(f"Step 2: SSH → {REMOTE_USER}@{REMOTE_HOST}:{REMOTE_PORT} ...")
ssh_cmd = (
    f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    f"-p {REMOTE_PORT} {REMOTE_USER}@{REMOTE_HOST}"
)
remote = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=30)
remote.logfile_read = sys.stdout

idx = remote.expect(
    [r"(?i)password.*:", r"[$#]\s*$", pexpect.TIMEOUT, pexpect.EOF],
    timeout=30
)
if idx == 0:
    remote.sendline(PASSWORD)
    expect_prompt(remote, [r"[$#]\s*$"], timeout=20, context="remote shell prompt")
elif idx == 2:
    die("SSH connection timed out.")
elif idx == 3:
    die("SSH connection closed unexpectedly.")

log("Remote shell ready.")

# ── Step 3: Start pktgen ──────────────────────────────────────────────────────
log("Step 3: Starting pktgen on remote ...")
remote.sendline(PKTGEN_CMD)

# pktgen may prompt for sudo password before showing its prompt
idx = remote.expect(
    [r"(?i)\[sudo\].*password.*:", r"(?i)password for", "Pktgen:/",
     pexpect.TIMEOUT, pexpect.EOF],
    timeout=60
)
if idx in (0, 1):
    remote.sendline(PASSWORD)
    expect_prompt(remote, ["Pktgen:/"], timeout=60, context="pktgen startup")
elif idx == 3:
    die("Timed out waiting for Pktgen prompt.")
elif idx == 4:
    die("Remote connection closed while starting pktgen.")

log("Pktgen is running.")

# ── Step 4: Enable range mode ─────────────────────────────────────────────────
log("Step 4: Enabling range mode on pktgen port 0 ...")
remote.sendline("enable 0 range")
expect_prompt(remote, ["Pktgen:/"], timeout=10, context="enable range")

# ── Step 5: Read experiment numbers ───────────────────────────────────────────
log(f"Step 5: Reading {EXP_NUM_FILE} ...")
with open(EXP_NUM_FILE) as f:
    lines = [l.strip() for l in f if l.strip()]

log(f"Found {len(lines)} experiment(s) to run.")

# ── Step 6: Iterate ───────────────────────────────────────────────────────────
for exp_index, line in enumerate(lines, start=1):
    n  = int(line)
    xx = format(n + 1, "02x")
    log(f"──── Experiment {exp_index}/{len(lines)}  (n={n}  XX={xx}) ────")

    # ── 6-1: Stop → set MAC → start ───────────────────────────────────────────
    log("  6-1: Configuring pktgen (stop → set MAC → start) ...")

    remote.sendline("stop 0")
    expect_prompt(remote, ["Pktgen:/"], timeout=10, context="stop 0")
    time.sleep(0.1)

    mac_cmd = (
        f"range 0 src mac 02:42:7e:7f:eb:02 02:42:7e:7f:eb:02 02:42:7e:7f:eb:{xx} 00:00:00:00:00:01"
    )
    remote.sendline(mac_cmd)
    expect_prompt(remote, ["Pktgen:/"], timeout=10, context="range mac")
    time.sleep(0.1)

    remote.sendline("start 0")
    expect_prompt(remote, ["Pktgen:/"], timeout=10, context="start 0")
    time.sleep(0.1)

    # ── 6-2: Check alive thread count ─────────────────────────────────────────
    log("  6-2: Checking alive DPA threads (cmd 1, ~0.5 s) ...")
    local.sendline("1")
    time.sleep(0.1)

    idx = local.expect(
        [r"Alive DPA threads:\s*(\d+)\s*/\s*(\d+)", pexpect.TIMEOUT, pexpect.EOF],
        timeout=15
    )
    if idx != 0:
        die("Timed out waiting for alive-thread output.")

    alive = int(local.match.group(1))
    total = int(local.match.group(2))
    thread_ok = (alive == n)
    if thread_ok:
        log(f"  Thread check OK: {alive} / {total}")
    else:
        log(f"  WARNING: Expected {n} alive threads, got {alive} / {total}")

    # consume '> ' prompt
    local.expect(["> ", pexpect.TIMEOUT], timeout=5)

    # ── 6-3: Measure and record rates ─────────────────────────────────────────
    log("  6-3: Measuring Rx rates (cmd 2, ~2-3 s) ...")
    local.sendline("2")
    time.sleep(0.1)

    # Capture App Rx
    idx = local.expect(
        [r"App Rx:\s+([0-9]+\.[0-9]+)", pexpect.TIMEOUT, pexpect.EOF],
        timeout=15
    )
    if idx != 0:
        die("Timed out waiting for App Rx rate.")
    app_rx = local.match.group(1)

    # Capture NIC Rx
    idx = local.expect(
        [r"NIC Rx transport pass host 0:\s+([0-9]+\.[0-9]+)",
         r"ngauge failed",
         pexpect.TIMEOUT, pexpect.EOF],
        timeout=15
    )
    if idx == 0:
        nic_rx = local.match.group(1)
    elif idx == 1:
        nic_rx = "N/A"
    else:
        die("Timed out waiting for NIC Rx rate.")

    # consume '> ' prompt
    local.expect(["> ", pexpect.TIMEOUT], timeout=5)

    log(f"  Result: app_rx={app_rx} Mpps  nic_rx={nic_rx} Mpps")

    with open(EXP_RESULT_FILE, "a") as rf:
        suffix = f",error,{alive}" if not thread_ok else ""
        rf.write(f"{n},{app_rx},{nic_rx}{suffix}\n")

# ── Step 7: Cleanup ───────────────────────────────────────────────────────────
log("Step 7: Cleaning up ...")

remote.sendline("quit")
remote.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=10)

local.sendline("0")
local.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=10)

log(f"All {len(lines)} experiments complete. Results saved to {EXP_RESULT_FILE}")
