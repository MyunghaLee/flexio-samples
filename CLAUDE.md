# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FlexIO SDK samples — reference implementations for NVIDIA DPA (Data Path Accelerator) applications running on ConnectX/BlueField SmartNIC hardware. Each sample has two sides: a **host** program (runs on DPU/host Linux) and a **device** program (runs on the DPA co-processor).

## Build Commands

```bash
# Standard build (default: bf3 CPU, debugoptimized, werror enabled)
./build.sh

# Clean and rebuild
./build.sh --rebuild

# Check system compatibility before building
./build.sh --check-compatibility

# Build for specific DPA CPU target (cx7, bf3, cx8, cx9 — bf3 is default)
./build.sh --cpu cx7

# Build with multiple CPU targets
./build.sh --cpu cx7,bf3,cx8

# Build with clang instead of gcc for host side
./build.sh --clang

# Allow warnings (skip -Werror)
./build.sh --allow-warnings

# Parallel build
./build.sh -j 8

# Optimization levels: 0=debug, 1=debugoptimized+lto (default), 2=release+lto
./build.sh -O 0
```

Build outputs land in `build/`:
- `build/flexio_rpc/host/flexio_rpc`
- `build/packet_processor/host/flexio_packet_processor`

To use meson/ninja directly (after initial setup):
```bash
meson setup build --buildtype=debugoptimized -Dwerror=true -Ddefault_library=static -Dwarning_level=3 -Dcpu=bf3
meson compile -C build
```

## Architecture

### Dual-side execution model
Every sample consists of two compiled binaries that work together:

- **Host side** (`*/host/`): C application linking against `libflexio`, `libibverbs`, `libmlx5`. Runs in userspace on the DPU ARM cores or host CPU.
- **Device side** (`*/dev/`): C application compiled by `dpacc` (DOCA DPACC compiler) for the RISC-V DPA processor. Must be freestanding (`-ffreestanding`).

### DPA entry point functions
Device functions callable from the host must use one of two attributes:
- `__dpa_rpc__` — RPC function, returns `uint64_t`, called via `flexio_process_call()`
- `__dpa_global__` — event handler, no return value, registered via `flexio_event_handler_create()`

### Host ↔ Device linkage
`dpacc` (at `build/` time) generates a host-side stub library containing:
- An `extern struct flexio_app *<app_name>` — used with `flexio_process_create()`
- `extern flexio_func_t <func_name>` stubs — used with `flexio_process_call()` or as event handler `host_stub_func`

These are initialized automatically before `main()` by a constructor injected by `dpacc`.

### Versioning
Both host and device code must declare the API version they target before including FlexIO headers:
```c
// Host side
#define FLEXIO_VER_USED FLEXIO_VER(25, 10, 0)
#include <libflexio/flexio.h>

// Device side
#define FLEXIO_DEV_VER_USED FLEXIO_DEV_VER(25, 10, 0)
#include <libflexio-dev/flexio_dev.h>
```

### Common library (`common/`)
Shared utilities split by execution context:
- `common/dev/` — DPA-side helpers: queue context structs (`cq_ctx_t`, `rq_ctx_t`, `sq_ctx_t`, `eq_ctx_t`, `dt_ctx_t`), queue stepping, buffer management
- `common/host/` — Host-side helpers: flow steering utilities

### Meson build structure
- Root `meson.build` sets up host compiler, DPA compiler flags, optimization levels, and iterates over all samples
- Each sample has its own `meson.build` that calls `subdir('dev')` and `subdir('host')`
- Device code is compiled via `doca_build_dpacc.sh` as a custom target; the resulting `.a` library is linked into the host executable

## Running Samples

```bash
# flexio_rpc — requires mlx5 device with DPA
./build/flexio_rpc/host/flexio_rpc mlx5_0 44 55

# packet_processor — requires root, mlx5 device with DPA
sudo ./build/packet_processor/host/flexio_packet_processor mlx5_0

# packet_processor on CX NIC or BF in NIC mode
sudo ./build/packet_processor/host/flexio_packet_processor mlx5_0 --nic-mode
```

## Required Dependencies

- DOCA DPACC (`/opt/mellanox/doca/tools/dpacc` ≥ 2.0.0.26)
- `libflexio` (FlexIO SDK), `libibverbs`, `libmlx5`
- meson ≥ 0.60.0, ninja, gcc ≥ 7.0 or clang ≥ 7.0, python3, pkg-config
- Device must be in ETH mode
