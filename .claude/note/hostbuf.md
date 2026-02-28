# Host Memory Packet Buffers — Research Notes & Implementation

## Status: IMPLEMENTED in packet_processor (branch: hostbuf)
Files changed:
- `packet_processor/flexio_packet_processor_com.h` — added `window_id` field
- `packet_processor/host/flexio_packet_processor_host.c` — host-side changes
- `packet_processor/dev/flexio_packet_processor_dev.c` — DPA-side changes

---

Goal: modify `packet_processor` so that RQ/SQ **packet data buffers** live in
host (DPU/CPU) memory rather than DPA heap memory.

---

## 0. BenchBF3 vs v25.10 API Differences (CRITICAL)

BenchBF3 uses FlexIO v23.10. Our code uses v25.10. Key API changes:

| v23.10 (BenchBF3) | v25.10 (our code) |
|---|---|
| `flexio_dev_window_config(dtctx, win_id, mkey)` | `flexio_dev_window_config(win_entity, win_id, mkey)` |
| `flexio_dev_window_ptr_acquire(dtctx, haddr, &daddr)` | `flexio_dev_window_ptr_acquire(win_entity, haddr, &daddr)` |
| `flexio_dev_cq_arm(dtctx, ci, qnum)` | `flexio_dev_cq_arm(ci, qnum)` |
| `flexio_dev_qp_sq_ring_db(dtctx, pi, qnum)` | `flexio_dev_qp_sq_ring_db(pi, qnum)` |

In v25.10, `flexio_dev_get_thread_ctx()` is NOT needed for these operations.

v25.10 introduces two window entities (`FLEXIO_DEV_WINDOW_ENTITY_0`, `FLEXIO_DEV_WINDOW_ENTITY_1`)
which lets you configure RQ and SQ buffers independently on different entities.

---

## 1. What Is DPA Window Access

The DPA cannot dereference host memory directly via normal load/store.  It must
use the **FlexIO Window** mechanism:

- A window maps a chunk of host-registered memory into the DPA process address
  space via memory apertures.
- The host creates a window object once; the DPA configures the mkey for the
  window each time the handler runs (the mkey is not preserved across handler
  invocations).
- After DPA writes to window memory it must call `__dpa_thread_window_writeback()`
  so the data becomes visible to external entities (NIC, host).
- Before re-reading stale window memory, call `__dpa_thread_window_read_inv()`.

### Host API
```c
// Create window (once, at setup)
flexio_window_create(process, pd, &window);

// Get window ID to pass to DPA
uint32_t win_id = flexio_window_get_id(window);

// Destroy at teardown
flexio_window_destroy(window);
```

### DPA API (inside event handler)
```c
// Configure the window with the mkey for the target buffer (must do every invocation)
flexio_dev_window_config(win_entity, win_id, mkey_id);

// Get a DPA-local pointer to a host address
flexio_uintptr_t dev_ptr;
flexio_dev_window_ptr_acquire(win_entity, (uint64_t)haddr, &dev_ptr);

// Use dev_ptr like a normal pointer; then flush writes:
__dpa_thread_window_writeback();
```

API variants (v25.10 uses entity-based multi-window):
- `flexio_dev_window_config(entity, window_id, mkey)` — sets window + mkey
- `flexio_dev_window_mkey_config(entity, mkey)` — sets only the mkey
- `flexio_dev_window_ptr_acquire(entity, haddr, &daddr)` — translates host addr
  to a DPA-accessible pointer in the window address space
- `flexio_dev_window_copy_from_host(entity, daddr, haddr, size)` — copy host→DPA
- `flexio_dev_window_copy_to_host(entity, haddr, daddr, size)` — copy DPA→host

---

## 2. Host Memory Registration — UMEM vs ibv_reg_mr

Two registration paths are needed:

### Path A: mlx5dv_devx_umem_reg (for queue descriptors / flexio_qmem)
Used when passing memory to `flexio_qmem` structs (`wq_ring_qmem`, `wq_dbr_qmem`,
`cq_ring_qmem`).

```c
struct mlx5dv_devx_umem *umem;
umem = mlx5dv_devx_umem_reg(ibv_ctx, buf, size,
                             IBV_ACCESS_LOCAL_WRITE);
// → umem->umem_id used in flexio_qmem.umem_id

flexio_qmem q;
q.memtype     = FLEXIO_MEMTYPE_HOST;
q.humem_offset = 0;          // byte offset into the registered region
q.umem_id     = umem->umem_id;
```

### Path B: ibv_reg_mr (for data buffer mkeys used in WQEs)
The data buffer pointer+lkey stored in RQ/SQ WQEs must reference host memory.
`ibv_reg_mr` gives you an `lkey` the NIC can use, and a `mkey_id` the DPA window
can use.

```c
struct ibv_mr *mr = ibv_reg_mr(pd, buf, size,
                                IBV_ACCESS_LOCAL_WRITE |
                                IBV_ACCESS_REMOTE_WRITE);
// mr->lkey  → put in WQE data seg as mkey_id
// mr->lkey  → DPA window mkey to configure with flexio_dev_window_config()
```

> **Important**: `flexio_device_mkey_create()` (currently used) wraps DPA heap
> memory.  It does NOT work for host memory.  Replace it with `ibv_reg_mr()`.

### Alignment
- Both address and size passed to UMEM/ibv_reg_mr must be **64-byte aligned**.
- Use `posix_memalign(&buf, 64, size)` on the host.

---

## 3. flexio_qmem Structure (for queue rings, not data buffers)

```c
struct flexio_qmem {
    enum flexio_memtype memtype;   // FLEXIO_MEMTYPE_DPA (0) or FLEXIO_MEMTYPE_HOST (1)
    union {
        flexio_uintptr_t daddr;    // DPA heap address (DPA type only)
        uint64_t humem_offset;     // offset within the registered UMEM (HOST type)
    };
    uint32_t umem_id;              // UMEM ID from mlx5dv_devx_umem_reg (HOST type)
};
```

Used in:
- `flexio_cq_attr.cq_ring_qmem`
- `flexio_wq_attr.wq_ring_qmem`
- `flexio_wq_attr.wq_dbr_qmem`

---

## 4. Current packet_processor Memory Layout

All allocations are on **DPA heap**:

| Buffer | Allocated by | Used in |
|--------|--------------|---------|
| RQ data (`wqd_daddr`) | `flexio_buf_dev_alloc()` | RQ WQEs point here (NIC DMA-writes packets here) |
| SQ data (`wqd_daddr`) | `flexio_buf_dev_alloc()` | DPA writes modified packet here; SQ WQE points here |
| RQ ring | `flexio_buf_dev_alloc()` | `rq_attr.wq_ring_qmem.daddr` |
| SQ ring | `flexio_buf_dev_alloc()` | `sq_attr.wq_ring_qmem.daddr` |
| RQ DBR  | `flexio_copy_from_host()` | `rq_attr.wq_dbr_qmem.daddr` |
| CQ rings/DBRs | `flexio_copy_from_host()` | `cq_ring_qmem.daddr` / `cq_dbr_daddr` |

The `create_dpa_mkey()` helper wraps the DPA `wqd_daddr` into a `flexio_mkey`
whose ID is placed in WQEs.

On the DPA side, `flexio_dev_rwqe_get_addr(rwqe)` returns the DPA pointer
directly — it's just cast from the WQE's addr field.

---

## 5. Required Changes to Use Host Memory for Packet Data Buffers

Only the **data buffers** (`wqd_daddr`) need to move.  The queue rings (WQ ring,
DBR, CQ ring) can remain on DPA for performance.

### 5.1 Host Side

**New fields needed in `app_context`:**
```c
void *rq_data_hbuf;          // host virtual address of RQ data buffer (aligned)
void *sq_data_hbuf;          // host virtual address of SQ data buffer (aligned)
struct ibv_mr   *rqd_mr;     // mr for RQ data → mr->lkey = rq mkey_id
struct ibv_mr   *sqd_mr;     // mr for SQ data → mr->lkey = sq mkey_id
struct flexio_window *window; // window for DPA access to host buffers
```

**New fields needed in transfer struct (`app_transfer_wq`):**
Add host virtual address to communicate to DPA:
```c
uint64_t wqd_haddr;   // host virtual address of data buffer
```

**Replace `flexio_buf_dev_alloc()` for data buffers:**
```c
posix_memalign(&ctx->rq_data_hbuf, 64, Q_DATA_BSIZE);
ctx->rqd_mr = ibv_reg_mr(pd, ctx->rq_data_hbuf, Q_DATA_BSIZE,
                          IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
// Pass mr->lkey as wqd_mkey_id and rq_data_hbuf as wqd_haddr in transfer struct
```

**Replace `create_dpa_mkey()` for data buffers:**
Use `ibv_reg_mr()` above instead.  The returned `mr->lkey` is the mkey_id to put
in WQEs.

**Initialize RQ WQEs:**
`mlx5dv_set_data_seg(dseg, Q_DATA_ENTRY_BSIZE, mr->lkey, (uint64_t)hbuf_slot)` —
use host virtual address + ibv lkey (not DPA address + flexio mkey).

**Create window:**
```c
flexio_window_create(process, pd, &ctx->window);
// pass flexio_window_get_id(ctx->window) to DPA in transfer struct
```

### 5.2 DPA Side

**New fields in `app_ctx`:**
```c
uint32_t window_id;       // from flexio_window_get_id()
uint32_t rqd_mkey;        // ibv lkey for RQ data (same as wqd_mkey_id in rq_transf)
uint32_t sqd_mkey;        // ibv lkey for SQ data
uint64_t rqd_haddr_base;  // host base address of RQ data buffer
uint64_t sqd_haddr_base;  // host base address of SQ data buffer
```

**On first run (in `app_ctx_init`):**
```c
// Configure window with one of the mkeys (can be reconfigured per access)
flexio_dev_window_config(FLEXIO_DEV_WINDOW_ENTITY_0, window_id, rqd_mkey);
```

> The window mkey must be re-configured each handler invocation because the
> thread context window ID resets to the default (NULL if no default set).

**In `process_packet()`:**

Instead of:
```c
rq_data = flexio_dev_rwqe_get_addr(rwqe);   // DPA pointer, usable directly
```

Do:
```c
uint64_t rq_haddr = (uint64_t)flexio_dev_rwqe_get_addr(rwqe);  // host VA
flexio_uintptr_t rq_dev_ptr;
// configure window for rq mkey
flexio_dev_window_config(FLEXIO_DEV_WINDOW_ENTITY_0, window_id, app_ctx.rqd_mkey);
flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0, rq_haddr, &rq_dev_ptr);
char *rq_data = (char *)rq_dev_ptr;
```

For SQ data buffer: compute host address from base + index, acquire window pointer,
write modified packet, then `__dpa_thread_window_writeback()` before ringing SQ doorbell.

**Fence order for SQ with host data buffer:**
| Step | Action | Notes |
|------|--------|-------|
| 1 | Write WQE payload to host memory via window | MMIO write |
| 2 | `__dpa_thread_window_writeback()` | Flush window writes |
| 3 | Write SQ WQE to DPA ring | Memory write |
| 4 | `__dpa_thread_memory_writeback()` | Flush DPA memory writes |
| 5 | Ring SQ doorbell | MMIO write |

---

## 6. Key API Reference

| API | Header | Purpose |
|-----|--------|---------|
| `mlx5dv_devx_umem_reg(ctx, addr, size, access)` | `mlx5dv.h` | Register host memory as UMEM; returns `{umem_id}` |
| `mlx5dv_devx_umem_dereg(umem)` | `mlx5dv.h` | Deregister UMEM |
| `ibv_reg_mr(pd, addr, len, access)` | `verbs.h` | Register MR; `mr->lkey` used in WQEs & window config |
| `ibv_dereg_mr(mr)` | `verbs.h` | Deregister MR |
| `flexio_window_create(process, pd, &win)` | `flexio.h` | Create window object |
| `flexio_window_get_id(win)` | `flexio.h` | Get window ID for DPA |
| `flexio_window_destroy(win)` | `flexio.h` | Destroy window |
| `flexio_dev_window_config(entity, win_id, mkey)` | `flexio_dev.h` | DPA: bind window to mkey |
| `flexio_dev_window_ptr_acquire(entity, haddr, &daddr)` | `flexio_dev.h` | DPA: translate host VA → DPA-accessible ptr |
| `flexio_dev_window_copy_from_host(entity, daddr, haddr, sz)` | `flexio_dev.h` | DPA: bulk copy host→DPA (UNSUPPORTED per header) |
| `flexio_dev_window_copy_to_host(entity, haddr, daddr, sz)` | `flexio_dev.h` | DPA: bulk copy DPA→host |
| `__dpa_thread_window_writeback()` | `dpaintrin.h` | Flush window writes to external memory |
| `__dpa_thread_window_read_inv()` | `dpaintrin.h` | Invalidate cached window reads |

---

## 7. Coherency Notes

- NIC→DPA: coherent. When NIC writes received packet to host buffer and generates
  CQE, the CQE ownership change guarantees the packet data is visible to DPA
  (via window). No extra fence needed before reading the packet.
- DPA→NIC (via SQ WQE data in host memory): NOT coherent.
  Must `__dpa_thread_window_writeback()` before ringing doorbell.

---

## 8. What Does NOT Need to Change

- CQ rings/DBRs — keep on DPA heap (`flexio_copy_from_host` as-is)
- WQ rings (SQ/RQ descriptor rings) — keep on DPA heap (`flexio_buf_dev_alloc` as-is)
- RQ DBR — keep on DPA heap
- `not_first_run` flag storage — keep on DPA heap
- Steering rules, event handler, process setup — unchanged

---

## 9. Implementation Details (actual code)

### Design choices made

**Single `ibv_reg_mr()` per buffer**: RQ and SQ data buffers are registered separately,
giving distinct lkeys. This allows using two window entities independently.

**Two window entities**: Entity 0 for RQ (rq_lkey), entity 1 for SQ (sq_lkey).
Both configured once at the START of each handler invocation, not per packet.
This is more efficient than reconfiguring per packet.

**DPA VA base translation**: Instead of calling `flexio_dev_window_ptr_acquire` per
packet, we:
1. Call it once per invocation with the buffer base address → get `rqd_dpa_base`/`sqd_dpa_base`
2. Per packet: compute offset from base and add to DPA base
   ```c
   rq_data = (char *)(rqd_dpa_base + (rq_haddr - rqd_haddr_base));
   sq_data = (char *)(sqd_dpa_base + tx_idx * slot_size);
   ```

**wqd_daddr field reuse**: `app_transfer_wq.wqd_daddr` stores the HOST virtual address
(not DPA address) when buffers are in host memory. The DPA reads it as a host VA.

**SQ WQE data addr**: `flexio_dev_swqe_seg_mem_ptr_data_set(swqe, sz, sq_lkey, sq_haddr)`
uses the HOST VA (`sq_haddr`) + ibv lkey. NIC uses lkey for IOMMU translation.

### Fence/writeback sequence in process_packet()
1. `memcpy(sq_data, rq_data, ...)` — DPA writes to host SQ buffer via window (MMIO)
2. `swap_macs(sq_data)` — more window writes
3. `__dpa_thread_window_writeback()` — flush window writes to host memory
4. `__dpa_thread_fence(__DPA_MEMORY, W, W)` — order WQE write vs doorbell
5. `flexio_dev_qp_sq_ring_db(...)` — ring doorbell

### host2dev struct change
Added `uint32_t window_id` to `host2dev_packet_processor_data` (packed/aligned struct).
The window ID comes from `flexio_window_get_id(app_ctx.window)`.

### NOT used: mlx5dv_devx_umem_reg
Only needed when passing memory to `flexio_qmem` structs (WQ ring/DBR in host memory).
Since we keep WQ rings on DPA, we use only `ibv_reg_mr()` for data buffer mkeys.

---

## 10. Fixes Applied (forwarding was not working)

Reference: `.claude/ref/flexio-samples_tkhan/packet_processor/`

### Root causes identified

**1. Missing `daddr_on_host` field in `app_transfer_wq`**
The reference uses `uint8_t daddr_on_host` to tell the DPA side whether the data buffer
is in host memory or DPA memory. Without this, the device side has no way to decide
whether to do window-based host address translation vs direct DPA pointer access.
- Added `daddr_on_host` to `app_transfer_wq` struct in `flexio_packet_processor_com.h`
- Host sets `daddr_on_host = 1` for both RQ and SQ in `sq_mem_alloc()` / `rq_mem_alloc()`

**2. No error checking on window config/acquire (device side)**
The original code called `flexio_dev_window_config()` and `flexio_dev_window_ptr_acquire()`
without checking return values. If either fails, the DPA base pointers remain 0 (from
static initialization), causing all packet reads/writes to go to wrong addresses.
- Added `map_host_buffers()` function (matching reference) that checks
  `FLEXIO_DEV_STATUS_SUCCESS` on every call and reschedules on failure.

**3. Unconditional `flexio_dev_print` in packet loop (device side)**
The original code called `flexio_dev_print("Process packet: %ld\n", ...)` on every
single packet in synchronous message stream mode. This blocks the DPA thread waiting
for host-side message stream consumption, slowing forwarding significantly or stalling it.
- Removed the unconditional print. Reference only prints when `debug_enable` is on.

**4. MR access flags too restrictive (host side)**
Original: `IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE`
Fixed:    `IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC`
The reference uses all four flags. `REMOTE_READ` may be needed for NIC DMA-read of
SQ packet data from host memory.

### Code structure changes (device side, aligned with reference)

- Renamed `sq_lkey` → `lkey`, `rq_lkey` stays `rq_lkey` (matches reference naming)
- Added `rq_on_host` / `sq_on_host` flags read from `daddr_on_host`
- Renamed `rqd_haddr_base`/`sqd_haddr_base` → `rq_host_base`/`sq_host_base`
- Renamed `rqd_dpa_base`/`sqd_dpa_base` → `rq_dpa_base`/`sq_dpa_base`
- Added `rq_host_to_dpa()` / `sq_host_to_dpa()` helper functions
- Uses `get_next_dte()` instead of manual `dt_ctx.tx_buff_idx++` computation
- Window writeback is now conditional: `if (app_ctx.sq_on_host) __dpa_thread_window_writeback()`
- `packets_count++` moved after `process_packet()` (matches reference)
- DPA bases initialized to host bases in `app_ctx_init()` — overwritten by
  `map_host_buffers()` when on host. This lets the same code path work for DPA-memory
  mode too (no window mapping needed, addresses used directly).
