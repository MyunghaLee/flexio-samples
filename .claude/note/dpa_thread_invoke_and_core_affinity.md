# DPA Thread: Inter-Thread Invocation & Core Co-location

Source: NVIDIA DOCA 3.2.1 documentation
Date: 2026-03-18

---

## 1. How One DPA Thread Invokes Another DPA Thread

### Mechanism: `doca_dpa_notification_completion`

This is the standard mechanism for a running DPA kernel to trigger/wake another DPA thread
that is not involved in packet receiving. The target thread is bound to a "notification
completion" object. The triggering kernel calls a single device-side function.

> **Key note from docs:** "Thread activation is done without receiving a completion on the
> attached thread. Therefore it is expected that the user of this method passes the message
> in another fashion – such as shared memory."

### Host-Side Setup

```c
// 1. Create and configure the target thread (the one to be triggered)
doca_dpa_thread_create(dpa, &target_thread);
doca_dpa_thread_set_func_arg(target_thread, &hello_kernel, func_arg);
doca_dpa_thread_start(target_thread);

// 2. Create the notification completion bound to that thread
doca_dpa_notification_completion_create(dpa, target_thread, &notify_comp);
doca_dpa_notification_completion_start(notify_comp);

// 3. Get the DPA-side opaque handle
doca_dpa_dev_notification_completion_t notify_comp_handle;
doca_dpa_notification_completion_get_dpa_handle(notify_comp, &notify_comp_handle);
// -> Pass notify_comp_handle to the triggering kernel via RPC arg or shared memory

// 4. Put the target thread in the waiting/runnable state
doca_dpa_thread_run(target_thread);
```

Host-side API summary:
```c
doca_dpa_notification_completion_create(dpa, thread, &notify_comp);
doca_dpa_notification_completion_start(notify_comp);
doca_dpa_notification_completion_stop(notify_comp);
doca_dpa_notification_completion_destroy(notify_comp);
doca_dpa_notification_completion_get_dpa_handle(notify_comp, &handle);
```

### Device-Side Trigger (inside any DPA kernel)

```c
// The triggering kernel fires the target thread:
doca_dpa_dev_thread_notify(notify_comp_handle);
// Target thread will be scheduled to run its kernel function.
```

### Passing Data Between Threads

There is **no built-in message passing**. Use shared DPA memory with volatile flags
and memory fences:

```c
// Triggering kernel writes data to shared memory, then notifies
volatile uint64_t *shared = (volatile uint64_t *)shared_dpa_buf;
*shared = my_data;
__dpa_thread_memory_writeback();   // or appropriate fence
doca_dpa_dev_thread_notify(notify_comp_handle);

// Target kernel reads from shared memory after waking
uint64_t data = *shared;
```

### Teardown

```c
doca_dpa_notification_completion_stop(notify_comp);
doca_dpa_notification_completion_destroy(notify_comp);
```

---

## 2. How to Set Two DPA Threads on the Same Core

### DPA Core/EU Architecture

- DPA has multiple physical **cores**, each with a fixed number of **Execution Units (EUs)**.
- EU IDs are contiguous per core:
  - Core 0 → EU IDs `[0, eus_per_core - 1]`
  - Core 1 → EU IDs `[eus_per_core, 2*eus_per_core - 1]`
  - Core C → EU IDs `[C * eus_per_core, (C+1) * eus_per_core - 1]`
- To co-locate two threads on the same physical core, assign them EU IDs within the same core's range.

### Query APIs

```c
unsigned int num_cores, eus_per_core, total_eus;
doca_dpa_get_core_num(dpa, &num_cores);
doca_dpa_get_num_eus_per_core(dpa, &eus_per_core);
doca_dpa_get_total_num_eus_available(dpa, &total_eus);
```

### EU Affinity APIs

```c
// Create affinity object (one per thread)
doca_dpa_eu_affinity_create(dpa, &affinity);
doca_dpa_eu_affinity_destroy(affinity);

// Set/clear/get the EU ID in the affinity object
doca_dpa_eu_affinity_set(affinity, eu_id);
doca_dpa_eu_affinity_clear(affinity);
doca_dpa_eu_affinity_get(affinity, &eu_id);

// Attach to thread (must be done BEFORE thread_start)
doca_dpa_thread_set_affinity(thread, affinity);
doca_dpa_thread_get_affinity(thread, &affinity);
```

### Complete Example: Two Threads on the Same Core

```c
unsigned int eus_per_core;
doca_dpa_get_num_eus_per_core(dpa, &eus_per_core);

// Pick two EUs from the same core (e.g., core 1)
unsigned int eu_a = 1 * eus_per_core + 0;  // first EU of core 1
unsigned int eu_b = 1 * eus_per_core + 1;  // second EU of core 1

// Thread A (e.g., packet-receiving thread)
doca_dpa_eu_affinity_create(dpa, &affinity_a);
doca_dpa_eu_affinity_set(affinity_a, eu_a);
doca_dpa_thread_set_affinity(thread_a, affinity_a);
doca_dpa_thread_start(thread_a);
doca_dpa_thread_run(thread_a);

// Thread B (e.g., worker thread triggered by Thread A)
doca_dpa_eu_affinity_create(dpa, &affinity_b);
doca_dpa_eu_affinity_set(affinity_b, eu_b);
doca_dpa_thread_set_affinity(thread_b, affinity_b);
doca_dpa_thread_start(thread_b);
doca_dpa_thread_run(thread_b);
```

### Key Constraints

- Each `doca_dpa_eu_affinity` object targets **exactly one EU** — separate objects per thread.
- DPA uses **cooperative, run-to-completion** scheduling — threads on the same core's EUs
  interleave at EU granularity, not preemptively.
- Maximum **256 DPA threads** total.
- Some EUs/cores may be **reserved by firmware** — always query before assigning; do not
  assume EU IDs 0..N-1 are all available.
- In sub-partitions (SPRD YAML), EU IDs are **relative** within the partition:
  ```yaml
  EU_allocation:
    - core: 1
      num_EUs: 4   # allocates 4 EUs from physical core 1
  ```
- There is no runtime API to query which EU a thread is currently executing on.

---

## Combined Pattern: Receiver Thread Triggers Worker Thread on Same Core

```
Host setup:
  1. Query eus_per_core → pick eu_recv and eu_worker from same core
  2. Create thread_recv with eu_recv affinity
  3. Create thread_worker with eu_worker affinity
  4. Create notify_comp bound to thread_worker
  5. Get notify_comp_handle, pass to thread_recv via RPC/shared mem
  6. thread_run both threads

DPA kernel (thread_recv, runs on eu_recv):
  - receives packet, processes it
  - writes result to shared DPA buf
  - doca_dpa_dev_thread_notify(notify_comp_handle)  <- triggers thread_worker

DPA kernel (thread_worker, runs on eu_worker, same core):
  - wakes up
  - reads result from shared DPA buf
  - performs offload/compute work
  - doca_dpa_dev_thread_reschedule() to wait for next trigger
```
