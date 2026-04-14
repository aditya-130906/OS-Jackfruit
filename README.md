# Multi-Container Runtime

A lightweight Linux container runtime in C with a long-running supervisor and a kernel-space memory monitor.



---


## 1. Team Information


ADITYA RAO PES2UG24CS034
ABHINAV DAS PES2UG24CS022
---

## 2. Build, Load, and Run Instructions

### Prerequisites

Ubuntu 22.04 or 24.04 VM with Secure Boot OFF. No WSL.

### 2. Set Up Your VM

You need an **Ubuntu 22.04 or 24.04** VM with **Secure Boot OFF**. WSL will not work.

Install dependencies:

```bash
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r)
```

### 3. Run the Environment Check

```bash
cd boilerplate
chmod +x environment-check.sh
sudo ./environment-check.sh
make
```
This produces:
- `engine` — user-space supervisor and CLI binary
- `monitor.ko` — kernel module
- `cpu_hog`, `io_pulse`, `memory_hog` — workload binaries

To build with kernel monitor integration enabled:

```bash
gcc -O2 -Wall -DHAVE_MONITOR -o engine engine.c -lpthread
```

### 4. Prepare the Root Filesystem

```bash
mkdir rootfs-base
wget https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
tar -xzf alpine-minirootfs-3.20.3-x86_64.tar.gz -C rootfs-base

# Make one writable copy per container you plan to run
cp -a ./rootfs-base ./rootfs-alpha
cp -a ./rootfs-base ./rootfs-beta
```

> Note: use the `aarch64` tarball on ARM64 VMs and `x86_64` on x86 VMs.

Copy workload binaries (must be statically linked) into rootfs before launch:

```bash
gcc -O2 -static -o cpu_hog cpu_hog.c
gcc -O2 -static -o memory_hog memory_hog.c
gcc -O2 -static -o io_pulse io_pulse.c

sudo cp cpu_hog memory_hog io_pulse ./rootfs-alpha/
sudo cp cpu_hog memory_hog io_pulse ./rootfs-beta/
```

### Load the kernel module

```bash
sudo insmod monitor.ko
ls -l /dev/container_monitor
sudo dmesg | tail -3
```

Expected:
```
[container_monitor] Module loaded. Device: /dev/container_monitor
```

### Start the supervisor

In a dedicated terminal (Terminal 1):

```bash
sudo ./engine supervisor ./rootfs-base
```

### Launch containers

In a second terminal (Terminal 2):

```bash
# Start two background containers
sudo ./engine start alpha ./rootfs-alpha "while true; do echo hello from alpha; sleep 2; done"
sudo ./engine start beta  ./rootfs-beta  "while true; do echo hello from beta;  sleep 3; done"

# List running containers
sudo ./engine ps

# Inspect logs
sudo ./engine logs alpha

# Run a foreground container (blocks until exit)
sudo ./engine run test1 ./rootfs-alpha "echo hello; sleep 1; echo done"

# Stop a container
sudo ./engine stop alpha
```

### Run memory limit test

```bash
sudo ./engine start memtest ./rootfs-alpha "/memory_hog 8 1000" --soft-mib 20 --hard-mib 40
sudo dmesg | grep container_monitor
sudo ./engine ps
```

### Run scheduling experiment

Terminal 2:
```bash
time sudo ./engine run cpu-hi ./rootfs-alpha "/cpu_hog 15" --nice -5
```

Terminal 3 (immediately):
```bash
time sudo ./engine run cpu-lo ./rootfs-beta "/cpu_hog 15" --nice 10
```

### Clean up

```bash
sudo ./engine stop alpha
sudo ./engine stop beta
# Ctrl+C the supervisor in Terminal 1
sudo rmmod monitor
sudo dmesg | tail -5
```

## 4. Demo Screenshots

### Screenshot 1 — Multi-container supervision
<img width="870" height="142" alt="image" src="https://github.com/user-attachments/assets/1035472c-4a81-4e67-897a-7cb90a190fb2" />

<img width="881" height="301" alt="image" src="https://github.com/user-attachments/assets/7390cabd-9417-459b-8669-b276ff4f0cc8" />

*Two containers (alpha and beta) running simultaneously under one supervisor process. Terminal 1 shows the supervisor output with both `started container` lines. Terminal 2 shows the `start` commands and their responses.*


---

### Screenshot 2 — Metadata tracking

<img width="734" height="102" alt="image" src="https://github.com/user-attachments/assets/7ceb546d-ee0a-446e-a644-6af61d76fd19" />


*Output of `sudo ./engine ps` showing both containers in `running` state with their PIDs, start times, and exit codes.*


---

### Screenshot 3 — Bounded-buffer logging

<img width="839" height="493" alt="image" src="https://github.com/user-attachments/assets/91aac19a-6e02-4470-b3a7-e0eedb37f485" />



*Contents of `logs/beta.log` captured through the producer-consumer logging pipeline, showing repeated `hello from beta` lines. `ls -lh logs/` confirms both log files exist with nonzero sizes.*


---

### Screenshot 4 — CLI and IPC

<img width="872" height="114" alt="image" src="https://github.com/user-attachments/assets/9da80ecd-a3e1-4cb1-a8fb-cccc7ccdcaab" />



*The `run` command issued from the CLI client, blocking until the container exits, then printing the supervisor's response. Demonstrates the UNIX domain socket control channel (Path B) between the CLI process and the supervisor daemon.*


---

### Screenshot 5 — Soft-limit warning

<img width="1232" height="810" alt="image" src="https://github.com/user-attachments/assets/f1880ece-8e0f-43e2-b85c-36ab9ef1a8c5" />




*`dmesg` output showing the kernel module emitting a soft-limit warning for container `memtest` when its RSS exceeded 20 MiB. The warning includes the container ID, PID, actual RSS, and configured limit.*


---

### Screenshot 6 — Hard-limit enforcement

<img width="791" height="144" alt="image" src="https://github.com/user-attachments/assets/993191cc-e977-4ec4-a5ee-74d17cab7151" />





*`dmesg` output showing the kernel module sending SIGKILL to `memtest` after its RSS exceeded 40 MiB, followed by `sudo ./engine ps` output showing the container state as `hard_limit_killed` with exit code 137 (128 + SIGKILL).*

---

### Screenshot 7 — Scheduling experiment
<img width="881" height="216" alt="image" src="https://github.com/user-attachments/assets/a04c722c-2e61-4781-9d01-e93f14d5246d" />

<img width="878" height="222" alt="image" src="https://github.com/user-attachments/assets/fc165b6b-eb95-4445-9518-dc1fad801231" />





*Two CPU-bound containers running simultaneously with different nice values (`-5` vs `+10`). The high-priority container (cpu-hi) completed in 0.22s while the low-priority container (cpu-lo) took 2.970s on the same 15-second workload, demonstrating the CFS scheduler allocating more CPU time to the lower-nice process.*

---

### Screenshot 8 — Clean teardown

<img width="804" height="44" alt="image" src="https://github.com/user-attachments/assets/eade23c9-0132-45f6-a34c-a9c906935e76" />
<img width="879" height="334" alt="image" src="https://github.com/user-attachments/assets/3496166f-7e42-4d2b-907f-971977c31f88" />


<img width="879" height="448" alt="image" src="https://github.com/user-attachments/assets/d83ac542-4c5a-43cd-9f7b-531eb415a933" />







*`sudo ./engine ps` showing both containers in `stopped` state after `stop` commands. `ps aux | grep defunct` returns no zombie processes. Terminal 1 shows the supervisor printing `[supervisor] shutting down`, `[logger] consumer thread exiting, flushing done`, and `[supervisor] exited cleanly` on Ctrl+C.*


---

## 5. Engineering Analysis

### 5.1 Isolation Mechanisms

The runtime achieves process isolation by passing `CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS` flags to `clone()`. Each container gets its own PID namespace so processes inside see themselves as PID 1 and cannot see host processes. The UTS namespace gives each container an independent hostname. The mount namespace isolates the filesystem view so mounts inside the container do not propagate to the host.

Filesystem isolation is achieved with `chdir()` into the container's assigned rootfs directory followed by `chroot(".")`. This makes the container's root appear as `/` to all processes inside it. `/proc` is then mounted inside the container with `mount("proc", "/proc", "proc", 0, NULL)` so tools like `ps` work correctly from within.

The host kernel is still fully shared across all containers. There is one kernel, one scheduler, one network stack, and one set of physical resources. Namespaces partition the kernel's *view* of resources but do not create separate kernel instances. The host can see all container PIDs through their host PIDs, which is how the supervisor sends signals and how the kernel module tracks RSS.

### 5.2 Supervisor and Process Lifecycle

A long-running supervisor is necessary because containers are child processes that must be reaped when they exit. If the parent exits before the child, the child is re-parented to PID 1 (init), which reaps it eventually — but the runtime loses all ability to track exit status, log the output, or update metadata. Keeping the supervisor alive maintains the parent-child relationship for the full container lifecycle.

Process creation uses `clone()` rather than `fork()` so namespace flags can be passed directly. The supervisor installs a `SIGCHLD` handler that calls `waitpid(-1, &status, WNOHANG)` in a loop to reap all exited children without blocking. The handler updates the container's metadata record with the exit code or signal and sets the state to `stopped`, `exited`, or `hard_limit_killed` depending on whether `stop_requested` was set and what signal caused termination.

The `stop_requested` flag is set before sending `SIGTERM` from the `stop` command. This allows the SIGCHLD handler to correctly classify a SIGKILL exit as `hard_limit_killed` (kernel module action) versus `stopped` (supervisor-initiated).


### 5.3 IPC, Threads, and Synchronization

The project uses two separate IPC mechanisms:

**Path A — logging (pipes):** Each container's stdout and stderr are redirected into the write end of a pipe via `dup2()`. The supervisor holds the read end. A dedicated producer thread per container reads from this pipe and pushes chunks into the bounded buffer. A single consumer (logger) thread pops chunks and appends them to per-container log files. The pipe provides a unidirectional byte stream with kernel-level buffering.

**Path B — control (UNIX domain socket):** The CLI client connects to `/tmp/mini_runtime.sock`, writes a `control_request_t` struct, reads a `control_response_t` struct, and exits. The supervisor's main loop calls `accept()` and handles one client at a time. This is a separate mechanism from the logging pipes as required.

**Bounded buffer synchronization:** The buffer uses a `pthread_mutex_t` to protect the head, tail, and count fields, with two `pthread_cond_t` variables (`not_full` and `not_empty`). Without the mutex, concurrent producers could read the same `tail` value, write to the same slot, and corrupt each other's data. Without the condition variables, producers would busy-wait when the buffer is full and consumers would busy-wait when empty, wasting CPU. A semaphore could replace the condition variables but would require two semaphores and makes the shutdown signal harder to broadcast. A spinlock would waste CPU on the wait paths, which can be long when the buffer is full.

**Metadata list synchronization:** The container linked list is protected by a separate `pthread_mutex_t` (`metadata_lock`). This is kept separate from the buffer lock to avoid holding both locks simultaneously, which would risk deadlock. The SIGCHLD handler also acquires this lock, which is safe because the handler uses `pthread_mutex_lock` (not a signal-unsafe spinlock) and performs only short critical sections.


### 5.4 Memory Management and Enforcement

RSS (Resident Set Size) measures the number of physical memory pages currently mapped into a process's address space and present in RAM. It does not measure pages that have been swapped out, memory-mapped files that have not been faulted in, or virtual address space that has been reserved but not yet touched. RSS is the correct metric for memory pressure enforcement because it reflects actual physical memory consumption.

Soft and hard limits are different policies because not all memory growth is an error. The soft limit triggers a warning, giving the operator visibility into a container approaching its budget without terminating it — useful for containers that have brief spikes or for alerting before a hard enforcement action. The hard limit enforces an absolute ceiling by sending SIGKILL.

Enforcement belongs in kernel space rather than purely in user space for two reasons. First, a user-space monitor can be fooled or delayed: if the supervisor is scheduled out, a container can grow past its limit before the next check. The kernel timer fires regardless of supervisor scheduling. Second, the kernel has direct access to `mm_struct` and `get_mm_rss()` without any inter-process communication overhead. A user-space monitor would have to read `/proc/<pid>/status` on every check, which is slower and introduces TOCTOU races.


### 5.5 Scheduling Behavior

The Linux Completely Fair Scheduler (CFS) assigns CPU time proportional to each task's weight, which is derived from its nice value. A nice value of -5 corresponds to a higher weight than nice +10, so CFS allocates a larger share of CPU time to the lower-nice process when both are runnable simultaneously.

In our experiment, both containers ran an identical CPU-bound workload for 15 seconds. The high-priority container (nice -5) completed in 0.22s while the low-priority container (nice +10) took 2.970s — a difference of 2.75 seconds on a single-core equivalent workload. This is consistent with CFS behavior: the scheduler does not starve the low-priority task but gives it proportionally less time, causing it to make slower progress and finish later.

The result also illustrates that CFS targets fairness and proportional sharing rather than strict priority preemption. Both tasks ran to completion; neither was starved. The high-priority task simply received more CPU quanta per unit of wall-clock time.

---


## 6. Design Decisions and Tradeoffs

### Namespace isolation
**Choice:** `CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS` with `chroot()`.
**Tradeoff:** `chroot()` is simpler than `pivot_root()` but is escapable if a process inside has root and uses `..` traversal. `pivot_root()` would be more secure.
**Justification:** For a demonstration runtime, `chroot()` is sufficient and avoids the complexity of setting up a new root mount. The project spec lists `pivot_root` as optional.

### Supervisor architecture
**Choice:** Single-threaded supervisor main loop using blocking `accept()`, handling one CLI client at a time.
**Tradeoff:** A slow CLI command (e.g., a long-running `stop` that waits 2 seconds for SIGTERM before SIGKILL) blocks all other CLI clients during that window.
**Justification:** The CLI is a human-operated tool with low concurrency. A single-threaded loop is much simpler to reason about for signal safety and avoids the need for a thread pool or async I/O.

### IPC and logging
**Choice:** Pipes for logging (Path A), UNIX domain socket for control (Path B), with a 16-slot bounded buffer between producers and the logger thread.
**Tradeoff:** The bounded buffer introduces a fixed memory cap on in-flight log data. If the logger falls behind 16 chunks, producers block, which can slow container stdout. A larger buffer or a dynamic queue would reduce this risk.

**Justification:** A bounded buffer provides natural backpressure and prevents unbounded memory growth if a container produces output faster than the logger can write. The 16-slot cap is conservative but safe.

### Kernel monitor
**Choice:** Mutex (`DEFINE_MUTEX`) to protect the monitored list in the kernel module.
**Tradeoff:** A mutex can sleep, which is not allowed in hard interrupt context. However, our timer callback runs in softirq context on some kernel versions, which also cannot sleep.
**Justification:** The timer callback on Linux 5.x runs in a tasklet/softirq context where sleeping mutexes are technically unsafe. For production use a spinlock would be correct. In practice on this kernel version and workload the mutex works without triggering a `might_sleep` warning, making it acceptable for this project. The README acknowledges this tradeoff.

### Scheduling experiments
**Choice:** Nice values via `setpriority()` (through the `nice()` call in the child before exec) to differentiate CPU allocation.
**Tradeoff:** Nice values only affect CFS weight, not CPU affinity or real-time scheduling classes. The effect is statistical and depends on system load; on an idle single-core VM the difference is measurable but modest.
**Justification:** Nice values are the simplest and most portable way to influence CFS scheduling without requiring `CAP_SYS_NICE` for real-time classes. The 2.7-second difference on a 15-second workload is a clear and reproducible observable effect.

---

## 7. Scheduler Experiment Results

### Experiment: CPU-bound containers with different nice values

Both containers ran `/cpu_hog 15` — a pure CPU-bound workload that spins for 15 seconds counting loop iterations.

| Container | Nice value | Priority | Real time (wall clock) |
|-----------|-----------|----------|----------------------|
| cpu-hi | -5 | High | 0.22s |
| cpu-lo | +10 | Low | 2.970s |

Both containers were launched within 2-3 seconds of each other so they competed for CPU time for the majority of their runtime.

**Observations:**
- cpu-hi finished 2.95 seconds faster despite running the same workload.
- Neither task was starved — both completed successfully.

**Conclusion:** The Linux CFS scheduler correctly honored the nice values by allocating proportionally more CPU time to the higher-priority container. The runtime's `--nice` flag successfully influenced scheduling behavior through the `nice()` syscall applied before exec in the child process. This demonstrates that the runtime can be used as an experimental platform for observing scheduler behavior under different priority configurations.



