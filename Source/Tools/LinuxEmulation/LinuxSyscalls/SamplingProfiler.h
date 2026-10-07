// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|Profiling
desc: In-process PC sampler for guest threads (no ptrace), driven by a host signal
$end_info$
*/
#pragma once

#include <cstdint>

namespace FEXCore::Core {
struct InternalThreadState;
}
namespace FEX::HLE {
class SignalDelegator;

/**
 * Statistical profiler for the emulated process, enabled with FEX_PROFILESAMPLEHZ=<hz> (0 = off).
 *
 * A host thread sends SIGPROF to the guest threads' host thread at the requested rate (the main guest thread by default,
 * every thread with FEX_PROFILESAMPLEALL=1); the signal handler records the interrupted host PC and the last guest RIP
 * FEX had stored into `/dev/shm/fex-<pid>-samples` as 16-byte records {pc, rip-or-tid}. Resolve host PCs with the
 * perf map produced by FEX_LIBRARYJITNAMING=1 (`/tmp/perf-<pid>.map`) and the FEX binary's symbols.
 *
 * It exists because attaching a debugger or `perf` to a process that runs an anti-cheat is detected (and rightly so);
 * this runs entirely inside the emulator process.
 */
void StartSamplingProfiler(FEX::HLE::SignalDelegator* Signals, uint32_t Hz, bool AllThreads);
} // namespace FEX::HLE
