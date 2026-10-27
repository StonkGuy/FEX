# wine-ntflag

EFLAGS.NT (bit 14) seen through Wine: a Windows x64 PE (`build.sh`, mingw). Run `wine ntflag.exe` natively on x86-64
(the oracle) and under FEX; every line must PASS and the exit code is the number of failed phases.

1. `popfq` sets NT and `pushfq` reads it back (two threads).
2. A raw `syscall` with an invalid number (`eax = -1`) returns with NT in R11.
3. An exception (`ud2`) reports the live NT in `CONTEXT.EFlags`; the NT a vectored handler writes there is live after
   `EXCEPTION_CONTINUE_EXECUTION` (0->0, 0->1, 1->0, 1->1).
4. `iretq` with NT = 1 faults at the `iretq` with its frame untouched and NT = 1 in the exception context (the line
   prints the exception code and parameters Wine reports).
5. `iretq` with NT = 0 loads NT from the RFLAGS in its frame.
6. Child processes can set NT.

The behaviour list follows the CPU checks that github.com/zzoko's THE FINALS / ARC Raiders CrossOver packages run
before enabling their translator fix; this program is written independently. The raw-kernel side (no Wine) is
`../iret-nt/`.
