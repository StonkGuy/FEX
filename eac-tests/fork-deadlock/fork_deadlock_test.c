/*
 * fork_deadlock_test — must a guest fork wait on a lock the guest never took?
 *
 * FEX forks via a raw host clone, bypassing glibc's fork() and its atfork handlers, and runs its own
 * lock protocol around the clone. That protocol (ContextImpl::LockBeforeFork and the syscall-layer
 * hooks) covers the allocator, the thread manager, the VMA tracking and the code-invalidation
 * mutexes — but not DiskCache's IndexLock / MemoryLRULock, two plain std::mutexes taken by the
 * dedicated "FEX:DiskCache" writer thread while it is storing a compiled block. When a guest thread
 * forks while the writer is inside that critical section, the child inherits the mutex locked with
 * its owner gone, and the child's next block lookup blocks forever on a futex. The mutex lives in
 * ContextImpl, which rpmalloc allocates — hence the child sleeps on a futex in [anon:FEXAllocator].
 *
 * This test is the differential: a guest program that holds no cross-thread locks of its own forks
 * in a tight loop while new guest code is being compiled, so the FEX-internal writer is busy, and
 * each child immediately executes code its parent never compiled, forcing the child's own block
 * lookup. Under native x86-64 Linux this trivially completes. Under a FEX that inherits the writer's
 * lock, some level of the fork chain hangs and the run times out. Under a FEX with the DiskCache
 * locks inside the fork protocol, it completes like native.
 *
 * The chain is linear: every process compiles one fresh switch case (a block new to it), forks,
 * and waits; the child continues the loop, so each level is both a fork-while-writer-busy
 * candidate and a first-lookup-after-fork candidate. A naive repro that takes a user pthread mutex
 * in a writer thread and forks is NOT a valid differential: user mutexes held across fork hang
 * natively too (glibc's atfork protection covers only its own locks) — that shape was tried and
 * it times out on real hardware. The FEX bug is precisely that locks the guest never created leak
 * into the child.
 *
 * Run with the FEX disk cache ENABLED (the default; do not set FEX_DISKCACHE=0) — the writer thread
 * and its Store/Lookup traffic are the mechanism under test.
 *
 * Exit status: 0 = completed, 124 (timeout) / 1 = a level hung or failed, 2 = setup failed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

/* One distinct basic block per case: the immediate is baked into the instruction, so each case
   compiles to code no other case shares. 256 levels of fresh compiles per run. */
#define LEVELS 256

static volatile unsigned long sink;

static void churn(unsigned i) {
  switch (i) {
/* GENERATED-CASES-BEGIN */
  case 0: sink ^= 74565UL; break;
  case 1: sink ^= 2654510326UL; break;
  case 2: sink ^= 5308946087UL; break;
  case 3: sink ^= 7963381848UL; break;
  case 4: sink ^= 10617817609UL; break;
  case 5: sink ^= 13272253370UL; break;
  case 6: sink ^= 15926689131UL; break;
  case 7: sink ^= 18581124892UL; break;
  case 8: sink ^= 21235560653UL; break;
  case 9: sink ^= 23889996414UL; break;
  case 10: sink ^= 26544432175UL; break;
  case 11: sink ^= 29198867936UL; break;
  case 12: sink ^= 31853303697UL; break;
  case 13: sink ^= 34507739458UL; break;
  case 14: sink ^= 37162175219UL; break;
  case 15: sink ^= 39816610980UL; break;
  case 16: sink ^= 42471046741UL; break;
  case 17: sink ^= 45125482502UL; break;
  case 18: sink ^= 47779918263UL; break;
  case 19: sink ^= 50434354024UL; break;
  case 20: sink ^= 53088789785UL; break;
  case 21: sink ^= 55743225546UL; break;
  case 22: sink ^= 58397661307UL; break;
  case 23: sink ^= 61052097068UL; break;
  case 24: sink ^= 63706532829UL; break;
  case 25: sink ^= 66360968590UL; break;
  case 26: sink ^= 69015404351UL; break;
  case 27: sink ^= 71669840112UL; break;
  case 28: sink ^= 74324275873UL; break;
  case 29: sink ^= 76978711634UL; break;
  case 30: sink ^= 79633147395UL; break;
  case 31: sink ^= 82287583156UL; break;
  case 32: sink ^= 84942018917UL; break;
  case 33: sink ^= 87596454678UL; break;
  case 34: sink ^= 90250890439UL; break;
  case 35: sink ^= 92905326200UL; break;
  case 36: sink ^= 95559761961UL; break;
  case 37: sink ^= 98214197722UL; break;
  case 38: sink ^= 100868633483UL; break;
  case 39: sink ^= 103523069244UL; break;
  case 40: sink ^= 106177505005UL; break;
  case 41: sink ^= 108831940766UL; break;
  case 42: sink ^= 111486376527UL; break;
  case 43: sink ^= 114140812288UL; break;
  case 44: sink ^= 116795248049UL; break;
  case 45: sink ^= 119449683810UL; break;
  case 46: sink ^= 122104119571UL; break;
  case 47: sink ^= 124758555332UL; break;
  case 48: sink ^= 127412991093UL; break;
  case 49: sink ^= 130067426854UL; break;
  case 50: sink ^= 132721862615UL; break;
  case 51: sink ^= 135376298376UL; break;
  case 52: sink ^= 138030734137UL; break;
  case 53: sink ^= 140685169898UL; break;
  case 54: sink ^= 143339605659UL; break;
  case 55: sink ^= 145994041420UL; break;
  case 56: sink ^= 148648477181UL; break;
  case 57: sink ^= 151302912942UL; break;
  case 58: sink ^= 153957348703UL; break;
  case 59: sink ^= 156611784464UL; break;
  case 60: sink ^= 159266220225UL; break;
  case 61: sink ^= 161920655986UL; break;
  case 62: sink ^= 164575091747UL; break;
  case 63: sink ^= 167229527508UL; break;
  case 64: sink ^= 169883963269UL; break;
  case 65: sink ^= 172538399030UL; break;
  case 66: sink ^= 175192834791UL; break;
  case 67: sink ^= 177847270552UL; break;
  case 68: sink ^= 180501706313UL; break;
  case 69: sink ^= 183156142074UL; break;
  case 70: sink ^= 185810577835UL; break;
  case 71: sink ^= 188465013596UL; break;
  case 72: sink ^= 191119449357UL; break;
  case 73: sink ^= 193773885118UL; break;
  case 74: sink ^= 196428320879UL; break;
  case 75: sink ^= 199082756640UL; break;
  case 76: sink ^= 201737192401UL; break;
  case 77: sink ^= 204391628162UL; break;
  case 78: sink ^= 207046063923UL; break;
  case 79: sink ^= 209700499684UL; break;
  case 80: sink ^= 212354935445UL; break;
  case 81: sink ^= 215009371206UL; break;
  case 82: sink ^= 217663806967UL; break;
  case 83: sink ^= 220318242728UL; break;
  case 84: sink ^= 222972678489UL; break;
  case 85: sink ^= 225627114250UL; break;
  case 86: sink ^= 228281550011UL; break;
  case 87: sink ^= 230935985772UL; break;
  case 88: sink ^= 233590421533UL; break;
  case 89: sink ^= 236244857294UL; break;
  case 90: sink ^= 238899293055UL; break;
  case 91: sink ^= 241553728816UL; break;
  case 92: sink ^= 244208164577UL; break;
  case 93: sink ^= 246862600338UL; break;
  case 94: sink ^= 249517036099UL; break;
  case 95: sink ^= 252171471860UL; break;
  case 96: sink ^= 254825907621UL; break;
  case 97: sink ^= 257480343382UL; break;
  case 98: sink ^= 260134779143UL; break;
  case 99: sink ^= 262789214904UL; break;
  case 100: sink ^= 265443650665UL; break;
  case 101: sink ^= 268098086426UL; break;
  case 102: sink ^= 270752522187UL; break;
  case 103: sink ^= 273406957948UL; break;
  case 104: sink ^= 276061393709UL; break;
  case 105: sink ^= 278715829470UL; break;
  case 106: sink ^= 281370265231UL; break;
  case 107: sink ^= 284024700992UL; break;
  case 108: sink ^= 286679136753UL; break;
  case 109: sink ^= 289333572514UL; break;
  case 110: sink ^= 291988008275UL; break;
  case 111: sink ^= 294642444036UL; break;
  case 112: sink ^= 297296879797UL; break;
  case 113: sink ^= 299951315558UL; break;
  case 114: sink ^= 302605751319UL; break;
  case 115: sink ^= 305260187080UL; break;
  case 116: sink ^= 307914622841UL; break;
  case 117: sink ^= 310569058602UL; break;
  case 118: sink ^= 313223494363UL; break;
  case 119: sink ^= 315877930124UL; break;
  case 120: sink ^= 318532365885UL; break;
  case 121: sink ^= 321186801646UL; break;
  case 122: sink ^= 323841237407UL; break;
  case 123: sink ^= 326495673168UL; break;
  case 124: sink ^= 329150108929UL; break;
  case 125: sink ^= 331804544690UL; break;
  case 126: sink ^= 334458980451UL; break;
  case 127: sink ^= 337113416212UL; break;
  case 128: sink ^= 339767851973UL; break;
  case 129: sink ^= 342422287734UL; break;
  case 130: sink ^= 345076723495UL; break;
  case 131: sink ^= 347731159256UL; break;
  case 132: sink ^= 350385595017UL; break;
  case 133: sink ^= 353040030778UL; break;
  case 134: sink ^= 355694466539UL; break;
  case 135: sink ^= 358348902300UL; break;
  case 136: sink ^= 361003338061UL; break;
  case 137: sink ^= 363657773822UL; break;
  case 138: sink ^= 366312209583UL; break;
  case 139: sink ^= 368966645344UL; break;
  case 140: sink ^= 371621081105UL; break;
  case 141: sink ^= 374275516866UL; break;
  case 142: sink ^= 376929952627UL; break;
  case 143: sink ^= 379584388388UL; break;
  case 144: sink ^= 382238824149UL; break;
  case 145: sink ^= 384893259910UL; break;
  case 146: sink ^= 387547695671UL; break;
  case 147: sink ^= 390202131432UL; break;
  case 148: sink ^= 392856567193UL; break;
  case 149: sink ^= 395511002954UL; break;
  case 150: sink ^= 398165438715UL; break;
  case 151: sink ^= 400819874476UL; break;
  case 152: sink ^= 403474310237UL; break;
  case 153: sink ^= 406128745998UL; break;
  case 154: sink ^= 408783181759UL; break;
  case 155: sink ^= 411437617520UL; break;
  case 156: sink ^= 414092053281UL; break;
  case 157: sink ^= 416746489042UL; break;
  case 158: sink ^= 419400924803UL; break;
  case 159: sink ^= 422055360564UL; break;
  case 160: sink ^= 424709796325UL; break;
  case 161: sink ^= 427364232086UL; break;
  case 162: sink ^= 430018667847UL; break;
  case 163: sink ^= 432673103608UL; break;
  case 164: sink ^= 435327539369UL; break;
  case 165: sink ^= 437981975130UL; break;
  case 166: sink ^= 440636410891UL; break;
  case 167: sink ^= 443290846652UL; break;
  case 168: sink ^= 445945282413UL; break;
  case 169: sink ^= 448599718174UL; break;
  case 170: sink ^= 451254153935UL; break;
  case 171: sink ^= 453908589696UL; break;
  case 172: sink ^= 456563025457UL; break;
  case 173: sink ^= 459217461218UL; break;
  case 174: sink ^= 461871896979UL; break;
  case 175: sink ^= 464526332740UL; break;
  case 176: sink ^= 467180768501UL; break;
  case 177: sink ^= 469835204262UL; break;
  case 178: sink ^= 472489640023UL; break;
  case 179: sink ^= 475144075784UL; break;
  case 180: sink ^= 477798511545UL; break;
  case 181: sink ^= 480452947306UL; break;
  case 182: sink ^= 483107383067UL; break;
  case 183: sink ^= 485761818828UL; break;
  case 184: sink ^= 488416254589UL; break;
  case 185: sink ^= 491070690350UL; break;
  case 186: sink ^= 493725126111UL; break;
  case 187: sink ^= 496379561872UL; break;
  case 188: sink ^= 499033997633UL; break;
  case 189: sink ^= 501688433394UL; break;
  case 190: sink ^= 504342869155UL; break;
  case 191: sink ^= 506997304916UL; break;
  case 192: sink ^= 509651740677UL; break;
  case 193: sink ^= 512306176438UL; break;
  case 194: sink ^= 514960612199UL; break;
  case 195: sink ^= 517615047960UL; break;
  case 196: sink ^= 520269483721UL; break;
  case 197: sink ^= 522923919482UL; break;
  case 198: sink ^= 525578355243UL; break;
  case 199: sink ^= 528232791004UL; break;
  case 200: sink ^= 530887226765UL; break;
  case 201: sink ^= 533541662526UL; break;
  case 202: sink ^= 536196098287UL; break;
  case 203: sink ^= 538850534048UL; break;
  case 204: sink ^= 541504969809UL; break;
  case 205: sink ^= 544159405570UL; break;
  case 206: sink ^= 546813841331UL; break;
  case 207: sink ^= 549468277092UL; break;
  case 208: sink ^= 552122712853UL; break;
  case 209: sink ^= 554777148614UL; break;
  case 210: sink ^= 557431584375UL; break;
  case 211: sink ^= 560086020136UL; break;
  case 212: sink ^= 562740455897UL; break;
  case 213: sink ^= 565394891658UL; break;
  case 214: sink ^= 568049327419UL; break;
  case 215: sink ^= 570703763180UL; break;
  case 216: sink ^= 573358198941UL; break;
  case 217: sink ^= 576012634702UL; break;
  case 218: sink ^= 578667070463UL; break;
  case 219: sink ^= 581321506224UL; break;
  case 220: sink ^= 583975941985UL; break;
  case 221: sink ^= 586630377746UL; break;
  case 222: sink ^= 589284813507UL; break;
  case 223: sink ^= 591939249268UL; break;
  case 224: sink ^= 594593685029UL; break;
  case 225: sink ^= 597248120790UL; break;
  case 226: sink ^= 599902556551UL; break;
  case 227: sink ^= 602556992312UL; break;
  case 228: sink ^= 605211428073UL; break;
  case 229: sink ^= 607865863834UL; break;
  case 230: sink ^= 610520299595UL; break;
  case 231: sink ^= 613174735356UL; break;
  case 232: sink ^= 615829171117UL; break;
  case 233: sink ^= 618483606878UL; break;
  case 234: sink ^= 621138042639UL; break;
  case 235: sink ^= 623792478400UL; break;
  case 236: sink ^= 626446914161UL; break;
  case 237: sink ^= 629101349922UL; break;
  case 238: sink ^= 631755785683UL; break;
  case 239: sink ^= 634410221444UL; break;
  case 240: sink ^= 637064657205UL; break;
  case 241: sink ^= 639719092966UL; break;
  case 242: sink ^= 642373528727UL; break;
  case 243: sink ^= 645027964488UL; break;
  case 244: sink ^= 647682400249UL; break;
  case 245: sink ^= 650336836010UL; break;
  case 246: sink ^= 652991271771UL; break;
  case 247: sink ^= 655645707532UL; break;
  case 248: sink ^= 658300143293UL; break;
  case 249: sink ^= 660954579054UL; break;
  case 250: sink ^= 663609014815UL; break;
  case 251: sink ^= 666263450576UL; break;
  case 252: sink ^= 668917886337UL; break;
  case 253: sink ^= 671572322098UL; break;
  case 254: sink ^= 674226757859UL; break;
  case 255: sink ^= 676881193620UL; break;
  /* GENERATED-CASES-END */
  default:
    sink ^= i;
  }
}

int main(void) {
  struct rlimit rl = {0, 0};
  setrlimit(RLIMIT_CORE, &rl);

  puts("PASS: setup (no core files)");

  for (unsigned i = 0; i < LEVELS; ++i) {
    churn(i);

    pid_t pid = fork();
    if (pid == 0) {
      /* CHILD: continue the chain. The next case is a block this process has never compiled,
         so its first execution after the fork is a fresh lookup. */
      continue;
    }
    if (pid < 0) {
      fprintf(stderr, "FAIL: fork at level %u\n", i);
      return 1;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      fprintf(stderr, "FAIL: child at level %u did not exit cleanly\n", i);
      return 1;
    }
    /* PARENT: its job at this level is done; the child carries the chain forward. */
    break;
  }

  puts("PASS: every fork level completed and was reaped");
  puts("RESULT: PASS");
  puts("completed");
  return 0;
}
