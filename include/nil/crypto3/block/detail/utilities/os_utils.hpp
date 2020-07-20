#ifndef CRYPTO3_OS_UTILS_HPP
#define CRYPTO3_OS_UTILS_HPP

#include <nil/crypto3/utilities/memory_operations.hpp>
#include <nil/crypto3/utilities/exceptions.hpp>
#include <nil/crypto3/utilities/cpuid/cpuid.hpp>
#include <nil/crypto3/utilities/types.hpp>

#include <functional>

#if defined(CRYPTO3_TARGET_OS_HAS_EXPLICIT_BZERO)
#include <string.h>
#endif

#if defined(CRYPTO3_TARGET_OS_HAS_POSIX1)

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <csignal>
#include <csetjmp>
#include <unistd.h>
#include <cerrno>

#elif defined(CRYPTO3_TARGET_OS_HAS_WIN32)
#define NOMINMAX 1
#include <windows.h>
#endif

namespace nil {
    namespace crypto3 {
#if defined(CRYPTO3_TARGET_OS_HAS_POSIX1)
        namespace detail {

            static ::sigjmp_buf sigill_jmp_buf;

            void sigill_handler(int) {
                siglongjmp(sigill_jmp_buf, /*non-zero return value*/ 1);
            }

        }    // namespace detail
#endif

        /*
         * This header is internal (not installed) and these functions are not
         * intended to be called by applications. However they are given public
         * visibility (using CRYPTO3_TEST_API macro) for the tests. This also probably
         * allows them to be overridden by the application on ELF systems, but
         * this hasn't been tested.
         */

        /**
         * @return process ID assigned by the operating system.
         * On Unix and Windows systems, this always returns a result
         * On IncludeOS it returns 0 since there is no process ID to speak of
         * in a unikernel.
         */
        uint32_t CRYPTO3_TEST_API get_process_id() {
#if defined(CRYPTO3_TARGET_OS_HAS_POSIX1)
            return ::getpid();
#elif defined(CRYPTO3_TARGET_OS_HAS_WIN32)
            return ::GetCurrentProcessId();
#elif defined(CRYPTO3_TARGET_OS_IS_INCLUDEOS) || defined(CRYPTO3_TARGET_OS_IS_LLVM)
            return 0;    // truly no meaningful value
#else
#error "Missing get_process_id"
#endif
        }

        /**
         * @return CPU processor clock, if available
         *
         * On Windows, calls QueryPerformanceCounter.
         *
         * Under GCC or Clang on supported platforms the hardware cycle counter is queried.
         * Currently supported processors are x86, PPC, Alpha, SPARC, IA-64, S/390x, and HP-PA.
         * If no CPU cycle counter is available on this system, returns zero.
         */
        uint64_t CRYPTO3_TEST_API get_processor_timestamp() {
            uint64_t rtc = 0;

#if defined(CRYPTO3_TARGET_OS_HAS_WIN32)
            LARGE_INTEGER tv;
            ::QueryPerformanceCounter(&tv);
            rtc = tv.QuadPart;

#elif defined(CRYPTO3_USE_GCC_INLINE_ASM)

#if defined(CRYPTO3_TARGET_CPU_IS_X86_FAMILY)

            if (cpuid::has_rdtsc()) {
                uint32_t rtc_low = 0, rtc_high = 0;
                asm volatile("rdtsc" : "=d"(rtc_high), "=a"(rtc_low));
                rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;
            }

#elif defined(CRYPTO3_TARGET_ARCHITECTURE_IS_PPC64)

            for (;;) {
                uint32_t rtc_low = 0, rtc_high = 0, rtc_high2 = 0;
                asm volatile("mftbu %0" : "=r"(rtc_high));
                asm volatile("mftb %0" : "=r"(rtc_low));
                asm volatile("mftbu %0" : "=r"(rtc_high2));

                if (rtc_high == rtc_high2) {
                    rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;
                    break;
                }
            }

#elif defined(CRYPTO3_TARGET_ARCHITECTURE_IS_ALPHA)
            asm volatile("rpcc %0" : "=r"(rtc));

            // OpenBSD does not trap access to the %tick register
#elif defined(CRYPTO3_TARGET_ARCHITECTURE_IS_SPARC64) && !defined(CRYPTO3_TARGET_OS_IS_OPENBSD)
            asm volatile("rd %%tick, %0" : "=r"(rtc));

#elif defined(CRYPTO3_TARGET_ARCHITECTURE_IS_IA64)
            asm volatile("mov %0=ar.itc" : "=r"(rtc));

#elif defined(CRYPTO3_TARGET_ARCHITECTURE_IS_S390X)
            asm volatile("stck 0(%0)" : : "a"(&rtc) : "memory", "cc");

#elif defined(CRYPTO3_TARGET_ARCHITECTURE_IS_HPPA)
            asm volatile("mfctl 16,%0" : "=r"(rtc));    // 64-bit only?

#else
            //#warning "get_processor_timestamp not implemented"
#endif

#endif

            return rtc;
        }

        /**
         * @return best resolution timestamp available
         *
         * The epoch and update rate of this clock is arbitrary and depending
         * on the hardware it may not tick at a constant rate.
         *
         * Uses hardware cycle counter, if available.
         * On POSIX platforms clock_gettime is used with a monotonic timer
         * As a final fallback std::chrono::high_resolution_clock is used.
         */
        uint64_t CRYPTO3_TEST_API get_high_resolution_clock() {
            if (uint64_t cpu_clock = get_processor_timestamp()) {
                return cpu_clock;
            }

            /*
            If we got here either we either don't have an asm instruction
            above, or (for x86) RDTSC is not available at runtime. Try some
            clock_gettimes and return the first one that works, or otherwise
            fall back to std::chrono.
            */

#if defined(BOOST_HAS_CLOCK_GETTIME)

            // The ordering here is somewhat arbitrary...
            const clockid_t clock_types[] = {
#if defined(CLOCK_MONOTONIC_HR)
                CLOCK_MONOTONIC_HR,
#endif
#if defined(CLOCK_MONOTONIC_RAW)
                CLOCK_MONOTONIC_RAW,
#endif
#if defined(CLOCK_MONOTONIC)
                CLOCK_MONOTONIC,
#endif
#if defined(CLOCK_PROCESS_CPUTIME_ID)
                CLOCK_PROCESS_CPUTIME_ID,
#endif
#if defined(CLOCK_THREAD_CPUTIME_ID)
                CLOCK_THREAD_CPUTIME_ID,
#endif
            };

            for (clockid_t clock : clock_types) {
                struct timespec ts;
                if (::clock_gettime(clock, &ts) == 0) {
                    return (static_cast<uint64_t>(ts.tv_sec) * 1000000000) + static_cast<uint64_t>(ts.tv_nsec);
                }
            }
#endif

            // Plain C++11 fallback
            auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
            return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
        }

        /**
         * @return system clock (reflecting wall clock) with best resolution
         * available, normalized to nanoseconds resolution.
         */
        uint64_t get_system_timestamp_ns() {
#if defined(BOOST_HAS_CLOCK_GETTIME)
            struct timespec ts;
            if (::clock_gettime(CLOCK_REALTIME, &ts) == 0) {
                return (static_cast<uint64_t>(ts.tv_sec) * 1000000000) + static_cast<uint64_t>(ts.tv_nsec);
            }
#endif

            auto now = std::chrono::system_clock::now().time_since_epoch();
            return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
        }

        /**
         * @return maximum amount of memory (in bytes) could/should be
         * hyptothetically allocated for the memory pool. Reads environment
         * variable "CRYPTO3_MLOCK_POOL_SIZE", set to "0" to disable pool.
         */
        size_t get_memory_locking_limit() {
#if defined(CRYPTO3_TARGET_OS_HAS_POSIX1)
            /*
             * Linux defaults to only 64 KiB of mlockable memory per process
             * (too small) but BSDs offer a small fraction of total RAM (more
             * than we need). Bound the total mlock size to 512 KiB which is
             * enough to run the entire test suite without spilling to non-mlock
             * memory (and thus presumably also enough for many useful
             * programs), but small enough that we should not cause problems
             * even if many processes are mlocking on the same machine.
             */
            size_t mlock_requested = CRYPTO3_MLOCK_ALLOCATOR_MAX_LOCKED_KB;

            /*
             * Allow override via env variable
             */
            if (const char *env = std::getenv("CRYPTO3_MLOCK_POOL_SIZE")) {
                try {
                    const size_t user_req = std::stoul(env, nullptr);
                    mlock_requested = std::min(user_req, mlock_requested);
                } catch (std::exception &) { /* ignore it */
                }
            }

#if defined(RLIMIT_MEMLOCK)
            if (mlock_requested > 0) {
                struct ::rlimit limits;

                ::getrlimit(RLIMIT_MEMLOCK, &limits);

                if (limits.rlim_cur < limits.rlim_max) {
                    limits.rlim_cur = limits.rlim_max;
                    ::setrlimit(RLIMIT_MEMLOCK, &limits);
                    ::getrlimit(RLIMIT_MEMLOCK, &limits);
                }

                return std::min<size_t>(limits.rlim_cur, mlock_requested * 1024);
            }
#else
            /*
             * If RLIMIT_MEMLOCK is not defined, likely the OS does not support
             * unprivileged mlock calls.
             */
            return 0;
#endif

#elif defined(CRYPTO3_TARGET_OS_HAS_VIRTUAL_LOCK)
            SIZE_T working_min = 0, working_max = 0;
            if (!::GetProcessWorkingSetSize(::GetCurrentProcess(), &working_min, &working_max)) {
                return 0;
            }

            // According to Microsoft MSDN:
            // The maximum number of pages that a process can lock is equal to the number of pages in its minimum
            // working set minus a small overhead In the book "Windows Internals Part 2": the maximum lockable pages
            // are minimum working set size - 8 pages But the information in the book seems to be
            // inaccurate/outdated I've tested this on Windows 8.1 x64, Windows 10 x64 and Windows 7 x86 On all
            // three OS the value is 11 instead of 8
            size_t overhead = system_page_size() * 11ULL;
            if (working_min > overhead) {
                size_t lockable_bytes = working_min - overhead;
                if (lockable_bytes < (CRYPTO3_MLOCK_ALLOCATOR_MAX_LOCKED_KB * 1024ULL)) {
                    return lockable_bytes;
                } else {
                    return CRYPTO3_MLOCK_ALLOCATOR_MAX_LOCKED_KB * 1024ULL;
                }
            }
#endif

            return 0;
        }

        /**
         * Return the size of a memory page, if that can be derived on the
         * current system. Otherwise returns some default value (eg 4096)
         */
        size_t system_page_size() {
#if defined(CRYPTO3_TARGET_OS_HAS_POSIX1)
            long p = ::sysconf(_SC_PAGESIZE);
            if (p > 1) {
                return static_cast<size_t>(p);
            } else {
                return 4096;
            }
#elif defined(CRYPTO3_TARGET_OS_HAS_VIRTUAL_LOCK)
            SYSTEM_INFO sys_info;
            ::GetSystemInfo(&sys_info);
            return sys_info.dwPageSize;
#endif

            // default value
            return 4096;
        }

        /**
         * Request so many bytes of page-aligned RAM locked into memory using
         * mlock, VirtualLock, or similar. Returns null on failure. The memory
         * returned is zeroed. Free it with free_locked_pages.
         * @param length requested allocation in bytes
         */
        void *allocate_locked_pages(size_t length) {
#if defined(CRYPTO3_TARGET_OS_HAS_POSIX1)

#if !defined(MAP_NOCORE)
#define MAP_NOCORE 0
#endif

#if !defined(MAP_ANONYMOUS)
#define MAP_ANONYMOUS MAP_ANON
#endif

            void *ptr = ::mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED | MAP_NOCORE,
                               /*fd*/ -1,
                               /*offset*/ 0);

            if (ptr == MAP_FAILED) {
                return nullptr;
            }

#if defined(MADV_DONTDUMP)
            ::madvise(ptr, length, MADV_DONTDUMP);
#endif

#if defined(CRYPTO3_TARGET_OS_HAS_POSIX_MLOCK)
            if (::mlock(ptr, length) != 0) {
                ::munmap(ptr, length);
                return nullptr;    // failed to lock
            }
#endif

            ::memset(ptr, 0, length);

            return ptr;
#elif defined(CRYPTO3_TARGET_OS_HAS_VIRTUAL_LOCK)
            LPVOID ptr = ::VirtualAlloc(nullptr, length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (!ptr) {
                return nullptr;
            }

            if (::VirtualLock(ptr, length) == 0) {
                ::VirtualFree(ptr, 0, MEM_RELEASE);
                return nullptr;    // failed to lock
            }

            return ptr;
#else
            CRYPTO3_UNUSED(length);
            return nullptr; /* not implemented */
#endif
        }

        /**
         * Free memory allocated by allocate_locked_pages
         * @param ptr a pointer returned by allocate_locked_pages
         * @param length length passed to allocate_locked_pages
         */
        void free_locked_pages(void *ptr, size_t length) {
            if (ptr == nullptr || length == 0) {
                return;
            }

#if defined(CRYPTO3_TARGET_OS_HAS_POSIX1)
            secure_scrub_memory(ptr, length);

#if defined(CRYPTO3_TARGET_OS_HAS_POSIX_MLOCK)
            ::munlock(ptr, length);
#endif

            ::munmap(ptr, length);
#elif defined(CRYPTO3_TARGET_OS_HAS_VIRTUAL_LOCK)
            secure_scrub_memory(ptr, length);
            ::VirtualUnlock(ptr, length);
            ::VirtualFree(ptr, 0, MEM_RELEASE);
#else
            // Invalid argument because no way this pointer was allocated by us
            throw std::invalid_argument("Invalid ptr to free_locked_pages");
#endif
        }

        /**
         * Run a probe instruction to test for support for a CPU instruction.
         * Runs in system-specific env that catches illegal instructions; this
         * function always fails if the OS doesn't provide this.
         * Returns value of probe_fn, if it could run.
         * If error occurs, returns negative number.
         * This allows probe_fn to indicate errors of its own, if it wants.
         * For example the instruction might not only be only available on some
         * CPUs, but also buggy on some subset of these - the probe function
         * can test to make sure the instruction works properly before
         * indicating that the instruction is available.
         *
         * @warning on Unix systems uses signal handling in a way that is not
         * thread safe. It should only be called in a single-threaded context
         * (ie, at static init time).
         *
         * If probe_fn throws an exception the result is undefined.
         *
         * Return codes:
         * -1 illegal instruction detected
         */
        int CRYPTO3_TEST_API run_cpu_instruction_probe(std::function<int()> probe_fn) {
            volatile int probe_result = -3;

#if defined(CRYPTO3_TARGET_OS_HAS_POSIX1)
            struct sigaction old_sigaction;
            struct sigaction sigaction;

            sigaction.sa_handler = detail::sigill_handler;
            sigemptyset(&sigaction.sa_mask);
            sigaction.sa_flags = 0;

            int rc = ::sigaction(SIGILL, &sigaction, &old_sigaction);

            if (rc != 0) {
                throw Exception("run_cpu_instruction_probe sigaction failed");
            }

            rc = sigsetjmp(detail::sigill_jmp_buf, /*save sigs*/ 1);

            if (rc == 0) {
                // first call to sigsetjmp
                probe_result = probe_fn();
            } else if (rc == 1) {
                // non-local return from siglongjmp in signal handler: return error
                probe_result = -1;
            }

            // Restore old SIGILL handler, if any
            rc = ::sigaction(SIGILL, &old_sigaction, nullptr);
            if (rc != 0) {
                throw Exception("run_cpu_instruction_probe sigaction restore failed");
            }

#elif defined(CRYPTO3_TARGET_OS_IS_WINDOWS) && defined(CRYPTO3_TARGET_COMPILER_IS_MSVC)

            // Windows SEH
            __try {
                probe_result = probe_fn();
            } __except (::GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION ? EXCEPTION_EXECUTE_HANDLER :
                                                                                EXCEPTION_CONTINUE_SEARCH) {
                probe_result = -1;
            }

#endif

            return probe_result;
        }

    }    // namespace crypto3
}    // namespace nil

#endif
