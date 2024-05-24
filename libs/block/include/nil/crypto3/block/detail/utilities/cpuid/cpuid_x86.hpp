#include <nil/crypto3/utilities/cpuid/cpuid.hpp>
#include <nil/crypto3/utilities/memory_operations.hpp>
#include <nil/crypto3/utilities/loadstore.hpp>

#if defined(BOOST_ARCH_X86)

#if defined(CRYPTO3_BUILD_COMPILER_IS_MSVC)
#include <intrin.h>
#elif defined(CRYPTO3_BUILD_COMPILER_IS_INTEL)
#include <ia32intrin.h>
#elif defined(CRYPTO3_BUILD_COMPILER_IS_GCC) || defined(CRYPTO3_BUILD_COMPILER_IS_CLANG)
#include <cpuid.h>
#endif

#endif

namespace nil {
    namespace crypto3 {

#if defined(BOOST_ARCH_X86)

        uint64_t cpuid::detect_cpu_features(size_t *cache_line_size) {
#if defined(CRYPTO3_BUILD_COMPILER_IS_MSVC)
#define X86_CPUID(type, out)       \
    do {                           \
        __cpuid((int *)out, type); \
    } while (0)
#define X86_CPUID_SUBLEVEL(type, level, out) \
    do {                                     \
        __cpuidex((int *)out, type, level);  \
    } while (0)

#elif defined(CRYPTO3_BUILD_COMPILER_IS_INTEL)
#define X86_CPUID(type, out) \
    do {                     \
        __cpuid(out, type);  \
    } while (0)
#define X86_CPUID_SUBLEVEL(type, level, out) \
    do {                                     \
        __cpuidex((int *)out, type, level);  \
    } while (0)

#elif defined(CRYPTO3_TARGET_ARCHITECTURE_IS_X86_64) && defined(CRYPTO3_USE_GCC_INLINE_ASM)
#define X86_CPUID(type, out) asm("cpuid\n\t" : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3]) : "0"(type))

#define X86_CPUID_SUBLEVEL(type, level, out) \
    asm("cpuid\n\t" : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3]) : "0"(type), "2"(level))

#elif defined(CRYPTO3_BUILD_COMPILER_IS_GCC) || defined(CRYPTO3_BUILD_COMPILER_IS_CLANG)
#define X86_CPUID(type, out)                               \
    do {                                                   \
        __get_cpuid(type, out, out + 1, out + 2, out + 3); \
    } while (0)

#define X86_CPUID_SUBLEVEL(type, level, out)                        \
    do {                                                            \
        __cpuid_count(type, level, out[0], out[1], out[2], out[3]); \
    } while (0)
#else
#warning "No way of calling x86 cpuid instruction for this compiler"
#define X86_CPUID(type, out) \
    do {                     \
        clear_mem(out, 4);   \
    } while (0)
#define X86_CPUID_SUBLEVEL(type, level, out) \
    do {                                     \
        clear_mem(out, 4);                   \
    } while (0)
#endif

            uint64_t features_detected = 0;
            uint32_t cpuid[4] = {0};

            // cpuid 0: vendor identification, max sublevel
            X86_CPUID(0, cpuid);

            const uint32_t max_supported_sublevel = cpuid[0];

            const uint32_t INTEL_CPUID[3] = {0x756E6547, 0x6C65746E, 0x49656E69};
            const uint32_t AMD_CPUID[3] = {0x68747541, 0x444D4163, 0x69746E65};
            const bool is_intel = same_mem(cpuid + 1, INTEL_CPUID, 3);
            const bool is_amd = same_mem(cpuid + 1, AMD_CPUID, 3);

            if (max_supported_sublevel >= 1) {
                // cpuid 1: feature bits
                X86_CPUID(1, cpuid);
                const uint64_t flags0 = (static_cast<uint64_t>(cpuid[2]) << 32) | cpuid[3];

                enum x86_CPUID_1_bits : uint64_t {
                    RDTSC = (1ULL << 4),
                    SSE2 = (1ULL << 26),
                    CLMUL = (1ULL << 33),
                    SSSE3 = (1ULL << 41),
                    SSE41 = (1ULL << 51),
                    SSE42 = (1ULL << 52),
                    AESNI = (1ULL << 57),
                    RDRAND = (1ULL << 62)
                };

                if (flags0 & x86_CPUID_1_bits::RDTSC)
                    features_detected |= cpuid::CPUID_RDTSC_BIT;
                if (flags0 & x86_CPUID_1_bits::SSE2)
                    features_detected |= cpuid::CPUID_SSE2_BIT;
                if (flags0 & x86_CPUID_1_bits::CLMUL)
                    features_detected |= cpuid::CPUID_CLMUL_BIT;
                if (flags0 & x86_CPUID_1_bits::SSSE3)
                    features_detected |= cpuid::CPUID_SSSE3_BIT;
                if (flags0 & x86_CPUID_1_bits::SSE41)
                    features_detected |= cpuid::CPUID_SSE41_BIT;
                if (flags0 & x86_CPUID_1_bits::SSE42)
                    features_detected |= cpuid::CPUID_SSE42_BIT;
                if (flags0 & x86_CPUID_1_bits::AESNI)
                    features_detected |= cpuid::CPUID_AESNI_BIT;
                if (flags0 & x86_CPUID_1_bits::RDRAND)
                    features_detected |= cpuid::CPUID_RDRAND_BIT;
            }

            if (is_intel) {
                // Intel cache line size is in cpuid(1) output
                *cache_line_size = 8 * extract_uint_t<CHAR_BIT>(cpuid[1], 2);
            } else if (is_amd) {
                // AMD puts it in vendor zone
                X86_CPUID(0x80000005, cpuid);
                *cache_line_size = extract_uint_t<CHAR_BIT>(cpuid[2], 3);
            }

            if (max_supported_sublevel >= 7) {
                clear_mem(cpuid, 4);
                X86_CPUID_SUBLEVEL(7, 0, cpuid);

                enum x86_CPUID_7_bits : uint64_t {
                    AVX2 = (1ULL << 5),
                    BMI2 = (1ULL << 8),
                    AVX512F = (1ULL << 16),
                    RDSEED = (1ULL << 18),
                    ADX = (1ULL << 19),
                    SHA = (1ULL << 29),
                };
                uint64_t flags7 = (static_cast<uint64_t>(cpuid[2]) << 32) | cpuid[1];

                if (flags7 & x86_CPUID_7_bits::AVX2)
                    features_detected |= cpuid::CPUID_AVX2_BIT;
                if (flags7 & x86_CPUID_7_bits::BMI2)
                    features_detected |= cpuid::CPUID_BMI2_BIT;
                if (flags7 & x86_CPUID_7_bits::AVX512F)
                    features_detected |= cpuid::CPUID_AVX512F_BIT;
                if (flags7 & x86_CPUID_7_bits::RDSEED)
                    features_detected |= cpuid::CPUID_RDSEED_BIT;
                if (flags7 & x86_CPUID_7_bits::ADX)
                    features_detected |= cpuid::CPUID_ADX_BIT;
                if (flags7 & x86_CPUID_7_bits::SHA)
                    features_detected |= cpuid::CPUID_SHA_BIT;
            }

#undef X86_CPUID
#undef X86_CPUID_SUBLEVEL

            /*
             * If we don't have access to cpuid, we can still safely assume that
             * any x86-64 processor has SSE2 and RDTSC
             */
#if defined(CRYPTO3_TARGET_ARCHITECTURE_IS_X86_64)
            if (features_detected == 0) {
                features_detected |= cpuid::CPUID_SSE2_BIT;
                features_detected |= cpuid::CPUID_RDTSC_BIT;
            }
#endif

            return features_detected;
        }

#endif
    }    // namespace crypto3
}    // namespace nil
