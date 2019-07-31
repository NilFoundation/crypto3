#ifndef CRYPTO3_BIT_OPS_HPP
#define CRYPTO3_BIT_OPS_HPP

#include <nil/crypto3/utilities/types.hpp>
#include <nil/crypto3/utilities/loadstore.hpp>

namespace nil {
    namespace crypto3 {

        /**
         * Return the index of the highest set bit
         * T is an unsigned integer type
         * @param n an integer value
         * @return index of the highest set bit in n
         */
        template<typename T>
        inline size_t high_bit(T n) {
            for (size_t i = 8 * sizeof(T); i > 0; --i) {
                if ((n >> (i - 1)) & 0x01) {
                    return i;
                }
            }
            return 0;
        }

        /**
         * Return the index of the lowest set bit
         * T is an unsigned integer type
         * @param n an integer value
         * @return index of the lowest set bit in n
         */
        template<typename T>
        inline size_t low_bit(T n) {
            for (size_t i = 0; i != 8 * sizeof(T); ++i) {
                if ((n >> i) & 0x01) {
                    return (i + 1);
                }
            }
            return 0;
        }

        /**
         * Return the number of significant bytes in n
         * @param n an integer value
         * @return number of significant bytes in n
         */
        template<typename T>
        inline size_t significant_bytes(T n) {
            for (size_t i = 0; i != sizeof(T); ++i) {
                if (extract_uint_t<CHAR_BIT>(n, i)) {
                    return sizeof(T) - i;
                }
            }
            return 0;
        }

        /**
         * Compute Hamming weights
         * @param n an integer value
         * @return number of bits in n set to 1
         */
        template<typename T>
        inline size_t hamming_weight(T n) {
            const uint8_t NIBBLE_WEIGHTS[] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};

            size_t weight = 0;
            for (size_t i = 0; i != 2 * sizeof(T); ++i) {
                weight += NIBBLE_WEIGHTS[(n >> (4 * i)) & 0x0F];
            }
            return weight;
        }

        /**
         * Count the trailing zero bits in n
         * @param n an integer value
         * @return maximum x st 2^x divides n
         */
        template<typename T>
        inline size_t ctz(T n) {
            for (size_t i = 0; i != 8 * sizeof(T); ++i) {
                if ((n >> i) & 0x01) {
                    return i;
                }
            }
            return 8 * sizeof(T);
        }

#if defined(CRYPTO3_BUILD_COMPILER_IS_GCC) || defined(CRYPTO3_BUILD_COMPILER_IS_CLANG)

        template<>
        inline size_t ctz(uint32_t n) {
            return __builtin_ctz(n);
        }

#endif

        template<typename T>
        size_t ceil_log2(T x) {
            if (x >> (sizeof(T) * 8 - 1)) {
                return sizeof(T) * 8;
            }

            size_t result = 0;
            T compare = 1;

            while (compare < x) {
                compare <<= 1;
                result++;
            }

            return result;
        }
    }    // namespace crypto3
}    // namespace nil

#endif
