#ifndef CRYPTO3_LOAD_STORE_HPP
#define CRYPTO3_LOAD_STORE_HPP

#include <boost/assert.hpp>
#include <boost/integer.hpp>
#include <boost/endian/arithmetic.hpp>

#include <nil/crypto3/block/detail/utilities/memory_operations.hpp>

#if defined(CRYPTO3_TARGET_CPU_IS_BIG_ENDIAN)
#define CRYPTO3_ENDIAN_N2L(x) boost::endian::endian_reverse(x)
#define CRYPTO3_ENDIAN_L2N(x) boost::endian::endian_reverse(x)
#define CRYPTO3_ENDIAN_N2B(x) (x)
#define CRYPTO3_ENDIAN_B2N(x) (x)

#elif defined(CRYPTO3_TARGET_CPU_IS_LITTLE_ENDIAN)
#define CRYPTO3_ENDIAN_N2L(x) (x)
#define CRYPTO3_ENDIAN_L2N(x) (x)
#define CRYPTO3_ENDIAN_N2B(x) boost::endian::endian_reverse(x)
#define CRYPTO3_ENDIAN_B2N(x) boost::endian::endian_reverse(x)

#endif

namespace nil {
    namespace crypto3 {
        template<std::size_t Size, typename Integer>
        static inline typename boost::uint_t<Size>::exact extract_uint_t(Integer v, std::size_t position) {
            BOOST_ASSERT(std::numeric_limits<Integer>::digits <= position * CHAR_BIT + Size);

            return static_cast<typename boost::uint_t<Size>::exact>(v >> (((~position) & (sizeof(Integer) - 1)) << 3));
        }

        template<std::size_t Size, typename... Args>
        static inline typename boost::uint_t<Size>::exact make_uint_t(const std::initializer_list<Args...> &args) {
            typedef typename std::initializer_list<Args...>::value_type value_type;
            typename boost::uint_t<Size>::exact result = 0;

#pragma clang loop unroll(full)
            for (const value_type &itr : args) {
                result = static_cast<typename boost::uint_t<Size>::exact>(
                    (result << std::numeric_limits<value_type>::digits) | itr);
            }

            return result;
        }

        template<std::size_t Size, typename... Args>
        static inline typename boost::uint_t<Size>::exact make_uint_t(Args... args) {
            return make_uint_t<Size, typename std::tuple_element<0, std::tuple<Args...>>::type>({args...});
        }

        /**
         * Swap 4 Ts in an array
         */
        template<typename T>
        inline void bswap_4(T x[4]) {
            x[0] = boost::endian::endian_reverse(x[0]);
            x[1] = boost::endian::endian_reverse(x[1]);
            x[2] = boost::endian::endian_reverse(x[2]);
            x[3] = boost::endian::endian_reverse(x[3]);
        }

        /**
         * Load a big-endian word
         * @param in a pointer to some bytes
         * @param off an offset into the array
         * @return off'th T of in, as a big-endian value
         */
        template<typename T>
        inline T load_be(const uint8_t in[], std::size_t off = 0) {
            in += off * sizeof(T);
            T out = 0;
            for (size_t i = 0; i != sizeof(T); ++i) {
                out = static_cast<T>((out << 8) | in[i]);
            }
            return out;
        }

        /**
         * Load a little-endian word
         * @param in a pointer to some bytes
         * @param off an offset into the array
         * @return off'th T of in, as a litte-endian value
         */
        template<typename T>
        inline T load_le(const uint8_t in[], std::size_t off = 0) {
            in += off * sizeof(T);
            T out = 0;
            for (size_t i = 0; i != sizeof(T); ++i) {
                out = (out << 8) | in[sizeof(T) - 1 - i];
            }
            return out;
        }

        /**
         * Load a big-endian uint16_t
         * @param in a pointer to some bytes
         * @param off an offset into the array
         * @return off'th uint16_t of in, as a big-endian value
         */
        template<>
        inline uint16_t load_be<uint16_t>(const uint8_t in[], std::size_t off) {
            in += off * sizeof(uint16_t);

#if defined(CRYPTO3_ENDIAN_N2B)
            uint16_t x;
            std::memcpy(&x, in, sizeof(x));
            return CRYPTO3_ENDIAN_N2B(x);
#else
            return make_uint_t<16>(in[0], in[1]);
#endif
        }

        /**
         * Load a little-endian uint16_t
         * @param in a pointer to some bytes
         * @param off an offset into the array
         * @return off'th uint16_t of in, as a little-endian value
         */
        template<>
        inline uint16_t load_le<uint16_t>(const uint8_t in[], std::size_t off) {
            in += off * sizeof(uint16_t);

#if defined(CRYPTO3_ENDIAN_N2L)
            uint16_t x;
            std::memcpy(&x, in, sizeof(x));
            return CRYPTO3_ENDIAN_N2L(x);
#else
            return make_uint_t<16>(in[1], in[0]);
#endif
        }

        /**
         * Load a big-endian uint32_t
         * @param in a pointer to some bytes
         * @param off an offset into the array
         * @return off'th uint32_t of in, as a big-endian value
         */
        template<>
        inline uint32_t load_be<uint32_t>(const uint8_t in[], std::size_t off) {
            in += off * sizeof(uint32_t);
#if defined(CRYPTO3_ENDIAN_N2B)
            uint32_t x;
            std::memcpy(&x, in, sizeof(x));
            return CRYPTO3_ENDIAN_N2B(x);
#else
            return make_uint_t<32>(in[0], in[1], in[2], in[3]);
#endif
        }

        /**
         * Load a little-endian uint32_t
         * @param in a pointer to some bytes
         * @param off an offset into the array
         * @return off'th uint32_t of in, as a little-endian value
         */
        template<>
        inline uint32_t load_le<uint32_t>(const uint8_t in[], std::size_t off) {
            in += off * sizeof(uint32_t);
#if defined(CRYPTO3_ENDIAN_N2L)
            uint32_t x;
            std::memcpy(&x, in, sizeof(x));
            return CRYPTO3_ENDIAN_N2L(x);
#else
            return make_uint_t<32>(in[3], in[2], in[1], in[0]);
#endif
        }

        /**
         * Load a big-endian uint64_t
         * @param in a pointer to some bytes
         * @param off an offset into the array
         * @return off'th uint64_t of in, as a big-endian value
         */
        template<>
        inline uint64_t load_be<uint64_t>(const uint8_t in[], std::size_t off) {
            in += off * sizeof(uint64_t);
#if defined(CRYPTO3_ENDIAN_N2B)
            uint64_t x;
            std::memcpy(&x, in, sizeof(x));
            return CRYPTO3_ENDIAN_N2B(x);
#else
            return make_uint_t<64>(in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7]);
#endif
        }

        /**
         * Load a little-endian uint64_t
         * @param in a pointer to some bytes
         * @param off an offset into the array
         * @return off'th uint64_t of in, as a little-endian value
         */
        template<>
        inline uint64_t load_le<uint64_t>(const uint8_t in[], std::size_t off) {
            in += off * sizeof(uint64_t);
#if defined(CRYPTO3_ENDIAN_N2L)
            uint64_t x;
            std::memcpy(&x, in, sizeof(x));
            return CRYPTO3_ENDIAN_N2L(x);
#else
            return make_uint_t<64>(in[7], in[6], in[5], in[4], in[3], in[2], in[1], in[0]);
#endif
        }

        /**
         * Load two little-endian words
         * @param in a pointer to some bytes
         * @param x0 where the first word will be written
         * @param x1 where the second word will be written
         */
        template<typename T>
        inline void load_le(const uint8_t in[], T &x0, T &x1) {
            x0 = load_le<T>(in, 0);
            x1 = load_le<T>(in, 1);
        }

        /**
         * Load four little-endian words
         * @param in a pointer to some bytes
         * @param x0 where the first word will be written
         * @param x1 where the second word will be written
         * @param x2 where the third word will be written
         * @param x3 where the fourth word will be written
         */
        template<typename T>
        inline void load_le(const uint8_t in[], T &x0, T &x1, T &x2, T &x3) {
            x0 = load_le<T>(in, 0);
            x1 = load_le<T>(in, 1);
            x2 = load_le<T>(in, 2);
            x3 = load_le<T>(in, 3);
        }

        /**
         * Load eight little-endian words
         * @param in a pointer to some bytes
         * @param x0 where the first word will be written
         * @param x1 where the second word will be written
         * @param x2 where the third word will be written
         * @param x3 where the fourth word will be written
         * @param x4 where the fifth word will be written
         * @param x5 where the sixth word will be written
         * @param x6 where the seventh word will be written
         * @param x7 where the eighth word will be written
         */
        template<typename T>
        inline void load_le(const uint8_t in[], T &x0, T &x1, T &x2, T &x3, T &x4, T &x5, T &x6, T &x7) {
            x0 = load_le<T>(in, 0);
            x1 = load_le<T>(in, 1);
            x2 = load_le<T>(in, 2);
            x3 = load_le<T>(in, 3);
            x4 = load_le<T>(in, 4);
            x5 = load_le<T>(in, 5);
            x6 = load_le<T>(in, 6);
            x7 = load_le<T>(in, 7);
        }

        /**
         * Load a variable number of little-endian words
         * @param out the output array of words
         * @param in the input array of bytes
         * @param count how many words are in in
         */
        template<typename T>
        inline void load_le(T out[], const uint8_t in[], size_t count) {
            if (count > 0) {
#if defined(CRYPTO3_TARGET_CPU_IS_LITTLE_ENDIAN)
                std::memcpy(out, in, sizeof(T) * count);
#elif defined(CRYPTO3_TARGET_CPU_IS_BIG_ENDIAN)
                std::memcpy(out, in, sizeof(T) * count);
                const size_t blocks = count - (count % 4);
                const size_t left = count - blocks;

                for (size_t i = 0; i != blocks; i += 4)
                    bswap_4(out + i);

                for (size_t i = 0; i != left; ++i)
                    out[blocks + i] = boost::endian::endian_reverse(out[blocks + i]);
#else
                for (size_t i = 0; i != count; ++i) {
                    out[i] = load_le<T>(in, i);
                }
#endif
            }
        }

        /**
         * Load two big-endian words
         * @param in a pointer to some bytes
         * @param x0 where the first word will be written
         * @param x1 where the second word will be written
         */
        template<typename T>
        inline void load_be(const uint8_t in[], T &x0, T &x1) {
            x0 = load_be<T>(in, 0);
            x1 = load_be<T>(in, 1);
        }

        /**
         * Load four big-endian words
         * @param in a pointer to some bytes
         * @param x0 where the first word will be written
         * @param x1 where the second word will be written
         * @param x2 where the third word will be written
         * @param x3 where the fourth word will be written
         */
        template<typename T>
        inline void load_be(const uint8_t in[], T &x0, T &x1, T &x2, T &x3) {
            x0 = load_be<T>(in, 0);
            x1 = load_be<T>(in, 1);
            x2 = load_be<T>(in, 2);
            x3 = load_be<T>(in, 3);
        }

        /**
         * Load eight big-endian words
         * @param in a pointer to some bytes
         * @param x0 where the first word will be written
         * @param x1 where the second word will be written
         * @param x2 where the third word will be written
         * @param x3 where the fourth word will be written
         * @param x4 where the fifth word will be written
         * @param x5 where the sixth word will be written
         * @param x6 where the seventh word will be written
         * @param x7 where the eighth word will be written
         */
        template<typename T>
        inline void load_be(const uint8_t in[], T &x0, T &x1, T &x2, T &x3, T &x4, T &x5, T &x6, T &x7) {
            x0 = load_be<T>(in, 0);
            x1 = load_be<T>(in, 1);
            x2 = load_be<T>(in, 2);
            x3 = load_be<T>(in, 3);
            x4 = load_be<T>(in, 4);
            x5 = load_be<T>(in, 5);
            x6 = load_be<T>(in, 6);
            x7 = load_be<T>(in, 7);
        }

        /**
         * Load a variable number of big-endian words
         * @param out the output array of words
         * @param in the input array of bytes
         * @param count how many words are in in
         */
        template<typename T>
        inline void load_be(T out[], const uint8_t in[], size_t count) {
            if (count > 0) {
#if defined(CRYPTO3_TARGET_CPU_IS_BIG_ENDIAN)
                std::memcpy(out, in, sizeof(T) * count);

#elif defined(CRYPTO3_TARGET_CPU_IS_LITTLE_ENDIAN)
                std::memcpy(out, in, sizeof(T) * count);
                const size_t blocks = count - (count % 4);
                const size_t left = count - blocks;

                for (size_t i = 0; i != blocks; i += 4) {
                    bswap_4(out + i);
                }

                for (size_t i = 0; i != left; ++i) {
                    out[blocks + i] = boost::endian::endian_reverse(out[blocks + i]);
                }
#else
                for (size_t i = 0; i != count; ++i) {
                    out[i] = load_be<T>(in, i);
                }
#endif
            }
        }

        /**
         * Store a big-endian uint16_t
         * @param in the input uint16_t
         * @param out the byte array to write to
         */
        inline void store_be(uint16_t in, uint8_t out[2]) {
#if defined(CRYPTO3_ENDIAN_N2B)
            uint16_t o = CRYPTO3_ENDIAN_N2B(in);
            std::memcpy(out, &o, sizeof(o));
#else
            out[0] = extract_uint_t<CHAR_BIT>(in, 0);
            out[1] = extract_uint_t<CHAR_BIT>(in, 1);
#endif
        }

        /**
         * Store a little-endian uint16_t
         * @param in the input uint16_t
         * @param out the byte array to write to
         */
        inline void store_le(uint16_t in, uint8_t out[2]) {
#if defined(CRYPTO3_ENDIAN_N2L)
            uint16_t o = CRYPTO3_ENDIAN_N2L(in);
            std::memcpy(out, &o, sizeof(o));
#else
            out[0] = extract_uint_t<CHAR_BIT>(in, 1);
            out[1] = extract_uint_t<CHAR_BIT>(in, 0);
#endif
        }

        /**
         * Store a big-endian uint32_t
         * @param in the input uint32_t
         * @param out the byte array to write to
         */
        inline void store_be(uint32_t in, uint8_t out[4]) {
#if defined(CRYPTO3_ENDIAN_B2N)
            uint32_t o = CRYPTO3_ENDIAN_B2N(in);
            std::memcpy(out, &o, sizeof(o));
#else
            out[0] = extract_uint_t<CHAR_BIT>(in, 0);
            out[1] = extract_uint_t<CHAR_BIT>(in, 1);
            out[2] = extract_uint_t<CHAR_BIT>(in, 2);
            out[3] = extract_uint_t<CHAR_BIT>(in, 3);
#endif
        }

        /**
         * Store a little-endian uint32_t
         * @param in the input uint32_t
         * @param out the byte array to write to
         */
        inline void store_le(uint32_t in, uint8_t out[4]) {
#if defined(CRYPTO3_ENDIAN_L2N)
            uint32_t o = CRYPTO3_ENDIAN_L2N(in);
            std::memcpy(out, &o, sizeof(o));
#else
            out[0] = extract_uint_t<CHAR_BIT>(in, 3);
            out[1] = extract_uint_t<CHAR_BIT>(in, 2);
            out[2] = extract_uint_t<CHAR_BIT>(in, 1);
            out[3] = extract_uint_t<CHAR_BIT>(in, 0);
#endif
        }

        /**
         * Store a big-endian uint64_t
         * @param in the input uint64_t
         * @param out the byte array to write to
         */
        inline void store_be(uint64_t in, uint8_t out[8]) {
#if defined(CRYPTO3_ENDIAN_B2N)
            uint64_t o = CRYPTO3_ENDIAN_B2N(in);
            std::memcpy(out, &o, sizeof(o));
#else
            out[0] = extract_uint_t<CHAR_BIT>(in, 0);
            out[1] = extract_uint_t<CHAR_BIT>(in, 1);
            out[2] = extract_uint_t<CHAR_BIT>(in, 2);
            out[3] = extract_uint_t<CHAR_BIT>(in, 3);
            out[4] = extract_uint_t<CHAR_BIT>(in, 4);
            out[5] = extract_uint_t<CHAR_BIT>(in, 5);
            out[6] = extract_uint_t<CHAR_BIT>(in, 6);
            out[7] = extract_uint_t<CHAR_BIT>(in, 7);
#endif
        }

        /**
         * Store a little-endian uint64_t
         * @param in the input uint64_t
         * @param out the byte array to write to
         */
        inline void store_le(uint64_t in, uint8_t out[8]) {
#if defined(CRYPTO3_ENDIAN_L2N)
            uint64_t o = CRYPTO3_ENDIAN_L2N(in);
            std::memcpy(out, &o, sizeof(o));
#else
            out[0] = extract_uint_t<CHAR_BIT>(in, 7);
            out[1] = extract_uint_t<CHAR_BIT>(in, 6);
            out[2] = extract_uint_t<CHAR_BIT>(in, 5);
            out[3] = extract_uint_t<CHAR_BIT>(in, 4);
            out[4] = extract_uint_t<CHAR_BIT>(in, 3);
            out[5] = extract_uint_t<CHAR_BIT>(in, 2);
            out[6] = extract_uint_t<CHAR_BIT>(in, 1);
            out[7] = extract_uint_t<CHAR_BIT>(in, 0);
#endif
        }

        /**
         * Store two little-endian words
         * @param out the output byte array
         * @param x0 the first word
         * @param x1 the second word
         */
        template<typename T>
        inline void store_le(uint8_t out[], T x0, T x1) {
            store_le(x0, out + (0 * sizeof(T)));
            store_le(x1, out + (1 * sizeof(T)));
        }

        /**
         * Store two big-endian words
         * @param out the output byte array
         * @param x0 the first word
         * @param x1 the second word
         */
        template<typename T>
        inline void store_be(uint8_t out[], T x0, T x1) {
            store_be(x0, out + (0 * sizeof(T)));
            store_be(x1, out + (1 * sizeof(T)));
        }

        /**
         * Store four little-endian words
         * @param out the output byte array
         * @param x0 the first word
         * @param x1 the second word
         * @param x2 the third word
         * @param x3 the fourth word
         */
        template<typename T>
        inline void store_le(uint8_t out[], T x0, T x1, T x2, T x3) {
            store_le(x0, out + (0 * sizeof(T)));
            store_le(x1, out + (1 * sizeof(T)));
            store_le(x2, out + (2 * sizeof(T)));
            store_le(x3, out + (3 * sizeof(T)));
        }

        /**
         * Store four big-endian words
         * @param out the output byte array
         * @param x0 the first word
         * @param x1 the second word
         * @param x2 the third word
         * @param x3 the fourth word
         */
        template<typename T>
        inline void store_be(uint8_t out[], T x0, T x1, T x2, T x3) {
            store_be(x0, out + (0 * sizeof(T)));
            store_be(x1, out + (1 * sizeof(T)));
            store_be(x2, out + (2 * sizeof(T)));
            store_be(x3, out + (3 * sizeof(T)));
        }

        /**
         * Store eight little-endian words
         * @param out the output byte array
         * @param x0 the first word
         * @param x1 the second word
         * @param x2 the third word
         * @param x3 the fourth word
         * @param x4 the fifth word
         * @param x5 the sixth word
         * @param x6 the seventh word
         * @param x7 the eighth word
         */
        template<typename T>
        inline void store_le(uint8_t out[], T x0, T x1, T x2, T x3, T x4, T x5, T x6, T x7) {
            store_le(x0, out + (0 * sizeof(T)));
            store_le(x1, out + (1 * sizeof(T)));
            store_le(x2, out + (2 * sizeof(T)));
            store_le(x3, out + (3 * sizeof(T)));
            store_le(x4, out + (4 * sizeof(T)));
            store_le(x5, out + (5 * sizeof(T)));
            store_le(x6, out + (6 * sizeof(T)));
            store_le(x7, out + (7 * sizeof(T)));
        }

        /**
         * Store eight big-endian words
         * @param out the output byte array
         * @param x0 the first word
         * @param x1 the second word
         * @param x2 the third word
         * @param x3 the fourth word
         * @param x4 the fifth word
         * @param x5 the sixth word
         * @param x6 the seventh word
         * @param x7 the eighth word
         */
        template<typename T>
        inline void store_be(uint8_t out[], T x0, T x1, T x2, T x3, T x4, T x5, T x6, T x7) {
            store_be(x0, out + (0 * sizeof(T)));
            store_be(x1, out + (1 * sizeof(T)));
            store_be(x2, out + (2 * sizeof(T)));
            store_be(x3, out + (3 * sizeof(T)));
            store_be(x4, out + (4 * sizeof(T)));
            store_be(x5, out + (5 * sizeof(T)));
            store_be(x6, out + (6 * sizeof(T)));
            store_be(x7, out + (7 * sizeof(T)));
        }
    }    // namespace crypto3
}    // namespace nil

#endif