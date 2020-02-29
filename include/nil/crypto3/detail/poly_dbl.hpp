#ifndef CRYPTO3_DETAIL_POLY_DBL_HPP
#define CRYPTO3_DETAIL_POLY_DBL_HPP

#include <algorithm>

namespace nil {
    namespace crypto3 {
        namespace detail {

            /*
             * The minimum weight irreducible binary polynomial of size n
             *
             * See http://www.hpl.hp.com/techreports/98/HPL-98-135.pdf
             */
            enum class min_weight_polynomial : uint64_t {
                P64 = 0x1B,
                P128 = 0x87,
                P192 = 0x87,
                P256 = 0x425,
                P512 = 0x125,
                P1024 = 0x80043,
            };

            template<std::size_t LIMBS, min_weight_polynomial P>
            void poly_double(uint8_t out[], const uint8_t in[]) {
                uint64_t W[LIMBS];
                load_be(W, in, LIMBS);

                const uint64_t POLY = static_cast<uint64_t>(P);

                const uint64_t carry = POLY * (W[0] >> 63);
                for (std::size_t i = 0; i != LIMBS - 1; ++i) {
                    W[i] = (W[i] << 1) ^ (W[i + 1] >> 63);
                }
                W[LIMBS - 1] = (W[LIMBS - 1] << 1) ^ carry;

                copy_out_be(out, LIMBS * 8, W);
            }

            template<std::size_t LIMBS, min_weight_polynomial P, typename InputIterator>
            void poly_double_le(uint8_t out[], InputIterator first, InputIterator last) {
                uint64_t W[LIMBS];
                load_le(W, &*first, LIMBS);

                const uint64_t POLY = static_cast<uint64_t>(P);

                const uint64_t carry = POLY * (W[LIMBS - 1] >> 63);
                for (std::size_t i = 0; i != LIMBS - 1; ++i) {
                    W[LIMBS - 1 - i] = (W[LIMBS - 1 - i] << 1) ^ (W[LIMBS - 2 - i] >> 63);
                }
                W[0] = (W[0] << 1) ^ carry;

                copy_out_le(out, LIMBS * 8, W);
            }
        }    // namespace detail

        /**
         * Polynomial doubling in GF(2^n)
         */
        template<typename InputIterator>
        void poly_double_n(uint8_t out[], InputIterator first, InputIterator last) {
            switch (std::distance(first, last)) {
                case 8:
                    return detail::poly_double<1, detail::min_weight_polynomial::P64>(out, first, last);
                case 16:
                    return detail::poly_double<2, detail::min_weight_polynomial::P128>(out, first, last);
                case 24:
                    return detail::poly_double<3, detail::min_weight_polynomial::P192>(out, first, last);
                case 32:
                    return detail::poly_double<4, detail::min_weight_polynomial::P256>(out, first, last);
                case 64:
                    return detail::poly_double<8, detail::min_weight_polynomial::P512>(out, first, last);
                case 128:
                    return detail::poly_double<8, detail::min_weight_polynomial::P1024>(out, first, last);
                default:
                    throw std::invalid_argument("Unsupported size for poly_double_n");
            }
        }

        /**
         * Returns true iff poly_double_n is implemented for this size.
         */
        inline constexpr bool poly_double_supported_size(size_t n) {
            return (n == 8 || n == 16 || n == 24 || n == 32 || n == 64 || n == 128);
        }

        template<typename Container>
        inline void poly_double_n(const Container &c) {
            return poly_double_n(c, c, c.size());
        }

        /*
         * Little endian convention - used for XTS
         */
        template<typename InputIterator>
        void poly_double_n_le(uint8_t out[], InputIterator first, InputIterator last) {
            switch (std::distance(first, last)) {
                case 8:
                    return detail::poly_double_le<1, detail::min_weight_polynomial::P64>(out, first, last);
                case 16:
                    return detail::poly_double_le<2, detail::min_weight_polynomial::P128>(out, first, last);
                case 24:
                    return detail::poly_double_le<3, detail::min_weight_polynomial::P192>(out, first, last);
                case 32:
                    return detail::poly_double_le<4, detail::min_weight_polynomial::P256>(out, first, last);
                case 64:
                    return detail::poly_double_le<8, detail::min_weight_polynomial::P512>(out, first, last);
                case 128:
                    return detail::poly_double_le<8, detail::min_weight_polynomial::P1024>(out, first, last);
                default:
                    throw std::invalid_argument("Unsupported size for poly_double_n_le");
            }
        }
    }    // namespace crypto3
}    // namespace nil

#endif
