#ifndef CRYPTO3_CURVE_NIST_P192_HPP
#define CRYPTO3_CURVE_NIST_P192_HPP

#include <memory>

#include <boost/multiprecision/cpp_int.hpp>

#include <nil/crypto3/multiprecision/mask_bits.hpp>
#include <nil/crypto3/multiprecision/reduce_below.hpp>

#include <nil/crypto3/pubkey/ec_group/curve_nist.hpp>

namespace nil {
    namespace crypto3 {

        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(192)

        /**
         * The NIST P-192 curve
         */
        template<std::size_t WordBits = CRYPTO3_MP_WORD_BITS>
        class p192 : public curve_nist_policy<192, WordBits> {
        public:
            constexpr static const std::size_t word_bits = curve_nist_policy<192, WordBits>::word_bits;
            constexpr static const std::size_t p_bits = curve_nist_policy<192, WordBits>::p_bits;
            constexpr static const std::size_t p_words = curve_nist_policy<192, WordBits>::p_words;

            typedef number<backends::cpp_int_backend<p_bits, p_bits, unsigned_magnitude, unchecked, void>> p_type;

            constexpr static const p_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF_cppui192;

            template<typename Backend, expression_template_option ExpressionTemplates>
            static void redc_mod_p(number<Backend, ExpressionTemplates> &x) {
                const uint32_t X6 = detail::get_uint32_t(x, 6);
                const uint32_t X7 = detail::get_uint32_t(x, 7);
                const uint32_t X8 = detail::get_uint32_t(x, 8);
                const uint32_t X9 = detail::get_uint32_t(x, 9);
                const uint32_t X10 = detail::get_uint32_t(x, 10);
                const uint32_t X11 = detail::get_uint32_t(x, 11);

                mask_bits(x, p_bits);

                uint64_t S = 0;

                S += detail::get_uint32_t(x, 0);
                S += X6;
                S += X10;
                detail::set_uint32_t(x, 0, S);
                S >>= 32;

                S += detail::get_uint32_t(x, 1);
                S += X7;
                S += X11;
                detail::set_uint32_t(x, 1, S);
                S >>= 32;

                S += detail::get_uint32_t(x, 2);
                S += X6;
                S += X8;
                S += X10;
                detail::set_uint32_t(x, 2, S);
                S >>= 32;

                S += detail::get_uint32_t(x, 3);
                S += X7;
                S += X9;
                S += X11;
                detail::set_uint32_t(x, 3, S);
                S >>= 32;

                S += detail::get_uint32_t(x, 4);
                S += X8;
                S += X10;
                detail::set_uint32_t(x, 4, S);
                S >>= 32;

                S += detail::get_uint32_t(x, 5);
                S += X9;
                S += X11;
                detail::set_uint32_t(x, 5, S);
                S >>= 32;

                detail::set_uint32_t(x, 6, S);

                // No underflow possible

                reduce_below(x, p);
            }
        };
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CURVE_NIST_P192_HPP