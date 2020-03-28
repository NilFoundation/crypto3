//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_GFP_CURVE_HPP
#define CRYPTO3_PUBKEY_GFP_CURVE_HPP

#include <memory>

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/prime.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            // Any use of user defined literals requires that we import the
            // literal-operators into current scope first:
            using namespace boost::multiprecision::literals;
            using namespace boost::multiprecision;

            /**
             * @brief This class represents an elliptic curve over GF(p)
             *
             * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
             *
             * @tparam Number Represents the Boost.Multiprecision number type.
             *
             * @note There should not be any reason for applications to use this
             * type. If you need EC primitives use the interfaces ec_group and
             * point_gfp
             */
            template<typename NumberType>
            class curve_gfp {
            public:
                typedef NumberType number_type;

                virtual ~curve_gfp() = default;

                virtual const number_type &p() const = 0;

                virtual const number_type &a() const = 0;

                virtual const number_type &b() const = 0;

                virtual size_t get_p_words() const = 0;

                virtual size_t get_ws_size() const = 0;

                virtual bool is_one(const number_type &x) const = 0;

                virtual bool a_is_zero() const = 0;

                virtual bool a_is_minus_3() const = 0;

                /*
                 * Returns to_curve_rep(get_a())
                 */
                virtual const number_type &get_a_rep() const = 0;

                /*
                 * Returns to_curve_rep(get_b())
                 */
                virtual const number_type &get_b_rep() const = 0;

                /*
                 * Returns to_curve_rep(1)
                 */
                virtual const number_type &get_1_rep() const = 0;

                virtual void redc_mod_p(number_type &z, secure_vector<word> &ws) const = 0;

                virtual number_type invert_element(const number_type &x, secure_vector<word> &ws) const = 0;

                virtual void to_curve_rep(number_type &x, secure_vector<word> &ws) const = 0;

                virtual void from_curve_rep(number_type &x, secure_vector<word> &ws) const = 0;

                void curve_mul(number_type &z, const number_type &x, const number_type &y,
                               secure_vector<word> &ws) const {
                    CRYPTO3_DEBUG_ASSERT(x.sig_words() <= m_p_words);
                    curve_mul_words(z, x.data(), x.size(), y, ws);
                }

                virtual void curve_mul_words(number_type &z, const word x_words[], std::size_t x_size,
                                             const number_type &y, secure_vector<word> &ws) const = 0;

                void curve_sqr(number_type &z, const number_type &x, secure_vector<word> &ws) const {
                    CRYPTO3_DEBUG_ASSERT(x.sig_words() <= m_p_words);
                    curve_sqr_words(z, x.data(), x.size(), ws);
                }

                virtual void curve_sqr_words(number_type &z, const word x_words[], size_t x_size,
                                             secure_vector<word> &ws) const = 0;

                template<typename NumberType1>
                inline bool operator==(const curve_gfp<NumberType1> &other) const {
                    return p() == other.p() && a() == other.a() && b() == other.b();
                }
            };

            template<typename NumberType1, typename NumberType2>
            inline bool operator!=(const curve_gfp<NumberType1> &lhs, const curve_gfp<NumberType2> &rhs) {
                return !(lhs == rhs);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
