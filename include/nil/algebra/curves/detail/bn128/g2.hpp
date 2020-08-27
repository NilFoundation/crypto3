//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BN128_G2_HPP
#define ALGEBRA_CURVES_BN128_G2_HPP

#include <boost/multiprecision/cpp_int/multiply.hpp>
#include <boost/multiprecision/modular/base_params.hpp>

#include <nil/algebra/curves/detail/element/curve_weierstrass.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template<typename PairingParams>
                struct bn128_g2 : public element_curve_weierstrass<typename PairingParams::g1_type> {
                    
                    using policy_type = PairingParams;
                    using element_type = element_curve_weierstrass<typename policy_type::g2_type>;
                    using underlying_field_type = typename element_type::underlying_field_type;

                    bn128_g2() : element_type(underlying_field_type::one(), underlying_field_type::one(), underlying_field_type::zero()) {};

                    bn128_g2(underlying_field_type X, underlying_field_type Y, underlying_field_type Z) : element_type(X, Y, Z) {};

                    static bn128_g2 zero() {
                        return bn128_g2();
                    }

                    static bn128_g2 one() {
                        return bn128_g2({15267802884793550383558706039165621050290089775961208824303765753922461897946,
                                         9034493566019742339402378670461897774509967669562610788113215988055021632533},
                                        {644888581738283025171396578091639672120333224302184904896215738366765861164,
                                         20532875081203448695448744255224543661959516361327385779878476709582931298750},
                                        {1, 0});
                    }

                    template<typename NumberType>
                    static NumberType base_field_char() {
                        return arithmetic_params<base_field>::q;
                    }

                    template<typename NumberType>
                    static NumberType order() {
                        return arithmetic_params<scalar_field>::q;
                    }

                private:
                    /* additional parameters for square roots in Fq2 */
                    underlying_field_type bn128_twist_coeff_b =
                        underlying_field_type({19485874751759354771024239261021720505790618469301721065564631296452457478373,
                                    266929791119991161246907387137283842545076965332900288569378510910307636690});
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_BN128_G2_HPP
