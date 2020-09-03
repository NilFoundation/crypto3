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
                    using underlying_field_type_value = typename element_type::underlying_field_type_value;

                    bn128_g2() : bn128_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};

                    bn128_g2(underlying_field_type_value X, underlying_field_type_value Y, underlying_field_type_value Z) : element_type(X, Y, Z) {};

                    static bn128_g2 zero() {
                        return bn128_g2();
                    }

                    static bn128_g2 one() {
                        return bn128_g2(one_fill[0], one_fill[1], one_fill[2]);
                    }

                private:

                    constexpr static const underlying_field_type_value zero_fill = {underlying_field_type_value::one(), underlying_field_type_value::one(), underlying_field_type_value::zero()};

                    constexpr static const underlying_field_type_value one_fill = {
                        underlying_field_type_value(0x21C1452BAD76CBAFD56F91BF61C4C7A4764793ABC7E62D2EB2382A21D01014DA_cppui254,
                                                0x13F9579708C580632ECD7DCD6EE2E6FC20F597815A2792CC5128240A38EEBC15_cppui254),
                        underlying_field_type_value(0x16CFE76F05CE1E4C043A5A50EE37E9B0ADD1E47D95E5250BA20538A3680892C_cppui254,
                                                0x2D6532096CCA63300C3BA564B9BD9949DCDFB32C84AC6E2A065FD2334A7D09BE_cppui254),
                        underlying_field_type_value::one()};
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_BN128_G2_HPP
