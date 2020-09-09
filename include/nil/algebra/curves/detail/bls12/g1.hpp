//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BLS12_G1_HPP
#define ALGEBRA_CURVES_BLS12_G1_HPP

#include <nil/algebra/curves/detail/bls12/basic_policy.hpp>

#include <nil/algebra/fields/fp2.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                struct bls12_g1{};

                template<>
                struct bls12_g1<381, CHAR_BIT> {

                    using policy_type = bls12_basic_policy<381, CHAR_BIT>;
                    constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                    typedef typename policy_type::base_field_type::value_type g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = policy_type::base_field_bits;
                    typedef typename fields::fp2<policy_type::base_field_type>::value_type g2_field_type_value;

                    using underlying_field_type_value = g1_field_type_value;

                    underlying_field_type_value p[3];

                    /*constexpr static */ const underlying_field_type_value x =
                        underlying_field_type_value(0x00);    //?
                    /*constexpr static */ const underlying_field_type_value y =
                        underlying_field_type_value(0x00);    //?

                    bls12_g1() :
                        bls12_g1(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                underlying_field_type_value::zero()) {};
                    // must be
                    // bls12_g1() : bls12_g1(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                    // when constexpr fields will be finished

                    bls12_g1(underlying_field_type_value X,
                            underlying_field_type_value Y,
                            underlying_field_type_value Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
                    };

                    static bls12_g1 zero() {
                        return bls12_g1();
                    }

                    static bls12_g1 one() {
                        return bls12_g1(
                            underlying_field_type_value(0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB_cppui381),
                            underlying_field_type_value(0x8B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1_cppui380),
                            underlying_field_type_value::one());
                        // must be
                        // bls12_g1() : bls12_g1(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                        // when constexpr fields will be finished
                    }

                    
                private:
                    /*constexpr static */ const g1_field_type_value a = g1_field_type_value(policy_type::a);
                    /*constexpr static */ const g1_field_type_value b = g1_field_type_value(policy_type::b);

                    /*constexpr static const underlying_field_type_value zero_fill = {
                        underlying_field_type_value::zero(), underlying_field_type_value::one(),
                        underlying_field_type_value::zero()};

                    constexpr static const underlying_field_type_value one_fill = {
                        underlying_field_type_value(0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB_cppui381),
                        underlying_field_type_value(0x8B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1_cppui380),
                        underlying_field_type_value::one()};*/
                };

                template<>
                struct bls12_g1<377, CHAR_BIT> {

                    using policy_type = bls12_basic_policy<377, CHAR_BIT>;
                    constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                    typedef typename policy_type::base_field_type::value_type g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = policy_type::base_field_bits;
                    typedef typename fields::fp2<policy_type::base_field_type>::value_type g2_field_type_value;

                    using underlying_field_type_value = g1_field_type_value;

                    underlying_field_type_value p[3];

                    /*constexpr static */ const underlying_field_type_value x =
                        underlying_field_type_value(0x00);    //?
                    /*constexpr static */ const underlying_field_type_value y =
                        underlying_field_type_value(0x00);    //?

                    bls12_g1() :
                        bls12_g1(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                underlying_field_type_value::zero()) {};
                    // must be
                    // bls12_g1() : bls12_g1(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                    // when constexpr fields will be finished

                    bls12_g1(underlying_field_type_value X,
                            underlying_field_type_value Y,
                            underlying_field_type_value Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
                    };

                    static bls12_g1 zero() {
                        return bls12_g1();
                    }

                    static bls12_g1 one() {
                        return bls12_g1(
                            underlying_field_type_value(0x8848DEFE740A67C8FC6225BF87FF5485951E2CAA9D41BB188282C8BD37CB5CD5481512FFCD394EEAB9B16EB21BE9EF_cppui376),
                            underlying_field_type_value(0x1914A69C5102EFF1F674F5D30AFEEC4BD7FB348CA3E52D96D182AD44FB82305C2FE3D3634A9591AFD82DE55559C8EA6_cppui377),
                            underlying_field_type_value::one());
                        // must be
                        // bls12_g1() : bls12_g1(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                        // when constexpr fields will be finished
                    }

                    
                private:
                    /*constexpr static */ const g1_field_type_value a = g1_field_type_value(policy_type::a);
                    /*constexpr static */ const g1_field_type_value b = g1_field_type_value(policy_type::b);

                    /*constexpr static const underlying_field_type_value zero_fill = {
                        underlying_field_type_value::zero(), underlying_field_type_value::one(),
                        underlying_field_type_value::zero()};

                    constexpr static const underlying_field_type_value one_fill = {
                        underlying_field_type_value(0x8848DEFE740A67C8FC6225BF87FF5485951E2CAA9D41BB188282C8BD37CB5CD5481512FFCD394EEAB9B16EB21BE9EF_cppui376),
                        underlying_field_type_value(0x1914A69C5102EFF1F674F5D30AFEEC4BD7FB348CA3E52D96D182AD44FB82305C2FE3D3634A9591AFD82DE55559C8EA6_cppui377),
                        underlying_field_type_value::one()};*/
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_BLS12_G1_HPP
