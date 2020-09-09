//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BLS12_G2_HPP
#define ALGEBRA_CURVES_BLS12_G2_HPP

#include <nil/algebra/curves/detail/bls12/basic_policy.hpp>

#include <nil/algebra/fields/fp2.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                struct bls12_g2 { };

                template<>
                struct bls12_g2<381, CHAR_BIT> {

                    using policy_type = bls12_basic_policy<381, CHAR_BIT>;
                    constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                    typedef typename policy_type::base_field_type::value_type g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = policy_type::base_field_bits;
                    typedef typename fields::fp2<typename policy_type::base_field_type>::value_type g2_field_type_value;

                    using underlying_field_type_value = g2_field_type_value;

                    underlying_field_type_value p[3];

                    /*constexpr static */ const underlying_field_type_value x =
                        underlying_field_type_value(0x00);    //?
                    /*constexpr static */ const underlying_field_type_value y =
                        underlying_field_type_value(0x00);    //?

                    bls12_g2() :
                        bls12_g2(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                 underlying_field_type_value::zero()) {};
                    // must be
                    // bls12_g2() : bls12_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                    // when constexpr fields will be finished

                    bls12_g2(underlying_field_type_value X,
                             underlying_field_type_value Y,
                             underlying_field_type_value Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
                    };

                    static bls12_g2 zero() {
                        return bls12_g2();
                    }

                    static bls12_g2 one() {
                        return bls12_g2(
                            underlying_field_type_value(
                                0x24AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8_cppui378,
                                0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E_cppui381),
                            underlying_field_type_value(
                                0xCE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801_cppui380,
                                0x606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE_cppui379),
                            underlying_field_type_value::one());
                        // must be
                        // bls12_g2() : bls12_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                        // when constexpr fields will be finished
                    }

                private:
                    /*constexpr static */ const g1_field_type_value a = g1_field_type_value(policy_type::a);
                    /*constexpr static */ const g1_field_type_value b = g1_field_type_value(policy_type::b);

                    /*constexpr static const underlying_field_type_value zero_fill = {
                        underlying_field_type_value::zero(), underlying_field_type_value::one(),
                        underlying_field_type_value::zero()};

                    constexpr static const underlying_field_type_value one_fill = {
                        underlying_field_type_value(
                            0x24AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8_cppui378,
                            0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E_cppui381),
                        underlying_field_type_value(
                            0xCE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801_cppui380,
                            0x606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE_cppui379),
                        underlying_field_type_value::one()};*/
                };

                template<>
                struct bls12_g2<377, CHAR_BIT> {

                    using policy_type = bls12_basic_policy<377, CHAR_BIT>;
                    constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                    typedef typename policy_type::base_field_type::value_type g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = policy_type::base_field_bits;
                    typedef typename fields::fp2<policy_type::base_field_type>::value_type g2_field_type_value;

                    using underlying_field_type_value = g2_field_type_value;

                    underlying_field_type_value p[3];

                    /*constexpr static */ const underlying_field_type_value x =
                        underlying_field_type_value(0x00);    //?
                    /*constexpr static */ const underlying_field_type_value y =
                        underlying_field_type_value(0x00);    //?

                    bls12_g2() :
                        bls12_g2(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                 underlying_field_type_value::zero()) {};
                    // must be
                    // bls12_g2() : bls12_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                    // when constexpr fields will be finished

                    bls12_g2(underlying_field_type_value X,
                             underlying_field_type_value Y,
                             underlying_field_type_value Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
                    };

                    static bls12_g2 zero() {
                        return bls12_g2();
                    }

                    static bls12_g2 one() {
                        return bls12_g2(
                            underlying_field_type_value(
                                0xB997FEF930828FE1B9E6A1707B8AA508A3DBFD7FE2246499C709226A0A6FEF49F85B3A375363F4F8F6EA3FBD159F8A_cppui376,
                                0xD6AC33B84947D9845F81A57A136BFA326E915FABC8CD6A57FF133B42D00F62E4E1AF460228CD5184DEAE976FA62596_cppui376),
                            underlying_field_type_value(
                                0x118DD509B2E9A13744A507D515A595DBB7E3B63DF568866473790184BDF83636C94DF2B7A962CB2AF4337F07CB7E622_cppui377,
                                0x185067C6CA76D992F064A432BD9F9BE832B0CAC2D824D0518F77D39E76C3E146AFB825F2092218D038867D7F337A010_cppui377),
                            underlying_field_type_value::one());
                        // must be
                        // bls12_g2() : bls12_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                        // when constexpr fields will be finished
                    }

                private:
                    /*constexpr static */ const g1_field_type_value a = g1_field_type_value(policy_type::a);
                    /*constexpr static */ const g1_field_type_value b = g1_field_type_value(policy_type::b);

                    /*constexpr static const underlying_field_type_value zero_fill = {
                        underlying_field_type_value::zero(), underlying_field_type_value::one(),
                        underlying_field_type_value::zero()};

                    constexpr static const underlying_field_type_value one_fill = {
                        underlying_field_type_value(
                            0xB997FEF930828FE1B9E6A1707B8AA508A3DBFD7FE2246499C709226A0A6FEF49F85B3A375363F4F8F6EA3FBD159F8A_cppui376,
                            0xD6AC33B84947D9845F81A57A136BFA326E915FABC8CD6A57FF133B42D00F62E4E1AF460228CD5184DEAE976FA62596_cppui376),
                        underlying_field_type_value(
                            0x118DD509B2E9A13744A507D515A595DBB7E3B63DF568866473790184BDF83636C94DF2B7A962CB2AF4337F07CB7E622_cppui377,
                            0x185067C6CA76D992F064A432BD9F9BE832B0CAC2D824D0518F77D39E76C3E146AFB825F2092218D038867D7F337A010_cppui377),
                        underlying_field_type_value::one()};*/
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_BLS12_G2_HPP
