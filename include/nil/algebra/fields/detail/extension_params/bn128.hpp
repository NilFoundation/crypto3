//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_BN128_EXTENSION_PARAMS_HPP
#define ALGEBRA_FIELDS_BN128_EXTENSION_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/element/fp6_3over2.hpp>

#include <nil/algebra/fields/params.hpp>
#include <nil/algebra/fields/bn128/base_field.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                using namespace nil::algebra;

                template<typename FieldType>
                struct fp2_extension_params;

                template<typename FieldType>
                struct fp6_3over2_extension_params;

                template<typename FieldType>
                struct fp12_2over3over2_extension_params;
                
                /************************* BN128 ***********************************/

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class fp2_extension_params<fields::bn128<ModulusBits, GeneratorBits>>
                    : public params<fields::bn128<ModulusBits, GeneratorBits>> {

                    typedef params<fields::bn128<ModulusBits, GeneratorBits>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;
                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp<policy_type> non_residue_type;
                    typedef element_fp<policy_type> underlying_type;

                    constexpr static const std::size_t s = 0x04;
                    constexpr static const extended_modulus_type t =
                        0x925C4B8763CBF9C599A6F7C0348D21CB00B85511637560626EDFA5C34C6B38D04689E957A1242C84A50189C6D96CADCA602072D09EAC1013B5458A2275D69B_cppui504;
                    constexpr static const extended_modulus_type t_minus_1_over_2 =
                        0x492E25C3B1E5FCE2CCD37BE01A4690E5805C2A88B1BAB031376FD2E1A6359C682344F4ABD09216425280C4E36CB656E5301039684F560809DAA2C5113AEB4D_cppui503;
                    constexpr static const std::array<modulus_type, 2> nqr = {0x02, 0x01};
                    constexpr static const std::array<modulus_type, 2> nqr_to_t = 
                        {0xB20DCB5704E326A0DD3ECD4F30515275398A41A4E1DC5D347CFBBEDDA71CF82_cppui252,
                         0xB1FFEFD8885BF22252522C29527D19F05CFC50E9715370AB0F3A6CA462390C_cppui248};

                    constexpr static const modulus_type non_residue = modulus_type(
                        0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD46_cppui254);
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class fp6_3over2_extension_params<fields::bn128<ModulusBits, GeneratorBits>>
                    : public params<fields::bn128<ModulusBits, GeneratorBits>> {

                    typedef fields::bn128<ModulusBits, GeneratorBits> field_type;
                    typedef params<field_type> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp2<field_type> non_residue_type;
                    typedef element_fp2<fp2_extension_params<field_type>> underlying_type;

                    constexpr static const std::array<modulus_type, 2> non_residue = {9, 1};
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class fp12_2over3over2_extension_params<fields::bn128<ModulusBits, GeneratorBits>>
                    : public params<fields::bn128<ModulusBits, GeneratorBits>> {

                    typedef fields::bn128<ModulusBits, GeneratorBits> field_type;
                    typedef params<field_type> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp2<field_type> non_residue_type;
                    typedef element_fp6_3over2<fp6_3over2_extension_params<field_type>> underlying_type;

                    constexpr static const std::array<modulus_type, 2> non_residue = {9, 1};
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename std::size_t const
                    fp2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::s;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::extended_modulus_type const
                    fp2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::t;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::extended_modulus_type const
                    fp2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::t_minus_1_over_2;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename fp2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type, 2> const
                    fp2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::nqr;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename fp2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type, 2> const
                    fp2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::nqr_to_t;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename fp6_3over2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type, 2> const
                    fp6_3over2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::non_residue;
                
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename fp12_2over3over2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type, 2> const
                    fp12_2over3over2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::non_residue;

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_BN128_EXTENSION_PARAMS_HPP
