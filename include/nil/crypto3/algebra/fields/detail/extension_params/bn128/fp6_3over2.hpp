//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_BN128_FP6_3OVER2_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BN128_FP6_3OVER2_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/bn128/base_field.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<typename FieldType>
                    struct fp6_3over2_extension_params;

                    /************************* BN128 ***********************************/

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    class fp6_3over2_extension_params<fields::bn128<ModulusBits, GeneratorBits>>
                        : public params<fields::bn128<ModulusBits, GeneratorBits>> {

                        typedef fields::bn128<ModulusBits, GeneratorBits> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef fields::fp2<base_field_type> non_residue_field_type;
                        typedef typename non_residue_field_type::value_type non_residue_type;
                        typedef fields::fp2<base_field_type> underlying_field_type;
                        typedef typename underlying_field_type::value_type underlying_type;

                        /*constexpr static const std::array<non_residue_type, 6> Frobenius_coeffs_c1 =
                        {non_residue_type(0x00, 0x00), non_residue_type(0x00, 0x00), non_residue_type(0x00, 0x00),
                            non_residue_type(0x00, 0x00),
                            non_residue_type(0x00, 0x00),
                            non_residue_type(0x00, 0x00)};

                        constexpr static const std::array<non_residue_type, 6> Frobenius_coeffs_c2 =
                        {non_residue_type(0x00, 0x00), non_residue_type(0x00, 0x00), non_residue_type(0x00, 0x00),
                            non_residue_type(0x00, 0x00),
                            non_residue_type(0x00, 0x00),
                            non_residue_type(0x00, 0x00)};*/

                        constexpr static const std::array<modulus_type, 6 * 2> Frobenius_coeffs_c1 = {
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

                        constexpr static const std::array<modulus_type, 6 * 2> Frobenius_coeffs_c2 = {
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

                        constexpr static const std::array<modulus_type, 2> non_residue = {9, 1};
                    };

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr std::array<typename fp6_3over2_extension_params<
                                             bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type,
                                         2> const
                        fp6_3over2_extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::non_residue;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BN128_FP6_3OVER2_EXTENSION_PARAMS_HPP
