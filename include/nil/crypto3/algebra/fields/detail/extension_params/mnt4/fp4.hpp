//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_MNT4_FP4_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_MNT4_FP4_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<typename FieldType>
                    struct fp4_extension_params;

                    /************************* MNT4 ***********************************/

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    class fp4_extension_params<fields::mnt4_base_field<ModulusBits, GeneratorBits>>
                        : public params<fields::mnt4_base_field<ModulusBits, GeneratorBits>> {

                        typedef fields::mnt4_base_field<ModulusBits, GeneratorBits> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef base_field_type non_residue_field_type;
                        typedef typename non_residue_field_type::value_type non_residue_type;
                        typedef fields::fp2<base_field_type> underlying_field_type;
                        typedef typename underlying_field_type::value_type underlying_type;
                        //typedef element_fp2<fp2_extension_params<field_type>> underlying_type;

                        /*constexpr static const std::array<non_residue_type, 4> Frobenius_coeffs_c1 =
                           {non_residue_type(0x01),
                            non_residue_type(0xF73779FE09916DFDCC2FD1F968D534BEB17DAF7518CD9FAE5C1F7BDCF94DD5D7DEF6980C4_cppui292),
                            non_residue_type(0x3BCF7BCD473A266249DA7B0548ECAEEC9635D1330EA41A9E35E51200E12C90CD65A71660000_cppui298),
                            non_residue_type(0x3AD84453493094F44C0E4B334F83D9B7D7845383998B4CFE8788F285043342F78DC81FC7F3D_cppui298)};*/

                        constexpr static const std::array<modulus_type, 4> Frobenius_coeffs_c1 = {
                            0x01, 0xF73779FE09916DFDCC2FD1F968D534BEB17DAF7518CD9FAE5C1F7BDCF94DD5D7DEF6980C4_cppui292,
                            0x3BCF7BCD473A266249DA7B0548ECAEEC9635D1330EA41A9E35E51200E12C90CD65A71660000_cppui298,
                            0x3AD84453493094F44C0E4B334F83D9B7D7845383998B4CFE8788F285043342F78DC81FC7F3D_cppui298};

                        constexpr static const modulus_type non_residue = modulus_type(0x11);
                    };

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr
                        typename fp4_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                            fp4_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::non_residue;

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr
                        typename fp4_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                            fp4_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::modulus;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_MNT4_FP4_EXTENSION_PARAMS_HPP
