//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BN128_PARAMS_HPP
#define ALGEBRA_CURVES_BN128_PARAMS_HPP

#include <nil/algebra/curves/mnt4.hpp>

#include <nil/algebra/curves/detail/params/params.hpp>

#include <nil/algebra/fields/mnt4/fq.hpp>

#include <nil/algebra/fields/detail/element/fp2.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template <std::size_t ModulusBits>
                struct pairing_params<mnt4<ModulusBits>> {

                    constexpr static const std::size_t g1_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp<fields::detail::arithmetic_params<fields::mnt4_fq<g1_field_bits, CHAR_BIT>>> g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp2<fields::detail::arithmetic_params<fields::mnt4_fq<g2_field_bits, CHAR_BIT>>> g2_field_type_value;

                    static const g2_field_type_value mnt4_twist = mnt4_Fq2(mnt4_Fq::zero(), mnt4_Fq::one());
                    static const g2_field_type_value mnt4_twist_coeff_a = mnt4_Fq2(mnt4_G1::coeff_a * mnt4_Fq2::non_residue, mnt4_Fq::zero());
                    static const g2_field_type_value mnt4_twist_coeff_b = mnt4_Fq2(mnt4_Fq::zero(), mnt4_G1::coeff_b * mnt4_Fq2::non_residue);

                    static const g1_field_type_value mnt4_twist_mul_by_a_c0 = mnt4_twist_coeff_a * g2_field_type_value::non_residue;
                    static const g1_field_type_value mnt4_twist_mul_by_a_c1 = mnt4_twist_coeff_a * g2_field_type_value::non_residue;
                    static const g1_field_type_value mnt4_twist_mul_by_b_c0 = mnt4_twist_coeff_b * g2_field_type_value::non_residue.square();
                    static const g1_field_type_value mnt4_twist_mul_by_b_c1 = mnt4_twist_coeff_b * g2_field_type_value::non_residue;
                    static const g1_field_type_value mnt4_twist_mul_by_q_X(0x3BCF7BCD473A266249DA7B0548ECAEEC9635D1330EA41A9E35E51200E12C90CD65A71660000_cppui298);
                    static const g1_field_type_value mnt4_twist_mul_by_q_Y(0xF73779FE09916DFDCC2FD1F968D534BEB17DAF7518CD9FAE5C1F7BDCF94DD5D7DEF6980C4_cppui292);
                };

            }    // namespace detail
        }    // namespace fields
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_DSA_BOTAN_PARAMS_HPP
