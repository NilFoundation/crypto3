//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_EDWARDS_PARAMS_HPP
#define ALGEBRA_CURVES_EDWARDS_PARAMS_HPP

#include <nil/algebra/curves/edwards.hpp>

#include <nil/algebra/curves/detail/params/params.hpp>

#include <nil/algebra/fields/edwards/fq.hpp>

#include <nil/algebra/fields/detail/element/fp2.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template <std::size_t ModulusBits>
                struct pairing_params<edwards<ModulusBits>> {

                    using policy_type = edwards<ModulusBits>;

                    constexpr static const policy_type::number_type edwards_coeff_a = policy_type::a;
                    constexpr static const policy_type::number_type edwards_coeff_d = policy_type::d;

                    constexpr static const std::size_t g1_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp<fields::detail::arithmetic_params<fields::edwards_fq<g1_field_bits, CHAR_BIT>>> g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp3<fields::detail::arithmetic_params<fields::edwards_fq<g2_field_bits, CHAR_BIT>>> g2_field_type_value;

                    static const g2_field_type_value edwards_twist (g2_field_type_value::underlying_type::zero(), 
                            g2_field_type_value::underlying_type::one(), g2_field_type_value::underlying_type::zero());
                    static const g2_field_type_value edwards_twist_coeff_a = edwards_twist.mul_by_Fp(edwards_coeff_a);
                    static const g2_field_type_value edwards_twist_coeff_d = edwards_twist.mul_by_Fp(edwards_coeff_d);

                    static const g1_field_type_value edwards_twist_mul_by_a_c0 = edwards_coeff_a * g2_field_type_value::non_residue;
                    static const g1_field_type_value edwards_twist_mul_by_a_c1 = edwards_coeff_a;
                    static const g1_field_type_value edwards_twist_mul_by_a_c2 = edwards_coeff_a;
                    static const g1_field_type_value edwards_twist_mul_by_d_c0 = edwards_coeff_d * g2_field_type_value::non_residue;
                    static const g1_field_type_value edwards_twist_mul_by_d_c1 = edwards_coeff_d;
                    static const g1_field_type_value edwards_twist_mul_by_d_c2 = edwards_coeff_d;
                    static const g1_field_type_value edwards_twist_mul_by_q_Y (0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);
                    static const g1_field_type_value edwards_twist_mul_by_q_Z (0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);
                };

            }    // namespace detail
        }    // namespace fields
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_EDWARDS_PARAMS_HPP
