//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_PAIRINGS_USINGS_HPP
#define CRYPTO3_ALGEBRA_PAIRINGS_USINGS_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {

            template<typename CurveType>
            using fqk_type = typename CurveType::pairing_policy::fqk_type;    // TODO: better name when stable

            using other_curve_type = curves::mnt6<ModulusBits>;

            typedef typename policy_type::number_type number_type;

            constexpr static const number_type pairing_loop_count = policy_type::ate_loop_count;

            constexpr static const bool ate_is_loop_count_neg = policy_type::ate_is_loop_count_neg;

            constexpr static const number_type final_exponent_last_chunk_abs_of_w0 =
                policy_type::final_exponent_last_chunk_abs_of_w0;
            constexpr static const bool final_exponent_last_chunk_is_w0_neg =
                policy_type::final_exponent_last_chunk_is_w0_neg;
            constexpr static const number_type final_exponent_last_chunk_w1 =
                policy_type::final_exponent_last_chunk_w1;

            /*constexpr static*/ const typename policy_type::g2_group::underlying_field_type::value_type twist =
                policy_type().twist;

            typedef typename policy_type::Fp_field Fp_type;
            using G1_type = typename policy_type::g1;
            using G2_type = typename policy_type::g2;
            typedef typename policy_type::Fq_field Fq_type;
            typedef typename policy_type::Fqe_field Fqe_type;
            typedef typename policy_type::Fqk_field Fqk_type;
            typedef typename policy_type::gt GT_type;

            using G1_precomp = typename policy_type::g1_precomp;
            using G2_precomp = typename policy_type::g2_precomp;

            using affine_ate_G1_precomp = typename policy_type::affine_ate_g1_precomputation;
            using affine_ate_G2_precomp = typename policy_type::affine_ate_g2_precomputation;

        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRINGS_USINGS_HPP
