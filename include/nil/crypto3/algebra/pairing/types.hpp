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

#ifndef CRYPTO3_ALGEBRA_PAIRINGS_TYPES_HPP
#define CRYPTO3_ALGEBRA_PAIRINGS_TYPES_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairings {

                template<typename CurveType>
                using other_curve_type = typename CurveType::pairing_policy::other_curve_type;

                template<typename CurveType>
                using Fp_type = typename CurveType::pairing_policy::Fp_type;

                template<typename CurveType>
                using Fq_type = typename CurveType::pairing_policy::Fq_type;

                template<typename CurveType>
                using Fqe_type = typename CurveType::pairing_policy::Fqe_type;

                template<typename CurveType>
                using Fqk_type = typename CurveType::pairing_policy::Fqk_type;

                template<typename CurveType>
                using g1_type = typename CurveType::pairing_policy::g1_type;

                template<typename CurveType>
                using g2_type = typename CurveType::pairing_policy::g2_type;

                template<typename CurveType>
                using gt_type = typename CurveType::pairing_policy::gt_type;

                template<typename CurveType>
                using G1_precomp = typename CurveType::pairing_policy::G1_precomp;

                template<typename CurveType>
                using G2_precomp = typename CurveType::pairing_policy::G2_precomp;

                template<typename CurveType>
                using affine_ate_G1_precomp = typename CurveType::pairing_policy::affine_ate_G1_precomp;

                template<typename CurveType>
                using affine_ate_G2_precomp = typename CurveType::pairing_policy::affine_ate_G2_precomp;


            }    // namespace pairings    
        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRINGS_TYPES_HPP
