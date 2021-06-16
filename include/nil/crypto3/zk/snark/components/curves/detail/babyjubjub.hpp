//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of specializations of basic_curve_component_policy<CurveType> to
// - basic_curve_component_policy<curves::babyjubjub>.
//
// See pairing_params.hpp .
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BABYJUBJUB_BASIC_CURVE_COMPONENT_POLICY_HPP
#define CRYPTO3_ZK_BABYJUBJUB_BASIC_CURVE_COMPONENT_POLICY_HPP

#include <nil/crypto3/algebra/curves/babyjubjub.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>

#include <nil/crypto3/zk/snark/components/fields/element_fp2.hpp>
// #include <nil/crypto3/zk/snark/components/fields/element_fp12_2over3over2.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace components {

                    using namespace nil::crypto3::algebra;

                    template<typename CurveType>
                    class basic_curve_component_policy;

                    /**
                     * Specialization for babyjubjub.
                     */
                    template<>
                    class basic_curve_component_policy<curves::babyjubjub> {
                        using curve_type = typename curves::babyjubjub;

                        // Maybe the name "pair_curve_type" is a little bit confusing
                        // We shouldn transfer this defention to algebra and remove this struct
                        typedef typename curves::alt_bn128<254> pair_curve_type;

                        typedef typename pair_curve_type::pairing::fqe_type fqe_type;
                        typedef typename pair_curve_type::pairing::fqk_type fqk_type;

                        typedef typename curve_type::pairing::fp_type field_type;

                    public:
                        typedef Fp2_variable<fqe_type> Fqe_variable_type;
                        typedef Fp2_mul_component<fqe_type> Fqe_mul_component_type;
                        typedef Fp2_mul_by_lc_component<fqe_type> Fqe_mul_by_lc_component_type;
                        typedef Fp2_sqr_component<fqe_type> Fqe_sqr_component_type;

                        // typedef Fp12_2over3over2_variable<fqk_type> Fqk_variable_type;
                        // typedef Fp12_2over3over2_mul_component<fqk_type> Fqk_mul_component_type;
                        // typedef Fp12_2over3over2_mul_by_2345_component<fqk_type> Fqk_special_mul_component_type;
                        // typedef Fp12_2over3over2_sqr_component<fqk_type> Fqk_sqr_component_type;
                    };
                }    // namespace components
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BABYJUBJUB_BASIC_CURVE_COMPONENT_POLICY_HPP
