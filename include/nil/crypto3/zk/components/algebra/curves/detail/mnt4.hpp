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
// - basic_curve_component_policy<curves::mnt4>.
//
// See pairing_params.hpp .
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_MNT4_BASIC_CURVE_COMPONENT_POLICY_HPP
#define CRYPTO3_ZK_BLUEPRINT_MNT4_BASIC_CURVE_COMPONENT_POLICY_HPP

#include <nil/crypto3/algebra/curves/mnt4.hpp>

#include <nil/crypto3/zk/components/algebra/fields/element_fp3.hpp>
#include <nil/crypto3/zk/components/algebra/fields/element_fp6_2over3.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                using namespace nil::crypto3::algebra;

                template<typename CurveType>
                class basic_curve_component_policy;

                /**
                 * Specialization for MNT4.
                 */
                template<std::size_t Version>
                class basic_curve_component_policy<curves::mnt4<Version>> {
                    using curve_type = typename curves::mnt4<Version>;

                    typedef typename curve_type::chained_on_curve_type chained_on_curve_type;    // mnt6

                    typedef typename chained_on_curve_type::pairing::fqe_type fqe_type;
                    typedef typename chained_on_curve_type::pairing::fqk_type fqk_type;

                    typedef typename curve_type::pairing::fp_type field_type;

                public:
                    typedef element_fp3<fqe_type> Fqe_variable_type;
                    typedef element_fp3_mul<fqe_type> Fqe_mul_component_type;
                    typedef element_fp3_mul_by_lc<fqe_type> Fqe_mul_by_lc_component_type;
                    typedef element_fp3_squared<fqe_type> Fqe_sqr_component_type;

                    typedef element_fp6_2over3<fqk_type> Fqk_variable_type;
                    typedef element_fp6_2over3_mul<fqk_type> Fqk_mul_component_type;
                    typedef element_fp6_2over3_mul_by_2345<fqk_type> Fqk_special_mul_component_type;
                    typedef element_fp6_2over3_squared<fqk_type> Fqk_sqr_component_type;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_MNT4_BASIC_CURVE_COMPONENT_POLICY_HPP
