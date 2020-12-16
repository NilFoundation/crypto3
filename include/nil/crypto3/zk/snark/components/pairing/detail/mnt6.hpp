//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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
// @file Declaration of specializations of basic_pairing_component_policy<CurveType> to
// - basic_pairing_component_policy<curves::mnt4>, and
// - basic_pairing_component_policy<curves::mnt6>.
//
// See pairing_params.hpp .
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MNT6_BASIC_PAIRING_HPP
#define CRYPTO3_ZK_MNT6_BASIC_PAIRING_HPP

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp2_components.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp3_components.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp4_components.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp6_2over3_components.hpp>
#include <nil/crypto3/zk/snark/components/pairing/pairing_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace components {

                    using namespace nil::crypto3::algebra;

                    /**
                     * Specialization for MNT6.
                     */
                    template<std::size_t Version>
                    class basic_pairing_component_policy<curves::mnt6<Version>> {
                        using curve_type = typename curves::mnt6<Version>;

                        typedef typename curve_type::pairing_policy::other_curve_type other_curve_type;    // mnt4

                        typedef typename other_curve_type::pairing_policy::Fqe_type fqe_type;
                        typedef typename other_curve_type::pairing_policy::Fqk_type fqk_type;

                        typedef typename curve_type::pairing_policy::Fp_type field_type;
                    public:

                        typedef Fp2_variable<fqe_type> Fqe_variable_type;
                        typedef Fp2_mul_component<fqe_type> Fqe_mul_component_type;
                        typedef Fp2_mul_by_lc_component<fqe_type> Fqe_mul_by_lc_component_type;
                        typedef Fp2_sqr_component<fqe_type> Fqe_sqr_component_type;

                        typedef Fp4_variable<fqk_type> Fqk_variable_type;
                        typedef Fp4_mul_component<fqk_type> Fqk_mul_component_type;
                        typedef Fp4_mul_component<fqk_type> Fqk_special_mul_component_type;
                        typedef Fp4_sqr_component<fqk_type> Fqk_sqr_component_type;

                        constexpr static const typename curve_type::pairing_policy::number_type &pairing_loop_count =
                            curve_type::pairing_policy::pairing_loop_count;
                    };

                }    // namespace components
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MNT6_BASIC_PAIRING_HPP
