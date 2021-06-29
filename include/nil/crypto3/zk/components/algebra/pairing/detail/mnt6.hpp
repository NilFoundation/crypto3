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
// @file Declaration of specializations of basic_pairing_component_policy<CurveType> to
// - basic_pairing_component_policy<curves::mnt6>.
//
// See pairing_params.hpp .
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_MNT6_BASIC_PAIRING_HPP
#define CRYPTO3_ZK_BLUEPRINT_MNT6_BASIC_PAIRING_HPP

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/zk/components/algebra/curves/detail/mnt6.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<typename CurveType>
                    class basic_pairing_component_policy;

                    /**
                     * Specialization for MNT6.
                     */
                    template<std::size_t Version>
                    class basic_pairing_component_policy<curves::mnt6<Version>> {
                        using curve_type = typename curves::mnt6<Version>;
                        using curve_component_policy = basic_curve_component_policy<curve_type>;

                    public:
                        using Fqe_variable_type = typename basic_curve_component_policy<curve_type>::Fqe_variable_type;
                        using Fqe_mul_component_type =
                            typename basic_curve_component_policy<curve_type>::Fqe_mul_component_type;
                        using Fqe_mul_by_lc_component_type =
                            typename basic_curve_component_policy<curve_type>::Fqe_mul_by_lc_component_type;
                        using Fqe_sqr_component_type =
                            typename basic_curve_component_policy<curve_type>::Fqe_sqr_component_type;

                        using Fqk_variable_type = typename basic_curve_component_policy<curve_type>::Fqk_variable_type;
                        using Fqk_mul_component_type =
                            typename basic_curve_component_policy<curve_type>::Fqk_mul_component_type;
                        using Fqk_special_mul_component_type =
                            typename basic_curve_component_policy<curve_type>::Fqk_special_mul_component_type;
                        using Fqk_sqr_component_type =
                            typename basic_curve_component_policy<curve_type>::Fqk_sqr_component_type;

                        constexpr static const typename curve_type::pairing::number_type &pairing_loop_count =
                            curve_type::pairing::pairing_loop_count;

                        constexpr static const typename curve_type::g1_type::underlying_field_type::value_type
                            g1_coeff_a = curve_type::a;

                        constexpr static const typename curve_type::g1_type::underlying_field_type::value_type
                            g1_coeff_b = curve_type::b;

                        constexpr static const typename curve_type::g2_type::underlying_field_type::value_type
                            g2_coeff_a = typename curve_type::g2_type::underlying_field_type::value_type(
                                curve_type::g2_type::underlying_field_type::underlying_field_type::value_type::zero(),
                                curve_type::g2_type::underlying_field_type::underlying_field_type::value_type::zero(),
                                g1_coeff_a);

                        constexpr static const typename curve_type::g2_type::underlying_field_type::value_type
                            g2_coeff_b = typename curve_type::g2_type::underlying_field_type::value_type(
                                g1_coeff_b *
                                    typename curve_type::g2_type::underlying_field_type::value_type::non_residue,
                                curve_type::g2_type::underlying_field_type::underlying_field_type::value_type::zero(),
                                curve_type::g2_type::underlying_field_type::underlying_field_type::value_type::zero());
                    };
                }    // namespace detail
            }        // namespace components
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_MNT6_BASIC_PAIRING_HPP
