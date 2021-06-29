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
// @file Declaration of interfaces for pairing-check components.
//
// Given that e(.,.) denotes a pairing,
// - the component "check_e_equals_e_component" checks the equation "e(P1,Q1)=e(P2,Q2)"; and
// - the component "check_e_equals_ee_component" checks the equation "e(P1,Q1)=e(P2,Q2)*e(P3,Q3)".
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PAIRING_CHECKS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PAIRING_CHECKS_HPP

#include <memory>

#include <nil/crypto3/zk/components/algebra/pairing/detail/mnt4.hpp>
#include <nil/crypto3/zk/components/algebra/pairing/detail/mnt6.hpp>

#include <nil/crypto3/zk/components/algebra/pairing/weierstrass/final_exponentiation.hpp>
#include <nil/crypto3/zk/components/algebra/pairing/weierstrass/miller_loop.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename CurveType>
                class check_e_equals_e_component : public component<typename CurveType::scalar_field_type> {

                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                    using Fqk_variable_type = typename component_policy::Fqk_variable_type;

                public:
                    typedef typename CurveType::scalar_field_type field_type;

                    std::shared_ptr<Fqk_variable_type> ratio;
                    std::shared_ptr<mnt_e_over_e_miller_loop_component<CurveType>> compute_ratio;
                    std::shared_ptr<final_exp_component<CurveType>> check_finexp;

                    g1_precomputation<CurveType> lhs_G1;
                    g2_precomputation<CurveType> lhs_G2;
                    g1_precomputation<CurveType> rhs_G1;
                    g2_precomputation<CurveType> rhs_G2;

                    blueprint_variable<field_type> result;

                    check_e_equals_e_component(blueprint<field_type> &bp,
                                               const g1_precomputation<CurveType> &lhs_G1,
                                               const g2_precomputation<CurveType> &lhs_G2,
                                               const g1_precomputation<CurveType> &rhs_G1,
                                               const g2_precomputation<CurveType> &rhs_G2,
                                               const blueprint_variable<field_type> &result) :
                        component<field_type>(bp),
                        lhs_G1(lhs_G1), lhs_G2(lhs_G2), rhs_G1(rhs_G1), rhs_G2(rhs_G2), result(result) {
                        ratio.reset(new Fqk_variable_type(bp));
                        compute_ratio.reset(new mnt_e_over_e_miller_loop_component<CurveType>(
                            bp, lhs_G1, lhs_G2, rhs_G1, rhs_G2, *ratio));
                        check_finexp.reset(new final_exp_component<CurveType>(bp, *ratio, result));
                    }

                    void generate_r1cs_constraints() {
                        compute_ratio->generate_r1cs_constraints();
                        check_finexp->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        compute_ratio->generate_r1cs_witness();
                        check_finexp->generate_r1cs_witness();
                    }
                };

                template<typename CurveType>
                class check_e_equals_ee_component : public component<typename CurveType::scalar_field_type> {

                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                    using Fqk_variable_type = typename component_policy::Fqk_variable_type;

                public:
                    typedef typename CurveType::scalar_field_type field_type;

                    std::shared_ptr<Fqk_variable_type> ratio;
                    std::shared_ptr<mnt_e_times_e_over_e_miller_loop_component<CurveType>> compute_ratio;
                    std::shared_ptr<final_exp_component<CurveType>> check_finexp;

                    g1_precomputation<CurveType> lhs_G1;
                    g2_precomputation<CurveType> lhs_G2;
                    g1_precomputation<CurveType> rhs1_G1;
                    g2_precomputation<CurveType> rhs1_G2;
                    g1_precomputation<CurveType> rhs2_G1;
                    g2_precomputation<CurveType> rhs2_G2;

                    blueprint_variable<field_type> result;

                    check_e_equals_ee_component(blueprint<field_type> &bp,
                                                const g1_precomputation<CurveType> &lhs_G1,
                                                const g2_precomputation<CurveType> &lhs_G2,
                                                const g1_precomputation<CurveType> &rhs1_G1,
                                                const g2_precomputation<CurveType> &rhs1_G2,
                                                const g1_precomputation<CurveType> &rhs2_G1,
                                                const g2_precomputation<CurveType> &rhs2_G2,
                                                const blueprint_variable<field_type> &result) :
                        component<field_type>(bp),
                        lhs_G1(lhs_G1), lhs_G2(lhs_G2), rhs1_G1(rhs1_G1), rhs1_G2(rhs1_G2), rhs2_G1(rhs2_G1),
                        rhs2_G2(rhs2_G2), result(result) {
                        ratio.reset(new Fqk_variable_type(bp));
                        compute_ratio.reset(new mnt_e_times_e_over_e_miller_loop_component<CurveType>(
                            bp, rhs1_G1, rhs1_G2, rhs2_G1, rhs2_G2, lhs_G1, lhs_G2, *ratio));
                        check_finexp.reset(new final_exp_component<CurveType>(bp, *ratio, result));
                    }

                    void generate_r1cs_constraints() {
                        compute_ratio->generate_r1cs_constraints();
                        check_finexp->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        compute_ratio->generate_r1cs_witness();
                        check_finexp->generate_r1cs_witness();
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PAIRING_CHECKS_HPP
