//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for pairing-check components.
//
// Given that e(.,.) denotes a pairing,
// - the component "check_e_equals_e_component" checks the equation "e(P1,Q1)=e(P2,Q2)"; and
// - the component "check_e_equals_ee_component" checks the equation "e(P1,Q1)=e(P2,Q2)*e(P3,Q3)".
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_PAIRING_CHECKS_HPP_
#define CRYPTO3_ZK_PAIRING_CHECKS_HPP_

#include <memory>

#include <nil/crypto3/zk/snark/components/pairing/pairing_params.hpp>
#include <nil/crypto3/zk/snark/components/pairing/weierstrass_final_exponentiation.hpp>
#include <nil/crypto3/zk/snark/components/pairing/weierstrass_miller_loop.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType>
                class check_e_equals_e_component : public component<typename CurveType::scalar_field_type> {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

                    std::shared_ptr<Fqk_variable<CurveType>> ratio;
                    std::shared_ptr<e_over_e_miller_loop_component<CurveType>> compute_ratio;
                    std::shared_ptr<final_exp_component<CurveType>> check_finexp;

                    G1_precomputation<CurveType> lhs_G1;
                    G2_precomputation<CurveType> lhs_G2;
                    G1_precomputation<CurveType> rhs_G1;
                    G2_precomputation<CurveType> rhs_G2;

                    variable<FieldType> result;

                    check_e_equals_e_component(blueprint<FieldType> &pb,
                                            const G1_precomputation<CurveType> &lhs_G1,
                                            const G2_precomputation<CurveType> &lhs_G2,
                                            const G1_precomputation<CurveType> &rhs_G1,
                                            const G2_precomputation<CurveType> &rhs_G2,
                                            const variable<FieldType> &result);

                    void generate_r1cs_constraints();

                    void generate_r1cs_witness();
                };

                template<typename CurveType>
                class check_e_equals_ee_component : public component<typename CurveType::scalar_field_type> {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

                    std::shared_ptr<Fqk_variable<CurveType>> ratio;
                    std::shared_ptr<e_times_e_over_e_miller_loop_component<CurveType>> compute_ratio;
                    std::shared_ptr<final_exp_component<CurveType>> check_finexp;

                    G1_precomputation<CurveType> lhs_G1;
                    G2_precomputation<CurveType> lhs_G2;
                    G1_precomputation<CurveType> rhs1_G1;
                    G2_precomputation<CurveType> rhs1_G2;
                    G1_precomputation<CurveType> rhs2_G1;
                    G2_precomputation<CurveType> rhs2_G2;

                    variable<FieldType> result;

                    check_e_equals_ee_component(blueprint<FieldType> &pb,
                                             const G1_precomputation<CurveType> &lhs_G1,
                                             const G2_precomputation<CurveType> &lhs_G2,
                                             const G1_precomputation<CurveType> &rhs1_G1,
                                             const G2_precomputation<CurveType> &rhs1_G2,
                                             const G1_precomputation<CurveType> &rhs2_G1,
                                             const G2_precomputation<CurveType> &rhs2_G2,
                                             const variable<FieldType> &result);

                    void generate_r1cs_constraints();

                    void generate_r1cs_witness();
                };
                template<typename CurveType>
                check_e_equals_e_component<CurveType>::check_e_equals_e_component(blueprint<FieldType> &pb,
                                                                      const G1_precomputation<CurveType> &lhs_G1,
                                                                      const G2_precomputation<CurveType> &lhs_G2,
                                                                      const G1_precomputation<CurveType> &rhs_G1,
                                                                      const G2_precomputation<CurveType> &rhs_G2,
                                                                      const variable<FieldType> &result) :
                    component<FieldType>(pb),
                    lhs_G1(lhs_G1), lhs_G2(lhs_G2), rhs_G1(rhs_G1), rhs_G2(rhs_G2), result(result) {
                    ratio.reset(new Fqk_variable<CurveType>(pb));
                    compute_ratio.reset(
                        new e_over_e_miller_loop_component<CurveType>(pb, lhs_G1, lhs_G2, rhs_G1, rhs_G2, *ratio));
                    check_finexp.reset(new final_exp_component<CurveType>(pb, *ratio, result));
                }

                template<typename CurveType>
                void check_e_equals_e_component<CurveType>::generate_r1cs_constraints() {
                    compute_ratio->generate_r1cs_constraints();
                    check_finexp->generate_r1cs_constraints();
                }

                template<typename CurveType>
                void check_e_equals_e_component<CurveType>::generate_r1cs_witness() {
                    compute_ratio->generate_r1cs_witness();
                    check_finexp->generate_r1cs_witness();
                }

                template<typename CurveType>
                check_e_equals_ee_component<CurveType>::check_e_equals_ee_component(
                    blueprint<FieldType> &pb,
                                                                        const G1_precomputation<CurveType> &lhs_G1,
                                                                        const G2_precomputation<CurveType> &lhs_G2,
                                                                        const G1_precomputation<CurveType> &rhs1_G1,
                                                                        const G2_precomputation<CurveType> &rhs1_G2,
                                                                        const G1_precomputation<CurveType> &rhs2_G1,
                                                                        const G2_precomputation<CurveType> &rhs2_G2,
                                                                        const variable<FieldType> &result) :
                    component<FieldType>(pb),
                    lhs_G1(lhs_G1), lhs_G2(lhs_G2), rhs1_G1(rhs1_G1), rhs1_G2(rhs1_G2), rhs2_G1(rhs2_G1),
                    rhs2_G2(rhs2_G2), result(result) {
                    ratio.reset(new Fqk_variable<CurveType>(pb));
                    compute_ratio.reset(new e_times_e_over_e_miller_loop_component<CurveType>(
                        pb, rhs1_G1, rhs1_G2, rhs2_G1, rhs2_G2, lhs_G1, lhs_G2, *ratio));
                    check_finexp.reset(new final_exp_component<CurveType>(pb, *ratio, result));
                }

                template<typename CurveType>
                void check_e_equals_ee_component<CurveType>::generate_r1cs_constraints() {
                    compute_ratio->generate_r1cs_constraints();
                    check_finexp->generate_r1cs_constraints();
                }

                template<typename CurveType>
                void check_e_equals_ee_component<CurveType>::generate_r1cs_witness() {
                    compute_ratio->generate_r1cs_witness();
                    check_finexp->generate_r1cs_witness();
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // PAIRING_CHECKS_HPP_
