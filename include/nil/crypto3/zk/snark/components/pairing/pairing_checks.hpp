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

#ifndef CRYPTO3_ZK_PAIRING_CHECKS_HPP
#define CRYPTO3_ZK_PAIRING_CHECKS_HPP

#include <memory>

#include <nil/crypto3/zk/snark/components/pairing/pairing_params.hpp>
#include <nil/crypto3/zk/snark/components/pairing/weierstrass_final_exponentiation.hpp>
#include <nil/crypto3/zk/snark/components/pairing/weierstrass_miller_loop.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType>
                struct check_e_equals_e_component : public component<typename CurveType::scalar_field_type> {
                
                    using field_type = typename CurveType::scalar_field_type;

                    std::shared_ptr<Fqk_variable<CurveType>> ratio;
                    std::shared_ptr<e_over_e_miller_loop_component<CurveType>> compute_ratio;
                    std::shared_ptr<final_exp_component<CurveType>> check_finexp;

                    G1_precomputation<CurveType> lhs_G1;
                    G2_precomputation<CurveType> lhs_G2;
                    G1_precomputation<CurveType> rhs_G1;
                    G2_precomputation<CurveType> rhs_G2;

                    variable<field_type> result;

                    check_e_equals_e_component(blueprint<field_type> &pb,
                                            const G1_precomputation<CurveType> &lhs_G1,
                                            const G2_precomputation<CurveType> &lhs_G2,
                                            const G1_precomputation<CurveType> &rhs_G1,
                                            const G2_precomputation<CurveType> &rhs_G2,
                                            const variable<field_type> &result) :
                        component<field_type>(pb),
                        lhs_G1(lhs_G1), lhs_G2(lhs_G2), rhs_G1(rhs_G1), rhs_G2(rhs_G2), result(result) {
                        ratio.reset(new Fqk_variable<CurveType>(pb));
                        compute_ratio.reset(
                            new e_over_e_miller_loop_component<CurveType>(pb, lhs_G1, lhs_G2, rhs_G1, rhs_G2, *ratio));
                        check_finexp.reset(new final_exp_component<CurveType>(pb, *ratio, result));
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
                struct check_e_equals_ee_component : public component<typename CurveType::scalar_field_type> {
                
                    using field_type = typename CurveType::scalar_field_type;

                    std::shared_ptr<Fqk_variable<CurveType>> ratio;
                    std::shared_ptr<e_times_e_over_e_miller_loop_component<CurveType>> compute_ratio;
                    std::shared_ptr<final_exp_component<CurveType>> check_finexp;

                    G1_precomputation<CurveType> lhs_G1;
                    G2_precomputation<CurveType> lhs_G2;
                    G1_precomputation<CurveType> rhs1_G1;
                    G2_precomputation<CurveType> rhs1_G2;
                    G1_precomputation<CurveType> rhs2_G1;
                    G2_precomputation<CurveType> rhs2_G2;

                    variable<field_type> result;

                    check_e_equals_ee_component(blueprint<field_type> &pb,
                                             const G1_precomputation<CurveType> &lhs_G1,
                                             const G2_precomputation<CurveType> &lhs_G2,
                                             const G1_precomputation<CurveType> &rhs1_G1,
                                             const G2_precomputation<CurveType> &rhs1_G2,
                                             const G1_precomputation<CurveType> &rhs2_G1,
                                             const G2_precomputation<CurveType> &rhs2_G2,
                                             const variable<field_type> &result) :
                        component<field_type>(pb),
                        lhs_G1(lhs_G1), lhs_G2(lhs_G2), rhs1_G1(rhs1_G1), rhs1_G2(rhs1_G2), rhs2_G1(rhs2_G1),
                        rhs2_G2(rhs2_G2), result(result) {
                        ratio.reset(new Fqk_variable<CurveType>(pb));
                        compute_ratio.reset(new e_times_e_over_e_miller_loop_component<CurveType>(
                            pb, rhs1_G1, rhs1_G2, rhs2_G1, rhs2_G2, lhs_G1, lhs_G2, *ratio));
                        check_finexp.reset(new final_exp_component<CurveType>(pb, *ratio, result));
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

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PAIRING_CHECKS_HPP
