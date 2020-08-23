//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for pairing-check gadgets.
//
// Given that e(.,.) denotes a pairing,
// - the gadget "check_e_equals_e_gadget" checks the equation "e(P1,Q1)=e(P2,Q2)"; and
// - the gadget "check_e_equals_ee_gadget" checks the equation "e(P1,Q1)=e(P2,Q2)*e(P3,Q3)".
//---------------------------------------------------------------------------//

#ifndef PAIRING_CHECKS_HPP_
#define PAIRING_CHECKS_HPP_

#include <memory>

#include <nil/crypto3/zk/snark/gadgets/pairing/pairing_params.hpp>
#include <nil/crypto3/zk/snark/gadgets/pairing/weierstrass_final_exponentiation.hpp>
#include <nil/crypto3/zk/snark/gadgets/pairing/weierstrass_miller_loop.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType>
                class check_e_equals_e_gadget : public gadget<typename CurveType::scalar_field_type> {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

                    std::shared_ptr<Fqk_variable<CurveType>> ratio;
                    std::shared_ptr<e_over_e_miller_loop_gadget<CurveType>> compute_ratio;
                    std::shared_ptr<final_exp_gadget<CurveType>> check_finexp;

                    G1_precomputation<CurveType> lhs_G1;
                    G2_precomputation<CurveType> lhs_G2;
                    G1_precomputation<CurveType> rhs_G1;
                    G2_precomputation<CurveType> rhs_G2;

                    pb_variable<FieldType> result;

                    check_e_equals_e_gadget(protoboard<FieldType> &pb,
                                            const G1_precomputation<CurveType> &lhs_G1,
                                            const G2_precomputation<CurveType> &lhs_G2,
                                            const G1_precomputation<CurveType> &rhs_G1,
                                            const G2_precomputation<CurveType> &rhs_G2,
                                            const pb_variable<FieldType> &result);

                    void generate_r1cs_constraints();

                    void generate_r1cs_witness();
                };

                template<typename CurveType>
                class check_e_equals_ee_gadget : public gadget<typename CurveType::scalar_field_type> {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

                    std::shared_ptr<Fqk_variable<CurveType>> ratio;
                    std::shared_ptr<e_times_e_over_e_miller_loop_gadget<CurveType>> compute_ratio;
                    std::shared_ptr<final_exp_gadget<CurveType>> check_finexp;

                    G1_precomputation<CurveType> lhs_G1;
                    G2_precomputation<CurveType> lhs_G2;
                    G1_precomputation<CurveType> rhs1_G1;
                    G2_precomputation<CurveType> rhs1_G2;
                    G1_precomputation<CurveType> rhs2_G1;
                    G2_precomputation<CurveType> rhs2_G2;

                    pb_variable<FieldType> result;

                    check_e_equals_ee_gadget(protoboard<FieldType> &pb,
                                             const G1_precomputation<CurveType> &lhs_G1,
                                             const G2_precomputation<CurveType> &lhs_G2,
                                             const G1_precomputation<CurveType> &rhs1_G1,
                                             const G2_precomputation<CurveType> &rhs1_G2,
                                             const G1_precomputation<CurveType> &rhs2_G1,
                                             const G2_precomputation<CurveType> &rhs2_G2,
                                             const pb_variable<FieldType> &result);

                    void generate_r1cs_constraints();

                    void generate_r1cs_witness();
                };
                template<typename CurveType>
                check_e_equals_e_gadget<CurveType>::check_e_equals_e_gadget(protoboard<FieldType> &pb,
                                                                      const G1_precomputation<CurveType> &lhs_G1,
                                                                      const G2_precomputation<CurveType> &lhs_G2,
                                                                      const G1_precomputation<CurveType> &rhs_G1,
                                                                      const G2_precomputation<CurveType> &rhs_G2,
                                                                      const pb_variable<FieldType> &result) :
                    gadget<FieldType>(pb),
                    lhs_G1(lhs_G1), lhs_G2(lhs_G2), rhs_G1(rhs_G1), rhs_G2(rhs_G2), result(result) {
                    ratio.reset(new Fqk_variable<CurveType>(pb));
                    compute_ratio.reset(
                        new e_over_e_miller_loop_gadget<CurveType>(pb, lhs_G1, lhs_G2, rhs_G1, rhs_G2, *ratio));
                    check_finexp.reset(new final_exp_gadget<CurveType>(pb, *ratio, result));
                }

                template<typename CurveType>
                void check_e_equals_e_gadget<CurveType>::generate_r1cs_constraints() {
                    compute_ratio->generate_r1cs_constraints();
                    check_finexp->generate_r1cs_constraints();
                }

                template<typename CurveType>
                void check_e_equals_e_gadget<CurveType>::generate_r1cs_witness() {
                    compute_ratio->generate_r1cs_witness();
                    check_finexp->generate_r1cs_witness();
                }

                template<typename CurveType>
                check_e_equals_ee_gadget<CurveType>::check_e_equals_ee_gadget(protoboard<FieldType> &pb,
                                                                        const G1_precomputation<CurveType> &lhs_G1,
                                                                        const G2_precomputation<CurveType> &lhs_G2,
                                                                        const G1_precomputation<CurveType> &rhs1_G1,
                                                                        const G2_precomputation<CurveType> &rhs1_G2,
                                                                        const G1_precomputation<CurveType> &rhs2_G1,
                                                                        const G2_precomputation<CurveType> &rhs2_G2,
                                                                        const pb_variable<FieldType> &result) :
                    gadget<FieldType>(pb),
                    lhs_G1(lhs_G1), lhs_G2(lhs_G2), rhs1_G1(rhs1_G1), rhs1_G2(rhs1_G2), rhs2_G1(rhs2_G1),
                    rhs2_G2(rhs2_G2), result(result) {
                    ratio.reset(new Fqk_variable<CurveType>(pb));
                    compute_ratio.reset(new e_times_e_over_e_miller_loop_gadget<CurveType>(
                        pb, rhs1_G1, rhs1_G2, rhs2_G1, rhs2_G2, lhs_G1, lhs_G2, *ratio));
                    check_finexp.reset(new final_exp_gadget<CurveType>(pb, *ratio, result));
                }

                template<typename CurveType>
                void check_e_equals_ee_gadget<CurveType>::generate_r1cs_constraints() {
                    compute_ratio->generate_r1cs_constraints();
                    check_finexp->generate_r1cs_constraints();
                }

                template<typename CurveType>
                void check_e_equals_ee_gadget<CurveType>::generate_r1cs_witness() {
                    compute_ratio->generate_r1cs_witness();
                    check_finexp->generate_r1cs_witness();
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // PAIRING_CHECKS_HPP_
