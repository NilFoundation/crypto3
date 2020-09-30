//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for final exponentiation components.
//
// The components verify final exponentiation for Weiersrass curves with embedding
// degrees 4 and 6.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_WEIERSTRASS_FINAL_EXPONENTIATION_HPP
#define CRYPTO3_ZK_WEIERSTRASS_FINAL_EXPONENTIATION_HPP

#include <memory>

#include <nil/crypto3/zk/snark/components/fields/exponentiation_component.hpp>
#include <nil/crypto3/zk/snark/components/pairing/mnt_pairing_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Gadget for final exponentiation with embedding degree 4.
                 */
                template<typename CurveType>
                struct mnt4_final_exp_component : public component<typename CurveType::scalar_field_type> {

                    using field_type = typename CurveType::scalar_field_type;

                    Fqk_variable<CurveType> el;
                    std::shared_ptr<Fqk_variable<CurveType>> one;
                    std::shared_ptr<Fqk_variable<CurveType>> el_inv;
                    std::shared_ptr<Fqk_variable<CurveType>> el_q_3;
                    std::shared_ptr<Fqk_variable<CurveType>> el_q_3_minus_1;
                    std::shared_ptr<Fqk_variable<CurveType>> alpha;
                    std::shared_ptr<Fqk_variable<CurveType>> beta;
                    std::shared_ptr<Fqk_variable<CurveType>> beta_q;
                    std::shared_ptr<Fqk_variable<CurveType>> el_inv_q_3;
                    std::shared_ptr<Fqk_variable<CurveType>> el_inv_q_3_minus_1;
                    std::shared_ptr<Fqk_variable<CurveType>> inv_alpha;
                    std::shared_ptr<Fqk_variable<CurveType>> inv_beta;
                    std::shared_ptr<Fqk_variable<CurveType>> w1;
                    std::shared_ptr<Fqk_variable<CurveType>> w0;
                    std::shared_ptr<Fqk_variable<CurveType>> result;

                    std::shared_ptr<Fqk_mul_component<CurveType>> compute_el_inv;
                    std::shared_ptr<Fqk_mul_component<CurveType>> compute_el_q_3_minus_1;
                    std::shared_ptr<Fqk_mul_component<CurveType>> compute_beta;
                    std::shared_ptr<Fqk_mul_component<CurveType>> compute_el_inv_q_3_minus_1;
                    std::shared_ptr<Fqk_mul_component<CurveType>> compute_inv_beta;

                    std::shared_ptr<exponentiation_component<CurveType>::pairing_policy::Fqk_type,
                                                          Fp6_variable,
                                                          Fp6_mul_component,
                                                          Fp6_cyclotomic_sqr_component,
                                                          algebra::mnt6_q_limbs>>
                        compute_w1;
                    std::shared_ptr<exponentiation_component<CurveType>::pairing_policy::Fqk_type,
                                                          Fp6_variable,
                                                          Fp6_mul_component,
                                                          Fp6_cyclotomic_sqr_component,
                                                          algebra::mnt6_q_limbs>>
                        compute_w0;
                    std::shared_ptr<Fqk_mul_component<CurveType>> compute_result;

                    variable<field_type> result_is_one;

                    mnt4_final_exp_component(blueprint<field_type> &pb,
                                          const Fqk_variable<CurveType> &el,
                                          const variable<field_type> &result_is_one) :
                                          component<field_type>(pb), el(el), 
                                          result_is_one(result_is_one) {
                        one.reset(new Fqk_variable<CurveType>(pb));
                        el_inv.reset(new Fqk_variable<CurveType>(pb));
                        el_q_3.reset(new Fqk_variable<CurveType>(el.Frobenius_map(3)));
                        el_q_3_minus_1.reset(new Fqk_variable<CurveType>(pb));
                        alpha.reset(new Fqk_variable<CurveType>(el_q_3_minus_1->Frobenius_map(1)));
                        beta.reset(new Fqk_variable<CurveType>(pb));
                        beta_q.reset(new Fqk_variable<CurveType>(beta->Frobenius_map(1)));

                        el_inv_q_3.reset(new Fqk_variable<CurveType>(el_inv->Frobenius_map(3)));
                        el_inv_q_3_minus_1.reset(new Fqk_variable<CurveType>(pb));
                        inv_alpha.reset(new Fqk_variable<CurveType>(el_inv_q_3_minus_1->Frobenius_map(1)));
                        inv_beta.reset(new Fqk_variable<CurveType>(pb));
                        w1.reset(new Fqk_variable<CurveType>(pb));
                        w0.reset(new Fqk_variable<CurveType>(pb));
                        result.reset(new Fqk_variable<CurveType>(pb));

                        compute_el_inv.reset(new Fqk_mul_component<CurveType>(pb, el, *el_inv, *one));
                        compute_el_q_3_minus_1.reset(new Fqk_mul_component<CurveType>(pb, *el_q_3, *el_inv, *el_q_3_minus_1));
                        compute_beta.reset(new Fqk_mul_component<CurveType>(pb, *alpha, *el_q_3_minus_1, *beta));

                        compute_el_inv_q_3_minus_1.reset(new Fqk_mul_component<CurveType>(pb, *el_inv_q_3, el, *el_inv_q_3_minus_1));
                        compute_inv_beta.reset(new Fqk_mul_component<CurveType>(pb, *inv_alpha, *el_inv_q_3_minus_1, *inv_beta));

                        compute_w1.reset(new exponentiation_component<CurveType>::pairing_policy::Fqk_type,
                                                                   Fp6_variable,
                                                                   Fp6_mul_component,
                                                                   Fp6_cyclotomic_sqr_component,
                                                                   algebra::mnt6_q_limbs>(
                            pb, *beta_q, algebra::mnt6_final_exponent_last_chunk_w1, *w1));

                        compute_w0.reset(new exponentiation_component<CurveType>::pairing_policy::Fqk_type,
                                                                   Fp6_variable,
                                                                   Fp6_mul_component,
                                                                   Fp6_cyclotomic_sqr_component,
                                                                   algebra::mnt6_q_limbs>(
                            pb,
                            (algebra::mnt6_final_exponent_last_chunk_is_w0_neg ? *inv_beta : *beta),
                            algebra::mnt6_final_exponent_last_chunk_abs_of_w0,
                            *w0));

                        compute_result.reset(new Fqk_mul_component<CurveType>(pb, *w1, *w0, *result));
                    }

                    void generate_r1cs_constraints() {
                        one->generate_r1cs_equals_const_constraints(other_curve<CurveType>::pairing_policy::Fqk_type::value_type::one());

                        compute_el_inv->generate_r1cs_constraints();
                        compute_el_q_3_minus_1->generate_r1cs_constraints();
                        compute_beta->generate_r1cs_constraints();

                        compute_el_inv_q_3_minus_1->generate_r1cs_constraints();
                        compute_inv_beta->generate_r1cs_constraints();

                        compute_w0->generate_r1cs_constraints();
                        compute_w1->generate_r1cs_constraints();
                        compute_result->generate_r1cs_constraints();

                        generate_boolean_r1cs_constraint<field_type>(this->pb, result_is_one);
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(result_is_one, 1 - result->c0.c0, 0));
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(result_is_one, result->c0.c1, 0));
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(result_is_one, result->c0.c2, 0));
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(result_is_one, result->c1.c0, 0));
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(result_is_one, result->c1.c1, 0));
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(result_is_one, result->c1.c2, 0));
                    }
                    
                    void generate_r1cs_witness() {
                        one->generate_r1cs_witness(other_curve<CurveType>::pairing_policy::Fqk_type::value_type::one());
                        el_inv->generate_r1cs_witness(el.get_element().inversed());

                        compute_el_inv->generate_r1cs_witness();
                        el_q_3->evaluate();
                        compute_el_q_3_minus_1->generate_r1cs_witness();
                        alpha->evaluate();
                        compute_beta->generate_r1cs_witness();
                        beta_q->evaluate();

                        el_inv_q_3->evaluate();
                        compute_el_inv_q_3_minus_1->generate_r1cs_witness();
                        inv_alpha->evaluate();
                        compute_inv_beta->generate_r1cs_witness();

                        compute_w0->generate_r1cs_witness();
                        compute_w1->generate_r1cs_witness();
                        compute_result->generate_r1cs_witness();

                        this->pb.val(result_is_one) =
                            (result->get_element() == one->get_element() ? field_type::value_type::zero() : field_type::value_type::zero());
                    }
                };

                /**
                 * Gadget for final exponentiation with embedding degree 6.
                 */
                template<typename CurveType>
                struct mnt6_final_exp_component : public component<typename CurveType::scalar_field_type> {
                
                    using field_type = typename CurveType::scalar_field_type;

                    Fqk_variable<CurveType> el;
                    std::shared_ptr<Fqk_variable<CurveType>> one;
                    std::shared_ptr<Fqk_variable<CurveType>> el_inv;
                    std::shared_ptr<Fqk_variable<CurveType>> el_q_2;
                    std::shared_ptr<Fqk_variable<CurveType>> el_q_2_minus_1;
                    std::shared_ptr<Fqk_variable<CurveType>> el_q_3_minus_q;
                    std::shared_ptr<Fqk_variable<CurveType>> el_inv_q_2;
                    std::shared_ptr<Fqk_variable<CurveType>> el_inv_q_2_minus_1;
                    std::shared_ptr<Fqk_variable<CurveType>> w1;
                    std::shared_ptr<Fqk_variable<CurveType>> w0;
                    std::shared_ptr<Fqk_variable<CurveType>> result;

                    std::shared_ptr<Fqk_mul_component<CurveType>> compute_el_inv;
                    std::shared_ptr<Fqk_mul_component<CurveType>> compute_el_q_2_minus_1;
                    std::shared_ptr<Fqk_mul_component<CurveType>> compute_el_inv_q_2_minus_1;

                    std::shared_ptr<exponentiation_component<CurveType>::pairing_policy::Fqk_type,
                                                          Fp4_variable,
                                                          Fp4_mul_component,
                                                          Fp4_cyclotomic_sqr_component,
                                                          algebra::mnt4_q_limbs>>
                        compute_w1;
                    std::shared_ptr<exponentiation_component<CurveType>::pairing_policy::Fqk_type,
                                                          Fp4_variable,
                                                          Fp4_mul_component,
                                                          Fp4_cyclotomic_sqr_component,
                                                          algebra::mnt4_q_limbs>>
                        compute_w0;
                    std::shared_ptr<Fqk_mul_component<CurveType>> compute_result;

                    variable<field_type> result_is_one;

                    mnt6_final_exp_component(blueprint<field_type> &pb,
                                          const Fqk_variable<CurveType> &el,
                                          const variable<field_type> &result_is_one) :
                                          component<field_type>(pb), el(el), 
                                          result_is_one(result_is_one) 
                    {
                        one.reset(new Fqk_variable<CurveType>(pb));
                        el_inv.reset(new Fqk_variable<CurveType>(pb));
                        el_q_2.reset(new Fqk_variable<CurveType>(el.Frobenius_map(2)));
                        el_q_2_minus_1.reset(new Fqk_variable<CurveType>(pb));
                        el_q_3_minus_q.reset(new Fqk_variable<CurveType>(el_q_2_minus_1->Frobenius_map(1)));
                        el_inv_q_2.reset(new Fqk_variable<CurveType>(el_inv->Frobenius_map(2)));
                        el_inv_q_2_minus_1.reset(new Fqk_variable<CurveType>(pb));
                        w1.reset(new Fqk_variable<CurveType>(pb));
                        w0.reset(new Fqk_variable<CurveType>(pb));
                        result.reset(new Fqk_variable<CurveType>(pb));

                        compute_el_inv.reset(new Fqk_mul_component<CurveType>(pb, el, *el_inv, *one));
                        compute_el_q_2_minus_1.reset(new Fqk_mul_component<CurveType>(pb, *el_q_2, *el_inv, *el_q_2_minus_1));
                        compute_el_inv_q_2_minus_1.reset(new Fqk_mul_component<CurveType>(pb, *el_inv_q_2, el, *el_inv_q_2_minus_1));

                        compute_w1.reset(new exponentiation_component<CurveType>::pairing_policy::Fqk_type,
                                                                   Fp4_variable,
                                                                   Fp4_mul_component,
                                                                   Fp4_cyclotomic_sqr_component,
                                                                   algebra::mnt4_q_limbs>(
                            pb, *el_q_3_minus_q, algebra::mnt4_final_exponent_last_chunk_w1, *w1));
                        compute_w0.reset(new exponentiation_component<CurveType>::pairing_policy::Fqk_type,
                                                                   Fp4_variable,
                                                                   Fp4_mul_component,
                                                                   Fp4_cyclotomic_sqr_component,
                                                                   algebra::mnt4_q_limbs>(
                            pb,
                            (algebra::mnt4_final_exponent_last_chunk_is_w0_neg ? *el_inv_q_2_minus_1 : *el_q_2_minus_1),
                            algebra::mnt4_final_exponent_last_chunk_abs_of_w0,
                            *w0));
                        compute_result.reset(new Fqk_mul_component<CurveType>(pb, *w1, *w0, *result));
                    }

                    void generate_r1cs_constraints() {
                        one->generate_r1cs_equals_const_constraints(other_curve<CurveType>::pairing_policy::Fqk_type::value_type::one());

                        compute_el_inv->generate_r1cs_constraints();
                        compute_el_q_2_minus_1->generate_r1cs_constraints();
                        compute_el_inv_q_2_minus_1->generate_r1cs_constraints();
                        compute_w1->generate_r1cs_constraints();
                        compute_w0->generate_r1cs_constraints();
                        compute_result->generate_r1cs_constraints();

                        generate_boolean_r1cs_constraint<field_type>(this->pb, result_is_one);
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(result_is_one, 1 - result->c0.c0, 0));
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(result_is_one, result->c0.c1, 0));
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(result_is_one, result->c1.c0, 0));
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(result_is_one, result->c1.c1, 0));
                    }

                    void generate_r1cs_witness() {
                        one->generate_r1cs_witness(other_curve<CurveType>::pairing_policy::Fqk_type::value_type::one());
                        el_inv->generate_r1cs_witness(el.get_element().inversed());

                        compute_el_inv->generate_r1cs_witness();
                        el_q_2->evaluate();
                        compute_el_q_2_minus_1->generate_r1cs_witness();
                        el_q_3_minus_q->evaluate();
                        el_inv_q_2->evaluate();
                        compute_el_inv_q_2_minus_1->generate_r1cs_witness();
                        compute_w1->generate_r1cs_witness();
                        compute_w0->generate_r1cs_witness();
                        compute_result->generate_r1cs_witness();

                        this->pb.val(result_is_one) =
                            (result->get_element() == one->get_element() ? field_type::value_type::zero() : field_type::value_type::zero());
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_WEIERSTRASS_FINAL_EXPONENTIATION_HPP
