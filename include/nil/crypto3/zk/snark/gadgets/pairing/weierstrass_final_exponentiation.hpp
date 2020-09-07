//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for final exponentiation gadgets.
//
// The gadgets verify final exponentiation for Weiersrass curves with embedding
// degrees 4 and 6.
//---------------------------------------------------------------------------//

#ifndef WEIERSTRASS_FINAL_EXPONENTIATION_HPP_
#define WEIERSTRASS_FINAL_EXPONENTIATION_HPP_

#include <memory>

#include <nil/crypto3/zk/snark/gadgets/fields/exponentiation_gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/pairing/mnt_pairing_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Gadget for final exponentiation with embedding degree 4.
                 */
                template<typename CurveType>
                class mnt4_final_exp_gadget : public gadget<typename CurveType::scalar_field_type> {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

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

                    std::shared_ptr<Fqk_mul_gadget<CurveType>> compute_el_inv;
                    std::shared_ptr<Fqk_mul_gadget<CurveType>> compute_el_q_3_minus_1;
                    std::shared_ptr<Fqk_mul_gadget<CurveType>> compute_beta;
                    std::shared_ptr<Fqk_mul_gadget<CurveType>> compute_el_inv_q_3_minus_1;
                    std::shared_ptr<Fqk_mul_gadget<CurveType>> compute_inv_beta;

                    std::shared_ptr<exponentiation_gadget<fqk_type<CurveType>,
                                                          Fp6_variable,
                                                          Fp6_mul_gadget,
                                                          Fp6_cyclotomic_sqr_gadget,
                                                          algebra::mnt6_q_limbs>>
                        compute_w1;
                    std::shared_ptr<exponentiation_gadget<fqk_type<CurveType>,
                                                          Fp6_variable,
                                                          Fp6_mul_gadget,
                                                          Fp6_cyclotomic_sqr_gadget,
                                                          algebra::mnt6_q_limbs>>
                        compute_w0;
                    std::shared_ptr<Fqk_mul_gadget<CurveType>> compute_result;

                    pb_variable<FieldType> result_is_one;

                    mnt4_final_exp_gadget(protoboard<FieldType> &pb,
                                          const Fqk_variable<CurveType> &el,
                                          const pb_variable<FieldType> &result_is_one);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                /**
                 * Gadget for final exponentiation with embedding degree 6.
                 */
                template<typename CurveType>
                class mnt6_final_exp_gadget : public gadget<typename CurveType::scalar_field_type> {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

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

                    std::shared_ptr<Fqk_mul_gadget<CurveType>> compute_el_inv;
                    std::shared_ptr<Fqk_mul_gadget<CurveType>> compute_el_q_2_minus_1;
                    std::shared_ptr<Fqk_mul_gadget<CurveType>> compute_el_inv_q_2_minus_1;

                    std::shared_ptr<exponentiation_gadget<fqk_type<CurveType>,
                                                          Fp4_variable,
                                                          Fp4_mul_gadget,
                                                          Fp4_cyclotomic_sqr_gadget,
                                                          algebra::mnt4_q_limbs>>
                        compute_w1;
                    std::shared_ptr<exponentiation_gadget<fqk_type<CurveType>,
                                                          Fp4_variable,
                                                          Fp4_mul_gadget,
                                                          Fp4_cyclotomic_sqr_gadget,
                                                          algebra::mnt4_q_limbs>>
                        compute_w0;
                    std::shared_ptr<Fqk_mul_gadget<CurveType>> compute_result;

                    pb_variable<FieldType> result_is_one;

                    mnt6_final_exp_gadget(protoboard<FieldType> &pb,
                                          const Fqk_variable<CurveType> &el,
                                          const pb_variable<FieldType> &result_is_one);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename CurveType>
                mnt4_final_exp_gadget<CurveType>::mnt4_final_exp_gadget(protoboard<FieldType> &pb,
                                                                  const Fqk_variable<CurveType> &el,
                                                                  const pb_variable<FieldType> &result_is_one) :
                    gadget<FieldType>(pb),
                    el(el), result_is_one(result_is_one) {
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

                    compute_el_inv.reset(new Fqk_mul_gadget<CurveType>(pb, el, *el_inv, *one));
                    compute_el_q_3_minus_1.reset(new Fqk_mul_gadget<CurveType>(pb, *el_q_3, *el_inv, *el_q_3_minus_1));
                    compute_beta.reset(new Fqk_mul_gadget<CurveType>(pb, *alpha, *el_q_3_minus_1, *beta));

                    compute_el_inv_q_3_minus_1.reset(new Fqk_mul_gadget<CurveType>(pb, *el_inv_q_3, el, *el_inv_q_3_minus_1));
                    compute_inv_beta.reset(new Fqk_mul_gadget<CurveType>(pb, *inv_alpha, *el_inv_q_3_minus_1, *inv_beta));

                    compute_w1.reset(new exponentiation_gadget<fqk_type<CurveType>,
                                                               Fp6_variable,
                                                               Fp6_mul_gadget,
                                                               Fp6_cyclotomic_sqr_gadget,
                                                               algebra::mnt6_q_limbs>(
                        pb, *beta_q, algebra::mnt6_final_exponent_last_chunk_w1, *w1));

                    compute_w0.reset(new exponentiation_gadget<fqk_type<CurveType>,
                                                               Fp6_variable,
                                                               Fp6_mul_gadget,
                                                               Fp6_cyclotomic_sqr_gadget,
                                                               algebra::mnt6_q_limbs>(
                        pb,
                        (algebra::mnt6_final_exponent_last_chunk_is_w0_neg ? *inv_beta : *beta),
                        algebra::mnt6_final_exponent_last_chunk_abs_of_w0,
                        *w0));

                    compute_result.reset(new Fqk_mul_gadget<CurveType>(pb, *w1, *w0, *result));
                }

                template<typename CurveType>
                void mnt4_final_exp_gadget<CurveType>::generate_r1cs_constraints() {
                    one->generate_r1cs_equals_const_constraints(algebra::Fqk<other_curve<CurveType>>::one());

                    compute_el_inv->generate_r1cs_constraints();
                    compute_el_q_3_minus_1->generate_r1cs_constraints();
                    compute_beta->generate_r1cs_constraints();

                    compute_el_inv_q_3_minus_1->generate_r1cs_constraints();
                    compute_inv_beta->generate_r1cs_constraints();

                    compute_w0->generate_r1cs_constraints();
                    compute_w1->generate_r1cs_constraints();
                    compute_result->generate_r1cs_constraints();

                    generate_boolean_r1cs_constraint<FieldType>(this->pb, result_is_one);
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(result_is_one, 1 - result->c0.c0, 0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(result_is_one, result->c0.c1, 0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(result_is_one, result->c0.c2, 0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(result_is_one, result->c1.c0, 0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(result_is_one, result->c1.c1, 0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(result_is_one, result->c1.c2, 0));
                }

                template<typename CurveType>
                void mnt4_final_exp_gadget<CurveType>::generate_r1cs_witness() {
                    one->generate_r1cs_witness(algebra::Fqk<other_curve<CurveType>>::one());
                    el_inv->generate_r1cs_witness(el.get_element().inverse());

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
                        (result->get_element() == one->get_element() ? FieldType::one() : FieldType::zero());
                }

                template<typename CurveType>
                mnt6_final_exp_gadget<CurveType>::mnt6_final_exp_gadget(protoboard<FieldType> &pb,
                                                                  const Fqk_variable<CurveType> &el,
                                                                  const pb_variable<FieldType> &result_is_one) :
                    gadget<FieldType>(pb),
                    el(el), result_is_one(result_is_one) {
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

                    compute_el_inv.reset(new Fqk_mul_gadget<CurveType>(pb, el, *el_inv, *one));
                    compute_el_q_2_minus_1.reset(new Fqk_mul_gadget<CurveType>(pb, *el_q_2, *el_inv, *el_q_2_minus_1));
                    compute_el_inv_q_2_minus_1.reset(new Fqk_mul_gadget<CurveType>(pb, *el_inv_q_2, el, *el_inv_q_2_minus_1));

                    compute_w1.reset(new exponentiation_gadget<fqk_type<CurveType>,
                                                               Fp4_variable,
                                                               Fp4_mul_gadget,
                                                               Fp4_cyclotomic_sqr_gadget,
                                                               algebra::mnt4_q_limbs>(
                        pb, *el_q_3_minus_q, algebra::mnt4_final_exponent_last_chunk_w1, *w1));
                    compute_w0.reset(new exponentiation_gadget<fqk_type<CurveType>,
                                                               Fp4_variable,
                                                               Fp4_mul_gadget,
                                                               Fp4_cyclotomic_sqr_gadget,
                                                               algebra::mnt4_q_limbs>(
                        pb,
                        (algebra::mnt4_final_exponent_last_chunk_is_w0_neg ? *el_inv_q_2_minus_1 : *el_q_2_minus_1),
                        algebra::mnt4_final_exponent_last_chunk_abs_of_w0,
                        *w0));
                    compute_result.reset(new Fqk_mul_gadget<CurveType>(pb, *w1, *w0, *result));
                }

                template<typename CurveType>
                void mnt6_final_exp_gadget<CurveType>::generate_r1cs_constraints() {
                    one->generate_r1cs_equals_const_constraints(algebra::Fqk<other_curve<CurveType>>::one());

                    compute_el_inv->generate_r1cs_constraints();
                    compute_el_q_2_minus_1->generate_r1cs_constraints();
                    compute_el_inv_q_2_minus_1->generate_r1cs_constraints();
                    compute_w1->generate_r1cs_constraints();
                    compute_w0->generate_r1cs_constraints();
                    compute_result->generate_r1cs_constraints();

                    generate_boolean_r1cs_constraint<FieldType>(this->pb, result_is_one);
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(result_is_one, 1 - result->c0.c0, 0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(result_is_one, result->c0.c1, 0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(result_is_one, result->c1.c0, 0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(result_is_one, result->c1.c1, 0));
                }

                template<typename CurveType>
                void mnt6_final_exp_gadget<CurveType>::generate_r1cs_witness() {
                    one->generate_r1cs_witness(algebra::Fqk<other_curve<CurveType>>::one());
                    el_inv->generate_r1cs_witness(el.get_element().inverse());

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
                        (result->get_element() == one->get_element() ? FieldType::one() : FieldType::zero());
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // WEIERSTRASS_FINAL_EXPONENTIATION_HPP_
