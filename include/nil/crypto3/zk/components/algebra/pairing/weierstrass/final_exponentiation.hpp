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
// @file Declaration of interfaces for final exponentiation components.
//
// The components verify final exponentiation for Weiersrass curves with embedding
// degrees 4 and 6.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_WEIERSTRASS_FINAL_EXPONENTIATION_HPP
#define CRYPTO3_ZK_BLUEPRINT_WEIERSTRASS_FINAL_EXPONENTIATION_HPP

#include <memory>

#include <nil/crypto3/algebra/algorithms/pair.hpp>

#include <nil/crypto3/zk/components/packing.hpp>
#include <nil/crypto3/zk/components/algebra/fields/exponentiation.hpp>
#include <nil/crypto3/zk/components/algebra/pairing/detail/mnt4.hpp>
#include <nil/crypto3/zk/components/algebra/pairing/detail/mnt6.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                /**
                 * Component for final exponentiation with embedding degree 4.
                 */
                template<typename CurveType>
                struct final_exp_component;

                template<std::size_t Version>
                class final_exp_component<curves::mnt4<Version>>
                    : public component<typename curves::mnt4<Version>::scalar_field_type> {

                    using curve_type = curves::mnt4<Version>;

                    using Fqk_variable_type =
                        typename detail::basic_pairing_component_policy<curve_type>::Fqk_variable_type;
                    using Fqk_mul_component_type =
                        typename detail::basic_pairing_component_policy<curve_type>::Fqk_mul_component_type;

                public:
                    typedef typename curve_type::scalar_field_type field_type;

                    Fqk_variable_type el;
                    std::shared_ptr<Fqk_variable_type> one;
                    std::shared_ptr<Fqk_variable_type> el_inv;
                    std::shared_ptr<Fqk_variable_type> el_q_3;
                    std::shared_ptr<Fqk_variable_type> el_q_3_minus_1;
                    std::shared_ptr<Fqk_variable_type> alpha;
                    std::shared_ptr<Fqk_variable_type> beta;
                    std::shared_ptr<Fqk_variable_type> beta_q;
                    std::shared_ptr<Fqk_variable_type> el_inv_q_3;
                    std::shared_ptr<Fqk_variable_type> el_inv_q_3_minus_1;
                    std::shared_ptr<Fqk_variable_type> inv_alpha;
                    std::shared_ptr<Fqk_variable_type> inv_beta;
                    std::shared_ptr<Fqk_variable_type> w1;
                    std::shared_ptr<Fqk_variable_type> w0;
                    std::shared_ptr<Fqk_variable_type> result;

                    std::shared_ptr<Fqk_mul_component_type> compute_el_inv;
                    std::shared_ptr<Fqk_mul_component_type> compute_el_q_3_minus_1;
                    std::shared_ptr<Fqk_mul_component_type> compute_beta;
                    std::shared_ptr<Fqk_mul_component_type> compute_el_inv_q_3_minus_1;
                    std::shared_ptr<Fqk_mul_component_type> compute_inv_beta;

                    using exponentiation_component_type =
                        exponentiation_component<typename curve_type::pairing::fqk_type,
                                                 element_fp6_2over3,
                                                 element_fp6_2over3_mul,
                                                 element_fp6_2over3_cyclotomic_squared>;

                    std::shared_ptr<exponentiation_component_type> compute_w1;
                    std::shared_ptr<exponentiation_component<typename curve_type::pairing::fqk_type,
                                                             element_fp6_2over3,
                                                             element_fp6_2over3_mul,
                                                             element_fp6_2over3_cyclotomic_squared>>
                        compute_w0;
                    std::shared_ptr<Fqk_mul_component_type> compute_result;

                    blueprint_variable<field_type> result_is_one;

                    final_exp_component(blueprint<field_type> &bp,
                                        const Fqk_variable_type &el,
                                        const blueprint_variable<field_type> &result_is_one) :
                        component<field_type>(bp),
                        el(el), result_is_one(result_is_one) {
                        one.reset(new Fqk_variable_type(bp));
                        el_inv.reset(new Fqk_variable_type(bp));
                        el_q_3.reset(new Fqk_variable_type(el.Frobenius_map(3)));
                        el_q_3_minus_1.reset(new Fqk_variable_type(bp));
                        alpha.reset(new Fqk_variable_type(el_q_3_minus_1->Frobenius_map(1)));
                        beta.reset(new Fqk_variable_type(bp));
                        beta_q.reset(new Fqk_variable_type(beta->Frobenius_map(1)));

                        el_inv_q_3.reset(new Fqk_variable_type(el_inv->Frobenius_map(3)));
                        el_inv_q_3_minus_1.reset(new Fqk_variable_type(bp));
                        inv_alpha.reset(new Fqk_variable_type(el_inv_q_3_minus_1->Frobenius_map(1)));
                        inv_beta.reset(new Fqk_variable_type(bp));
                        w1.reset(new Fqk_variable_type(bp));
                        w0.reset(new Fqk_variable_type(bp));
                        result.reset(new Fqk_variable_type(bp));

                        compute_el_inv.reset(new Fqk_mul_component_type(bp, el, *el_inv, *one));
                        compute_el_q_3_minus_1.reset(new Fqk_mul_component_type(bp, *el_q_3, *el_inv, *el_q_3_minus_1));
                        compute_beta.reset(new Fqk_mul_component_type(bp, *alpha, *el_q_3_minus_1, *beta));

                        compute_el_inv_q_3_minus_1.reset(
                            new Fqk_mul_component_type(bp, *el_inv_q_3, el, *el_inv_q_3_minus_1));
                        compute_inv_beta.reset(
                            new Fqk_mul_component_type(bp, *inv_alpha, *el_inv_q_3_minus_1, *inv_beta));

                        compute_w1.reset(new exponentiation_component<typename curve_type::pairing::fqk_type,
                                                                      element_fp6_2over3,
                                                                      element_fp6_2over3_mul,
                                                                      element_fp6_2over3_cyclotomic_squared>(
                            bp, *beta_q, curve_type::pairing::final_exponent_last_chunk_w1, *w1));

                        compute_w0.reset(new exponentiation_component<typename curve_type::pairing::fqk_type,
                                                                      element_fp6_2over3,
                                                                      element_fp6_2over3_mul,
                                                                      element_fp6_2over3_cyclotomic_squared>(
                            bp,
                            (curve_type::pairing::final_exponent_last_chunk_is_w0_neg ? *inv_beta : *beta),
                            curve_type::pairing::final_exponent_last_chunk_abs_of_w0,
                            *w0));

                        compute_result.reset(new Fqk_mul_component_type(bp, *w1, *w0, *result));
                    }

                    void generate_r1cs_constraints() {
                        one->generate_r1cs_equals_const_constraints(
                            curve_type::pairing::pair_curve_type::pairing::fqk_type::value_type::one());

                        compute_el_inv->generate_r1cs_constraints();
                        compute_el_q_3_minus_1->generate_r1cs_constraints();
                        compute_beta->generate_r1cs_constraints();

                        compute_el_inv_q_3_minus_1->generate_r1cs_constraints();
                        compute_inv_beta->generate_r1cs_constraints();

                        compute_w0->generate_r1cs_constraints();
                        compute_w1->generate_r1cs_constraints();
                        compute_result->generate_r1cs_constraints();

                        generate_boolean_r1cs_constraint<field_type>(this->bp, result_is_one);
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(result_is_one, 1 - result->c0.c0, 0));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(result_is_one, result->c0.c1, 0));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(result_is_one, result->c0.c2, 0));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(result_is_one, result->c1.c0, 0));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(result_is_one, result->c1.c1, 0));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(result_is_one, result->c1.c2, 0));
                    }

                    void generate_r1cs_witness() {
                        one->generate_r1cs_witness(
                            curve_type::pairing::pair_curve_type::pairing::fqk_type::value_type::one());
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

                        this->bp.val(result_is_one) =
                            (result->get_element() == one->get_element() ? field_type::value_type::one() :
                                                                           field_type::value_type::zero());
                    }
                };

                /**
                 * Component for final exponentiation with embedding degree 6.
                 */
                template<std::size_t Version>
                class final_exp_component<curves::mnt6<Version>>
                    : public component<typename curves::mnt6<Version>::scalar_field_type> {

                    using curve_type = curves::mnt6<Version>;

                    using Fqk_variable_type =
                        typename detail::basic_pairing_component_policy<curve_type>::Fqk_variable_type;
                    using Fqk_mul_component_type =
                        typename detail::basic_pairing_component_policy<curve_type>::Fqk_mul_component_type;

                public:
                    typedef typename curve_type::scalar_field_type field_type;

                    Fqk_variable_type el;
                    std::shared_ptr<Fqk_variable_type> one;
                    std::shared_ptr<Fqk_variable_type> el_inv;
                    std::shared_ptr<Fqk_variable_type> el_q_2;
                    std::shared_ptr<Fqk_variable_type> el_q_2_minus_1;
                    std::shared_ptr<Fqk_variable_type> el_q_3_minus_q;
                    std::shared_ptr<Fqk_variable_type> el_inv_q_2;
                    std::shared_ptr<Fqk_variable_type> el_inv_q_2_minus_1;
                    std::shared_ptr<Fqk_variable_type> w1;
                    std::shared_ptr<Fqk_variable_type> w0;
                    std::shared_ptr<Fqk_variable_type> result;

                    std::shared_ptr<Fqk_mul_component_type> compute_el_inv;
                    std::shared_ptr<Fqk_mul_component_type> compute_el_q_2_minus_1;
                    std::shared_ptr<Fqk_mul_component_type> compute_el_inv_q_2_minus_1;

                    std::shared_ptr<exponentiation_component<typename curve_type::pairing::fqk_type,
                                                             element_fp4,
                                                             element_fp4_mul,
                                                             element_fp4_cyclotomic_squared>>
                        compute_w1;
                    std::shared_ptr<exponentiation_component<typename curve_type::pairing::fqk_type,
                                                             element_fp4,
                                                             element_fp4_mul,
                                                             element_fp4_cyclotomic_squared>>
                        compute_w0;
                    std::shared_ptr<Fqk_mul_component_type> compute_result;

                    blueprint_variable<field_type> result_is_one;

                    final_exp_component(blueprint<field_type> &bp,
                                        const Fqk_variable_type &el,
                                        const blueprint_variable<field_type> &result_is_one) :
                        component<field_type>(bp),
                        el(el), result_is_one(result_is_one) {
                        one.reset(new Fqk_variable_type(bp));
                        el_inv.reset(new Fqk_variable_type(bp));
                        el_q_2.reset(new Fqk_variable_type(el.Frobenius_map(2)));
                        el_q_2_minus_1.reset(new Fqk_variable_type(bp));
                        el_q_3_minus_q.reset(new Fqk_variable_type(el_q_2_minus_1->Frobenius_map(1)));
                        el_inv_q_2.reset(new Fqk_variable_type(el_inv->Frobenius_map(2)));
                        el_inv_q_2_minus_1.reset(new Fqk_variable_type(bp));
                        w1.reset(new Fqk_variable_type(bp));
                        w0.reset(new Fqk_variable_type(bp));
                        result.reset(new Fqk_variable_type(bp));

                        compute_el_inv.reset(new Fqk_mul_component_type(bp, el, *el_inv, *one));
                        compute_el_q_2_minus_1.reset(new Fqk_mul_component_type(bp, *el_q_2, *el_inv, *el_q_2_minus_1));
                        compute_el_inv_q_2_minus_1.reset(
                            new Fqk_mul_component_type(bp, *el_inv_q_2, el, *el_inv_q_2_minus_1));

                        compute_w1.reset(new exponentiation_component<typename curve_type::pairing::fqk_type,
                                                                      element_fp4,
                                                                      element_fp4_mul,
                                                                      element_fp4_cyclotomic_squared> >
                                         (bp, *el_q_3_minus_q, curve_type::pairing::final_exponent_last_chunk_w1, *w1));
                        compute_w0.reset(
                            new exponentiation_component<typename curve_type::pairing::fqk_type,
                                                         element_fp4,
                                                         element_fp4_mul,
                                                         element_fp4_cyclotomic_squared> >
                            (bp,
                             (curve_type::pairing::final_exponent_last_chunk_is_w0_neg ? *el_inv_q_2_minus_1 :
                                                                                         *el_q_2_minus_1),
                             curve_type::pairing::final_exponent_last_chunk_abs_of_w0,
                             *w0));
                        compute_result.reset(new Fqk_mul_component_type(bp, *w1, *w0, *result));
                    }

                    void generate_r1cs_constraints() {
                        one->generate_r1cs_equals_const_constraints(
                            curve_type::pairing::pair_curve_type::pairing::fqk_type::value_type::one());

                        compute_el_inv->generate_r1cs_constraints();
                        compute_el_q_2_minus_1->generate_r1cs_constraints();
                        compute_el_inv_q_2_minus_1->generate_r1cs_constraints();
                        compute_w1->generate_r1cs_constraints();
                        compute_w0->generate_r1cs_constraints();
                        compute_result->generate_r1cs_constraints();

                        generate_boolean_r1cs_constraint<field_type>(this->bp, result_is_one);
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(result_is_one, 1 - result->c0.c0, 0));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(result_is_one, result->c0.c1, 0));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(result_is_one, result->c1.c0, 0));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(result_is_one, result->c1.c1, 0));
                    }

                    void generate_r1cs_witness() {
                        one->generate_r1cs_witness(
                            curve_type::pairing::pair_curve_type::pairing::fqk_type::value_type::one());
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

                        this->bp.val(result_is_one) =
                            (result->get_element() == one->get_element() ? field_type::value_type::one() :
                                                                           field_type::value_type::zero());
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_WEIERSTRASS_FINAL_EXPONENTIATION_HPP
