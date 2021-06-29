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
// @file Declaration of interfaces for components for Miller loops.
//
// The components verify computations of (single or multiple simultaneous) Miller loops.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_WEIERSTRASS_MILLER_LOOP_HPP
#define CRYPTO3_ZK_BLUEPRINT_WEIERSTRASS_MILLER_LOOP_HPP

#include <memory>

#include <nil/crypto3/algebra/algorithms/pair.hpp>

#include <nil/crypto3/zk/components/algebra/pairing/detail/mnt4.hpp>
#include <nil/crypto3/zk/components/algebra/pairing/detail/mnt6.hpp>

#include <nil/crypto3/zk/components/algebra/pairing/weierstrass/precomputation.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                using namespace nil::crypto3::algebra::pairing;

                /**
                 * Component for doubling step in the Miller loop.
                 *
                 * Technical note:
                 *
                 * mnt_Fqk g_RR_at_P = mnt_Fqk(prec_P.PY_twist_squared,
                 *                             -prec_P.PX * c.gamma_twist + c.gamma_X - c.old_RY);
                 *
                 *(later in Miller loop: f = f.squared() * g_RR_at_P)
                 *
                 * Note the slight interface change: this component allocates g_RR_at_P inside itself (!)
                 */
                template<typename CurveType>
                class mnt_miller_loop_dbl_line_eval : public component<typename CurveType::scalar_field_type> {

                    typedef typename CurveType::pairing::fp_type field_type;
                    using fqe_type = typename CurveType::pairing::pair_curve_type::pairing::fqe_type;

                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                public:
                    g1_precomputation<CurveType> prec_P;
                    precompute_G2_component_coeffs<CurveType> c;
                    std::shared_ptr<typename component_policy::Fqk_variable_type>
                        &g_RR_at_P;    // reference from outside

                    std::shared_ptr<typename component_policy::Fqe_variable_type> gamma_twist;
                    std::shared_ptr<typename component_policy::Fqe_variable_type> g_RR_at_P_c1;
                    std::shared_ptr<typename component_policy::Fqe_mul_by_lc_component_type> compute_g_RR_at_P_c1;

                    mnt_miller_loop_dbl_line_eval(
                        blueprint<field_type> &bp,
                        const g1_precomputation<CurveType> &prec_P,
                        const precompute_G2_component_coeffs<CurveType> &c,
                        std::shared_ptr<typename component_policy::Fqk_variable_type> &g_RR_at_P) :
                        component<field_type>(bp),
                        prec_P(prec_P), c(c), g_RR_at_P(g_RR_at_P) {

                        gamma_twist.reset(new typename component_policy::Fqe_variable_type(c.gamma->mul_by_X()));
                        // prec_P.PX * c.gamma_twist = c.gamma_X - c.old_RY - g_RR_at_P_c1
                        if (gamma_twist->is_constant()) {
                            gamma_twist->evaluate();
                            const typename fqe_type::value_type gamma_twist_const = gamma_twist->get_element();
                            g_RR_at_P_c1.reset(new typename component_policy::Fqe_variable_type(
                                typename component_policy::Fqe_variable_type(this->bp, -gamma_twist_const,
                                                                             prec_P.P->X) +
                                *(c.gamma_X) + *(c.RY) * (-field_type::value_type::one())));
                        } else if (prec_P.P->X.is_constant()) {
                            prec_P.P->X.evaluate(bp);
                            const typename field_type::value_type P_X_const = prec_P.P->X.constant_term();
                            g_RR_at_P_c1.reset(new typename component_policy::Fqe_variable_type(
                                *gamma_twist * (-P_X_const) + *(c.gamma_X) +
                                *(c.RY) * (-field_type::value_type::one())));
                        } else {
                            g_RR_at_P_c1.reset(new typename component_policy::Fqe_variable_type(bp));
                            compute_g_RR_at_P_c1.reset(new typename component_policy::Fqe_mul_by_lc_component_type(
                                bp, *gamma_twist, prec_P.P->X,
                                *(c.gamma_X) + *(c.RY) * (-field_type::value_type::one()) +
                                    (*g_RR_at_P_c1) * (-field_type::value_type::one())));
                        }
                        g_RR_at_P.reset(new typename component_policy::Fqk_variable_type(bp, *(prec_P.PY_twist_squared),
                                                                                         *g_RR_at_P_c1));
                    }

                    void generate_r1cs_constraints() {
                        if (!gamma_twist->is_constant() && !prec_P.P->X.is_constant()) {
                            compute_g_RR_at_P_c1->generate_r1cs_constraints();
                        }
                    }

                    void generate_r1cs_witness() {
                        gamma_twist->evaluate();
                        const typename fqe_type::value_type gamma_twist_val = gamma_twist->get_element();
                        const typename field_type::value_type PX_val = this->bp.lc_val(prec_P.P->X);
                        const typename fqe_type::value_type gamma_X_val = c.gamma_X->get_element();
                        const typename fqe_type::value_type RY_val = c.RY->get_element();
                        const typename fqe_type::value_type g_RR_at_P_c1_val =
                            -PX_val * gamma_twist_val + gamma_X_val - RY_val;
                        g_RR_at_P_c1->generate_r1cs_witness(g_RR_at_P_c1_val);

                        if (!gamma_twist->is_constant() && !prec_P.P->X.is_constant()) {
                            compute_g_RR_at_P_c1->generate_r1cs_witness();
                        }
                        g_RR_at_P->evaluate();
                    }
                };

                /**
                 * Component for addition step in the Miller loop.
                 *
                 * Technical note:
                 *
                 * mnt_Fqk g_RQ_at_P = mnt_Fqk(prec_P.PY_twist_squared,
                 *                            -prec_P.PX * c.gamma_twist + c.gamma_X - prec_Q.QY);
                 *
                 * (later in Miller loop: f = f * g_RQ_at_P)
                 *
                 * Note the slight interface change: this component will allocate g_RQ_at_P inside itself (!)
                 */
                template<typename CurveType>
                class mnt_miller_loop_add_line_eval : public component<typename CurveType::scalar_field_type> {

                    typedef typename CurveType::pairing::fp_type field_type;
                    using fqe_type = typename CurveType::pairing::pair_curve_type::pairing::fqe_type;

                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                public:
                    bool invert_Q;
                    g1_precomputation<CurveType> prec_P;
                    precompute_G2_component_coeffs<CurveType> c;
                    element_g2<CurveType> Q;
                    std::shared_ptr<typename component_policy::Fqk_variable_type>
                        &g_RQ_at_P;    // reference from outside

                    std::shared_ptr<typename component_policy::Fqe_variable_type> gamma_twist;
                    std::shared_ptr<typename component_policy::Fqe_variable_type> g_RQ_at_P_c1;
                    std::shared_ptr<typename component_policy::Fqe_mul_by_lc_component_type> compute_g_RQ_at_P_c1;

                    mnt_miller_loop_add_line_eval(
                        blueprint<field_type> &bp,
                        const bool invert_Q,
                        const g1_precomputation<CurveType> &prec_P,
                        const precompute_G2_component_coeffs<CurveType> &c,
                        const element_g2<CurveType> &Q,
                        std::shared_ptr<typename component_policy::Fqk_variable_type> &g_RQ_at_P) :
                        component<field_type>(bp),
                        invert_Q(invert_Q), prec_P(prec_P), c(c), Q(Q), g_RQ_at_P(g_RQ_at_P) {
                        gamma_twist.reset(new typename component_policy::Fqe_variable_type(c.gamma->mul_by_X()));
                        // prec_P.PX * c.gamma_twist = c.gamma_X - prec_Q.QY - g_RQ_at_P_c1
                        if (gamma_twist->is_constant()) {
                            gamma_twist->evaluate();
                            const typename fqe_type::value_type gamma_twist_const = gamma_twist->get_element();
                            g_RQ_at_P_c1.reset(new typename component_policy::Fqe_variable_type(
                                typename component_policy::Fqe_variable_type(this->bp, -gamma_twist_const,
                                                                             prec_P.P->X) +
                                *(c.gamma_X) +
                                *(Q.Y) * (!invert_Q ? -field_type::value_type::one() : field_type::value_type::one())));
                        } else if (prec_P.P->X.is_constant()) {
                            prec_P.P->X.evaluate(bp);
                            const typename field_type::value_type P_X_const = prec_P.P->X.constant_term();
                            g_RQ_at_P_c1.reset(new typename component_policy::Fqe_variable_type(
                                *gamma_twist * (-P_X_const) + *(c.gamma_X) +
                                *(Q.Y) * (!invert_Q ? -field_type::value_type::one() : field_type::value_type::one())));
                        } else {
                            g_RQ_at_P_c1.reset(new typename component_policy::Fqe_variable_type(bp));
                            compute_g_RQ_at_P_c1.reset(new typename component_policy::Fqe_mul_by_lc_component_type(
                                bp, *gamma_twist, prec_P.P->X,
                                *(c.gamma_X) +
                                    *(Q.Y) *
                                        (!invert_Q ? -field_type::value_type::one() : field_type::value_type::one()) +
                                    (*g_RQ_at_P_c1) * (-field_type::value_type::one())));
                        }
                        g_RQ_at_P.reset(new typename component_policy::Fqk_variable_type(bp, *(prec_P.PY_twist_squared),
                                                                                         *g_RQ_at_P_c1));
                    }
                    void generate_r1cs_constraints() {
                        if (!gamma_twist->is_constant() && !prec_P.P->X.is_constant()) {
                            compute_g_RQ_at_P_c1->generate_r1cs_constraints();
                        }
                    }
                    void generate_r1cs_witness() {
                        gamma_twist->evaluate();
                        const typename fqe_type::value_type gamma_twist_val = gamma_twist->get_element();
                        const typename field_type::value_type PX_val = this->bp.lc_val(prec_P.P->X);
                        const typename fqe_type::value_type gamma_X_val = c.gamma_X->get_element();
                        const typename fqe_type::value_type QY_val = Q.Y->get_element();
                        const typename fqe_type::value_type g_RQ_at_P_c1_val =
                            -PX_val * gamma_twist_val + gamma_X_val + (!invert_Q ? -QY_val : QY_val);
                        g_RQ_at_P_c1->generate_r1cs_witness(g_RQ_at_P_c1_val);

                        if (!gamma_twist->is_constant() && !prec_P.P->X.is_constant()) {
                            compute_g_RQ_at_P_c1->generate_r1cs_witness();
                        }
                        g_RQ_at_P->evaluate();
                    }
                };

                /**
                 * Component for verifying a single Miller loop.
                 */
                template<typename CurveType>
                class mnt_miller_loop_component : public component<typename CurveType::scalar_field_type> {

                    typedef typename CurveType::pairing::fp_type field_type;
                    using fqk_type = typename CurveType::pairing::pair_curve_type::pairing::fqk_type;

                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                public:
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> g_RR_at_Ps;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> g_RQ_at_Ps;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> fs;

                    std::vector<std::shared_ptr<mnt_miller_loop_add_line_eval<CurveType>>> addition_steps;
                    std::vector<std::shared_ptr<mnt_miller_loop_dbl_line_eval<CurveType>>> doubling_steps;

                    std::vector<std::shared_ptr<typename component_policy::Fqk_special_mul_component_type>> dbl_muls;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_sqr_component_type>> dbl_sqrs;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_special_mul_component_type>> add_muls;

                    std::size_t f_count;
                    std::size_t add_count;
                    std::size_t dbl_count;

                    g1_precomputation<CurveType> prec_P;
                    g2_precomputation<CurveType> prec_Q;
                    typename component_policy::Fqk_variable_type result;

                    mnt_miller_loop_component(blueprint<field_type> &bp,
                                              const g1_precomputation<CurveType> &prec_P,
                                              const g2_precomputation<CurveType> &prec_Q,
                                              const typename component_policy::Fqk_variable_type &result) :
                        component<field_type>(bp),
                        prec_P(prec_P), prec_Q(prec_Q), result(result) {

                        f_count = add_count = dbl_count = 0;

                        bool found_nonzero = false;
                        std::vector<long> NAF = find_wnaf(1, CurveType::pairing::pairing_loop_count);
                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            ++dbl_count;
                            f_count += 2;

                            if (NAF[i] != 0) {
                                ++add_count;
                                f_count += 1;
                            }
                        }

                        fs.resize(f_count);
                        doubling_steps.resize(dbl_count);
                        addition_steps.resize(add_count);
                        g_RR_at_Ps.resize(dbl_count);
                        g_RQ_at_Ps.resize(add_count);

                        for (std::size_t i = 0; i < f_count; ++i) {
                            fs[i].reset(new typename component_policy::Fqk_variable_type(bp));
                        }

                        dbl_sqrs.resize(dbl_count);
                        dbl_muls.resize(dbl_count);
                        add_muls.resize(add_count);

                        std::size_t add_id = 0;
                        std::size_t dbl_id = 0;
                        std::size_t f_id = 0;
                        std::size_t prec_id = 0;

                        found_nonzero = false;
                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            doubling_steps[dbl_id].reset(new mnt_miller_loop_dbl_line_eval<CurveType>(
                                bp, prec_P, *prec_Q.coeffs[prec_id], g_RR_at_Ps[dbl_id]));
                            ++prec_id;
                            dbl_sqrs[dbl_id].reset(
                                new typename component_policy::Fqk_sqr_component_type(bp, *fs[f_id], *fs[f_id + 1]));
                            ++f_id;
                            dbl_muls[dbl_id].reset(new typename component_policy::Fqk_special_mul_component_type(
                                bp, *fs[f_id], *g_RR_at_Ps[dbl_id], (f_id + 1 == f_count ? result : *fs[f_id + 1])));
                            ++f_id;
                            ++dbl_id;

                            if (NAF[i] != 0) {
                                addition_steps[add_id].reset(new mnt_miller_loop_add_line_eval<CurveType>(
                                    bp, NAF[i] < 0, prec_P, *prec_Q.coeffs[prec_id], *prec_Q.Q, g_RQ_at_Ps[add_id]));
                                ++prec_id;
                                add_muls[add_id].reset(new typename component_policy::Fqk_special_mul_component_type(
                                    bp, *fs[f_id], *g_RQ_at_Ps[add_id],
                                    (f_id + 1 == f_count ? result : *fs[f_id + 1])));
                                ++f_id;
                                ++add_id;
                            }
                        }
                    }
                    void generate_r1cs_constraints() {
                        fs[0]->generate_r1cs_equals_const_constraints(fqk_type::value_type::one());

                        for (std::size_t i = 0; i < dbl_count; ++i) {
                            doubling_steps[i]->generate_r1cs_constraints();
                            dbl_sqrs[i]->generate_r1cs_constraints();
                            dbl_muls[i]->generate_r1cs_constraints();
                        }

                        for (std::size_t i = 0; i < add_count; ++i) {
                            addition_steps[i]->generate_r1cs_constraints();
                            add_muls[i]->generate_r1cs_constraints();
                        }
                    }
                    void generate_r1cs_witness() {
                        fs[0]->generate_r1cs_witness(fqk_type::value_type::one());

                        std::size_t add_id = 0;
                        std::size_t dbl_id = 0;

                        bool found_nonzero = false;
                        std::vector<long> NAF = find_wnaf(1, CurveType::pairing::pairing_loop_count);
                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            doubling_steps[dbl_id]->generate_r1cs_witness();
                            dbl_sqrs[dbl_id]->generate_r1cs_witness();
                            dbl_muls[dbl_id]->generate_r1cs_witness();
                            ++dbl_id;

                            if (NAF[i] != 0) {
                                addition_steps[add_id]->generate_r1cs_witness();
                                add_muls[add_id]->generate_r1cs_witness();
                                ++add_id;
                            }
                        }
                    }
                };

                /**
                 * Component for verifying a double Miller loop (where the second is inverted).
                 */
                template<typename CurveType>
                class mnt_e_over_e_miller_loop_component : public component<typename CurveType::scalar_field_type> {

                    typedef typename CurveType::pairing::fp_type field_type;
                    using fqe_type = typename CurveType::pairing::pair_curve_type::pairing::fqe_type;
                    using fqk_type = typename CurveType::pairing::pair_curve_type::pairing::fqk_type;

                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                public:
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> g_RR_at_P1s;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> g_RQ_at_P1s;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> g_RR_at_P2s;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> g_RQ_at_P2s;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> fs;

                    std::vector<std::shared_ptr<mnt_miller_loop_add_line_eval<CurveType>>> addition_steps1;
                    std::vector<std::shared_ptr<mnt_miller_loop_dbl_line_eval<CurveType>>> doubling_steps1;
                    std::vector<std::shared_ptr<mnt_miller_loop_add_line_eval<CurveType>>> addition_steps2;
                    std::vector<std::shared_ptr<mnt_miller_loop_dbl_line_eval<CurveType>>> doubling_steps2;

                    std::vector<std::shared_ptr<typename component_policy::Fqk_sqr_component_type>> dbl_sqrs;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_special_mul_component_type>> dbl_muls1;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_special_mul_component_type>> add_muls1;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_special_mul_component_type>> dbl_muls2;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_special_mul_component_type>> add_muls2;

                    std::size_t f_count;
                    std::size_t add_count;
                    std::size_t dbl_count;

                    g1_precomputation<CurveType> prec_P1;
                    g2_precomputation<CurveType> prec_Q1;
                    g1_precomputation<CurveType> prec_P2;
                    g2_precomputation<CurveType> prec_Q2;
                    typename component_policy::Fqk_variable_type result;

                    mnt_e_over_e_miller_loop_component(blueprint<field_type> &bp,
                                                       const g1_precomputation<CurveType> &prec_P1,
                                                       const g2_precomputation<CurveType> &prec_Q1,
                                                       const g1_precomputation<CurveType> &prec_P2,
                                                       const g2_precomputation<CurveType> &prec_Q2,
                                                       const typename component_policy::Fqk_variable_type &result) :
                        component<field_type>(bp),
                        prec_P1(prec_P1), prec_Q1(prec_Q1), prec_P2(prec_P2), prec_Q2(prec_Q2), result(result) {

                        f_count = add_count = dbl_count = 0;

                        bool found_nonzero = false;
                        std::vector<long> NAF = find_wnaf(1, CurveType::pairing::pairing_loop_count);

                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            ++dbl_count;
                            f_count += 3;

                            if (NAF[i] != 0) {
                                ++add_count;
                                f_count += 2;
                            }
                        }

                        fs.resize(f_count);
                        doubling_steps1.resize(dbl_count);
                        addition_steps1.resize(add_count);
                        doubling_steps2.resize(dbl_count);
                        addition_steps2.resize(add_count);
                        g_RR_at_P1s.resize(dbl_count);
                        g_RQ_at_P1s.resize(add_count);
                        g_RR_at_P2s.resize(dbl_count);
                        g_RQ_at_P2s.resize(add_count);

                        for (std::size_t i = 0; i < f_count; ++i) {
                            fs[i].reset(new typename component_policy::Fqk_variable_type(bp));
                        }

                        dbl_sqrs.resize(dbl_count);
                        dbl_muls1.resize(dbl_count);
                        add_muls1.resize(add_count);
                        dbl_muls2.resize(dbl_count);
                        add_muls2.resize(add_count);

                        std::size_t add_id = 0;
                        std::size_t dbl_id = 0;
                        std::size_t f_id = 0;
                        std::size_t prec_id = 0;

                        found_nonzero = false;
                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            doubling_steps1[dbl_id].reset(new mnt_miller_loop_dbl_line_eval<CurveType>(
                                bp, prec_P1, *prec_Q1.coeffs[prec_id], g_RR_at_P1s[dbl_id]));
                            doubling_steps2[dbl_id].reset(new mnt_miller_loop_dbl_line_eval<CurveType>(
                                bp, prec_P2, *prec_Q2.coeffs[prec_id], g_RR_at_P2s[dbl_id]));
                            ++prec_id;

                            dbl_sqrs[dbl_id].reset(
                                new typename component_policy::Fqk_sqr_component_type(bp, *fs[f_id], *fs[f_id + 1]));
                            ++f_id;
                            dbl_muls1[dbl_id].reset(new typename component_policy::Fqk_special_mul_component_type(
                                bp, *fs[f_id], *g_RR_at_P1s[dbl_id], *fs[f_id + 1]));
                            ++f_id;
                            dbl_muls2[dbl_id].reset(new typename component_policy::Fqk_special_mul_component_type(
                                bp, (f_id + 1 == f_count ? result : *fs[f_id + 1]), *g_RR_at_P2s[dbl_id], *fs[f_id]));
                            ++f_id;
                            ++dbl_id;

                            if (NAF[i] != 0) {
                                addition_steps1[add_id].reset(new mnt_miller_loop_add_line_eval<CurveType>(
                                    bp, NAF[i] < 0, prec_P1, *prec_Q1.coeffs[prec_id], *prec_Q1.Q,
                                    g_RQ_at_P1s[add_id]));
                                addition_steps2[add_id].reset(new mnt_miller_loop_add_line_eval<CurveType>(
                                    bp, NAF[i] < 0, prec_P2, *prec_Q2.coeffs[prec_id], *prec_Q2.Q,
                                    g_RQ_at_P2s[add_id]));
                                ++prec_id;
                                add_muls1[add_id].reset(new typename component_policy::Fqk_special_mul_component_type(
                                    bp, *fs[f_id], *g_RQ_at_P1s[add_id], *fs[f_id + 1]));
                                ++f_id;
                                add_muls2[add_id].reset(new typename component_policy::Fqk_special_mul_component_type(
                                    bp, (f_id + 1 == f_count ? result : *fs[f_id + 1]), *g_RQ_at_P2s[add_id],
                                    *fs[f_id]));
                                ++f_id;
                                ++add_id;
                            }
                        }
                    }
                    void generate_r1cs_constraints() {
                        fs[0]->generate_r1cs_equals_const_constraints(fqk_type::value_type::one());

                        for (std::size_t i = 0; i < dbl_count; ++i) {
                            doubling_steps1[i]->generate_r1cs_constraints();
                            doubling_steps2[i]->generate_r1cs_constraints();
                            dbl_sqrs[i]->generate_r1cs_constraints();
                            dbl_muls1[i]->generate_r1cs_constraints();
                            dbl_muls2[i]->generate_r1cs_constraints();
                        }

                        for (std::size_t i = 0; i < add_count; ++i) {
                            addition_steps1[i]->generate_r1cs_constraints();
                            addition_steps2[i]->generate_r1cs_constraints();
                            add_muls1[i]->generate_r1cs_constraints();
                            add_muls2[i]->generate_r1cs_constraints();
                        }
                    }
                    void generate_r1cs_witness() {
                        fs[0]->generate_r1cs_witness(fqk_type::value_type::one());

                        std::size_t add_id = 0;
                        std::size_t dbl_id = 0;
                        std::size_t f_id = 0;

                        bool found_nonzero = false;
                        std::vector<long> NAF = find_wnaf(1, CurveType::pairing::pairing_loop_count);

                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            doubling_steps1[dbl_id]->generate_r1cs_witness();
                            doubling_steps2[dbl_id]->generate_r1cs_witness();
                            dbl_sqrs[dbl_id]->generate_r1cs_witness();
                            ++f_id;
                            dbl_muls1[dbl_id]->generate_r1cs_witness();
                            ++f_id;
                            (f_id + 1 == f_count ? result : *fs[f_id + 1])
                                .generate_r1cs_witness(fs[f_id]->get_element() *
                                                       g_RR_at_P2s[dbl_id]->get_element().inversed());
                            dbl_muls2[dbl_id]->generate_r1cs_witness();
                            ++f_id;
                            ++dbl_id;

                            if (NAF[i] != 0) {
                                addition_steps1[add_id]->generate_r1cs_witness();
                                addition_steps2[add_id]->generate_r1cs_witness();
                                add_muls1[add_id]->generate_r1cs_witness();
                                ++f_id;
                                (f_id + 1 == f_count ? result : *fs[f_id + 1])
                                    .generate_r1cs_witness(fs[f_id]->get_element() *
                                                           g_RQ_at_P2s[add_id]->get_element().inversed());
                                add_muls2[add_id]->generate_r1cs_witness();
                                ++f_id;
                                ++add_id;
                            }
                        }
                    }
                };

                /**
                 * Component for verifying a triple Miller loop (where the third is inverted).
                 */
                template<typename CurveType>
                class mnt_e_times_e_over_e_miller_loop_component
                    : public component<typename CurveType::scalar_field_type> {

                    typedef typename CurveType::pairing::fp_type field_type;
                    using fqe_type = typename CurveType::pairing::pair_curve_type::pairing::fqe_type;
                    using fqk_type = typename CurveType::pairing::pair_curve_type::pairing::fqk_type;

                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                public:
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> g_RR_at_P1s;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> g_RQ_at_P1s;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> g_RR_at_P2s;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> g_RQ_at_P2s;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> g_RR_at_P3s;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> g_RQ_at_P3s;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_variable_type>> fs;

                    std::vector<std::shared_ptr<mnt_miller_loop_add_line_eval<CurveType>>> addition_steps1;
                    std::vector<std::shared_ptr<mnt_miller_loop_dbl_line_eval<CurveType>>> doubling_steps1;
                    std::vector<std::shared_ptr<mnt_miller_loop_add_line_eval<CurveType>>> addition_steps2;
                    std::vector<std::shared_ptr<mnt_miller_loop_dbl_line_eval<CurveType>>> doubling_steps2;
                    std::vector<std::shared_ptr<mnt_miller_loop_add_line_eval<CurveType>>> addition_steps3;
                    std::vector<std::shared_ptr<mnt_miller_loop_dbl_line_eval<CurveType>>> doubling_steps3;

                    std::vector<std::shared_ptr<typename component_policy::Fqk_sqr_component_type>> dbl_sqrs;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_special_mul_component_type>> dbl_muls1;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_special_mul_component_type>> add_muls1;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_special_mul_component_type>> dbl_muls2;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_special_mul_component_type>> add_muls2;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_special_mul_component_type>> dbl_muls3;
                    std::vector<std::shared_ptr<typename component_policy::Fqk_special_mul_component_type>> add_muls3;

                    std::size_t f_count;
                    std::size_t add_count;
                    std::size_t dbl_count;

                    g1_precomputation<CurveType> prec_P1;
                    g2_precomputation<CurveType> prec_Q1;
                    g1_precomputation<CurveType> prec_P2;
                    g2_precomputation<CurveType> prec_Q2;
                    g1_precomputation<CurveType> prec_P3;
                    g2_precomputation<CurveType> prec_Q3;
                    typename component_policy::Fqk_variable_type result;

                    mnt_e_times_e_over_e_miller_loop_component(
                        blueprint<field_type> &bp,
                        const g1_precomputation<CurveType> &prec_P1,
                        const g2_precomputation<CurveType> &prec_Q1,
                        const g1_precomputation<CurveType> &prec_P2,
                        const g2_precomputation<CurveType> &prec_Q2,
                        const g1_precomputation<CurveType> &prec_P3,
                        const g2_precomputation<CurveType> &prec_Q3,
                        const typename component_policy::Fqk_variable_type &result) :
                        component<field_type>(bp),
                        prec_P1(prec_P1), prec_Q1(prec_Q1), prec_P2(prec_P2), prec_Q2(prec_Q2), prec_P3(prec_P3),
                        prec_Q3(prec_Q3), result(result) {

                        f_count = add_count = dbl_count = 0;

                        bool found_nonzero = false;
                        std::vector<long> NAF = find_wnaf(1, CurveType::pairing::pairing_loop_count);

                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            ++dbl_count;
                            f_count += 4;

                            if (NAF[i] != 0) {
                                ++add_count;
                                f_count += 3;
                            }
                        }

                        fs.resize(f_count);
                        doubling_steps1.resize(dbl_count);
                        addition_steps1.resize(add_count);
                        doubling_steps2.resize(dbl_count);
                        addition_steps2.resize(add_count);
                        doubling_steps3.resize(dbl_count);
                        addition_steps3.resize(add_count);
                        g_RR_at_P1s.resize(dbl_count);
                        g_RQ_at_P1s.resize(add_count);
                        g_RR_at_P2s.resize(dbl_count);
                        g_RQ_at_P2s.resize(add_count);
                        g_RR_at_P3s.resize(dbl_count);
                        g_RQ_at_P3s.resize(add_count);

                        for (std::size_t i = 0; i < f_count; ++i) {
                            fs[i].reset(new typename component_policy::Fqk_variable_type(bp));
                        }

                        dbl_sqrs.resize(dbl_count);
                        dbl_muls1.resize(dbl_count);
                        add_muls1.resize(add_count);
                        dbl_muls2.resize(dbl_count);
                        add_muls2.resize(add_count);
                        dbl_muls3.resize(dbl_count);
                        add_muls3.resize(add_count);

                        std::size_t add_id = 0;
                        std::size_t dbl_id = 0;
                        std::size_t f_id = 0;
                        std::size_t prec_id = 0;

                        found_nonzero = false;
                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            doubling_steps1[dbl_id].reset(new mnt_miller_loop_dbl_line_eval<CurveType>(
                                bp, prec_P1, *prec_Q1.coeffs[prec_id], g_RR_at_P1s[dbl_id]));
                            doubling_steps2[dbl_id].reset(new mnt_miller_loop_dbl_line_eval<CurveType>(
                                bp, prec_P2, *prec_Q2.coeffs[prec_id], g_RR_at_P2s[dbl_id]));
                            doubling_steps3[dbl_id].reset(new mnt_miller_loop_dbl_line_eval<CurveType>(
                                bp, prec_P3, *prec_Q3.coeffs[prec_id], g_RR_at_P3s[dbl_id]));
                            ++prec_id;

                            dbl_sqrs[dbl_id].reset(
                                new typename component_policy::Fqk_sqr_component_type(bp, *fs[f_id], *fs[f_id + 1]));
                            ++f_id;
                            dbl_muls1[dbl_id].reset(new typename component_policy::Fqk_special_mul_component_type(
                                bp, *fs[f_id], *g_RR_at_P1s[dbl_id], *fs[f_id + 1]));
                            ++f_id;
                            dbl_muls2[dbl_id].reset(new typename component_policy::Fqk_special_mul_component_type(
                                bp, *fs[f_id], *g_RR_at_P2s[dbl_id], *fs[f_id + 1]));
                            ++f_id;
                            dbl_muls3[dbl_id].reset(new typename component_policy::Fqk_special_mul_component_type(
                                bp, (f_id + 1 == f_count ? result : *fs[f_id + 1]), *g_RR_at_P3s[dbl_id], *fs[f_id]));
                            ++f_id;
                            ++dbl_id;

                            if (NAF[i] != 0) {
                                addition_steps1[add_id].reset(new mnt_miller_loop_add_line_eval<CurveType>(
                                    bp, NAF[i] < 0, prec_P1, *prec_Q1.coeffs[prec_id], *prec_Q1.Q,
                                    g_RQ_at_P1s[add_id]));
                                addition_steps2[add_id].reset(new mnt_miller_loop_add_line_eval<CurveType>(
                                    bp, NAF[i] < 0, prec_P2, *prec_Q2.coeffs[prec_id], *prec_Q2.Q,
                                    g_RQ_at_P2s[add_id]));
                                addition_steps3[add_id].reset(new mnt_miller_loop_add_line_eval<CurveType>(
                                    bp, NAF[i] < 0, prec_P3, *prec_Q3.coeffs[prec_id], *prec_Q3.Q,
                                    g_RQ_at_P3s[add_id]));
                                ++prec_id;
                                add_muls1[add_id].reset(new typename component_policy::Fqk_special_mul_component_type(
                                    bp, *fs[f_id], *g_RQ_at_P1s[add_id], *fs[f_id + 1]));
                                ++f_id;
                                add_muls2[add_id].reset(new typename component_policy::Fqk_special_mul_component_type(
                                    bp, *fs[f_id], *g_RQ_at_P2s[add_id], *fs[f_id + 1]));
                                ++f_id;
                                add_muls3[add_id].reset(new typename component_policy::Fqk_special_mul_component_type(
                                    bp, (f_id + 1 == f_count ? result : *fs[f_id + 1]), *g_RQ_at_P3s[add_id],
                                    *fs[f_id]));
                                ++f_id;
                                ++add_id;
                            }
                        }
                    }
                    void generate_r1cs_constraints() {
                        fs[0]->generate_r1cs_equals_const_constraints(fqk_type::value_type::one());

                        for (std::size_t i = 0; i < dbl_count; ++i) {
                            doubling_steps1[i]->generate_r1cs_constraints();
                            doubling_steps2[i]->generate_r1cs_constraints();
                            doubling_steps3[i]->generate_r1cs_constraints();
                            dbl_sqrs[i]->generate_r1cs_constraints();
                            dbl_muls1[i]->generate_r1cs_constraints();
                            dbl_muls2[i]->generate_r1cs_constraints();
                            dbl_muls3[i]->generate_r1cs_constraints();
                        }

                        for (std::size_t i = 0; i < add_count; ++i) {
                            addition_steps1[i]->generate_r1cs_constraints();
                            addition_steps2[i]->generate_r1cs_constraints();
                            addition_steps3[i]->generate_r1cs_constraints();
                            add_muls1[i]->generate_r1cs_constraints();
                            add_muls2[i]->generate_r1cs_constraints();
                            add_muls3[i]->generate_r1cs_constraints();
                        }
                    }
                    void generate_r1cs_witness() {
                        fs[0]->generate_r1cs_witness(fqk_type::value_type::one());

                        std::size_t add_id = 0;
                        std::size_t dbl_id = 0;
                        std::size_t f_id = 0;

                        bool found_nonzero = false;
                        std::vector<long> NAF = find_wnaf(1, CurveType::pairing::pairing_loop_count);

                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            doubling_steps1[dbl_id]->generate_r1cs_witness();
                            doubling_steps2[dbl_id]->generate_r1cs_witness();
                            doubling_steps3[dbl_id]->generate_r1cs_witness();
                            dbl_sqrs[dbl_id]->generate_r1cs_witness();
                            ++f_id;
                            dbl_muls1[dbl_id]->generate_r1cs_witness();
                            ++f_id;
                            dbl_muls2[dbl_id]->generate_r1cs_witness();
                            ++f_id;
                            (f_id + 1 == f_count ? result : *fs[f_id + 1])
                                .generate_r1cs_witness(fs[f_id]->get_element() *
                                                       g_RR_at_P3s[dbl_id]->get_element().inversed());
                            dbl_muls3[dbl_id]->generate_r1cs_witness();
                            ++f_id;
                            ++dbl_id;

                            if (NAF[i] != 0) {
                                addition_steps1[add_id]->generate_r1cs_witness();
                                addition_steps2[add_id]->generate_r1cs_witness();
                                addition_steps3[add_id]->generate_r1cs_witness();
                                add_muls1[add_id]->generate_r1cs_witness();
                                ++f_id;
                                add_muls2[add_id]->generate_r1cs_witness();
                                ++f_id;
                                (f_id + 1 == f_count ? result : *fs[f_id + 1])
                                    .generate_r1cs_witness(fs[f_id]->get_element() *
                                                           g_RQ_at_P3s[add_id]->get_element().inversed());
                                add_muls3[add_id]->generate_r1cs_witness();
                                ++f_id;
                                ++add_id;
                            }
                        }
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_WEIERSTRASS_MILLER_LOOP_HPP
