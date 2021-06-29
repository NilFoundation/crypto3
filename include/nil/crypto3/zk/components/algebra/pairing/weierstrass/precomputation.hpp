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
// @file Declaration of interfaces for pairing precomputation components.
//
// The components verify correct precomputation of values for the G1 and G2 elements.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_AS_WAKSMAN_HPP
#define CRYPTO3_ZK_BLUEPRINT_AS_WAKSMAN_HPP

#include <memory>

#include <nil/crypto3/algebra/algorithms/pair.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/zk/components/algebra/curves/weierstrass/element_g1.hpp>
#include <nil/crypto3/zk/components/algebra/curves/weierstrass/element_g2.hpp>

#include <nil/crypto3/zk/components/algebra/pairing/detail/mnt4.hpp>
#include <nil/crypto3/zk/components/algebra/pairing/detail/mnt6.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                using namespace nil::crypto3::algebra::pairing;

                /**************************** G1 Precomputation ******************************/

                /**
                 * Not a component. It only holds values.
                 */
                template<typename CurveType>
                class g1_precomputation {
                    typedef typename CurveType::pairing::fp_type FieldType;
                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                public:
                    std::shared_ptr<element_g1<CurveType>> P;
                    std::shared_ptr<typename component_policy::Fqe_variable_type> PY_twist_squared;

                    g1_precomputation() {
                        // will be filled in precompute_G1_component, so do nothing here
                    }

                    g1_precomputation(blueprint<FieldType> &bp,
                                      const typename CurveType::pairing::pair_curve_type::g1_type::value_type &P_val) {
                        typename CurveType::pairing::pair_curve_type::g1_type::value_type P_val_copy =
                            P_val.to_affine();
                        P.reset(new element_g1<CurveType>(bp, P_val_copy));
                        PY_twist_squared.reset(new typename component_policy::Fqe_variable_type(
                            bp,
                            P_val_copy.Y() *
                                CurveType::pairing::pair_curve_type::g2_type::value_type::twist.squared()));
                    }
                };

                /**
                 * Component that verifies correct precomputation of the G1 element.
                 */
                template<typename CurveType>
                class precompute_G1_component : public component<typename CurveType::scalar_field_type> {
                    using curve_type = CurveType;
                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                public:
                    using fqk_type = typename CurveType::pairing::pair_curve_type::pairing::fqk_type;

                    g1_precomputation<CurveType> &precomp;    // must be a reference.

                    /* two possible pre-computations one for mnt4 and one for mnt6 */
                    template<typename FieldType>
                    precompute_G1_component(
                        blueprint<FieldType> &bp,
                        const element_g1<CurveType> &P,
                        g1_precomputation<CurveType> &precomp,    // will allocate this inside
                        const typename std::enable_if<fqk_type::arity == 4, typename FieldType::value_type>::type & =
                            typename FieldType::value_type()) :
                        component<FieldType>(bp),
                        precomp(precomp) {

                        using twist_curve_type = nil::crypto3::algebra::curves::mnt4<298>;

                        blueprint_linear_combination<FieldType> c0, c1;
                        c0.assign(bp, P.Y * ((twist_curve_type::pairing::twist).squared().data[0]));
                        c1.assign(bp, P.Y * ((twist_curve_type::pairing::twist).squared().data[1]));

                        precomp.P.reset(new element_g1<CurveType>(P));
                        precomp.PY_twist_squared.reset(new typename component_policy::Fqe_variable_type(bp, c0, c1));
                    }

                    template<typename FieldType>
                    precompute_G1_component(
                        blueprint<FieldType> &bp,
                        const element_g1<CurveType> &P,
                        g1_precomputation<CurveType> &precomp,    // will allocate this inside
                        const typename std::enable_if<fqk_type::arity == 6, typename FieldType::value_type>::type & =
                            typename FieldType::value_type()) :
                        component<FieldType>(bp),
                        precomp(precomp) {

                        using twist_curve_type = nil::crypto3::algebra::curves::mnt6<298>;

                        blueprint_linear_combination<FieldType> c0, c1, c2;
                        c0.assign(bp, P.Y * ((twist_curve_type::pairing::twist).squared().data[0]));
                        c1.assign(bp, P.Y * ((twist_curve_type::pairing::twist).squared().data[1]));
                        c2.assign(bp, P.Y * ((twist_curve_type::pairing::twist).squared().data[2]));

                        precomp.P.reset(new element_g1<CurveType>(P));
                        precomp.PY_twist_squared.reset(new
                                                       typename component_policy::Fqe_variable_type(bp, c0, c1, c2));
                    }

                    void generate_r1cs_constraints() {
                        /* the same for neither CurveType = mnt4 nor CurveType = mnt6 */
                    }

                    void generate_r1cs_witness() {
                        precomp.PY_twist_squared
                            ->evaluate(); /* the same for both CurveType = mnt4 and CurveType = mnt6 */
                    }
                };

                /**************************** G2 Precomputation ******************************/

                /**
                 * Not a component. It only holds values.
                 */
                template<typename CurveType>
                class precompute_G2_component_coeffs {
                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                public:
                    typedef typename CurveType::pairing::fp_type FieldType;

                    std::shared_ptr<typename component_policy::Fqe_variable_type> RX;
                    std::shared_ptr<typename component_policy::Fqe_variable_type> RY;
                    std::shared_ptr<typename component_policy::Fqe_variable_type> gamma;
                    std::shared_ptr<typename component_policy::Fqe_variable_type> gamma_X;

                    precompute_G2_component_coeffs() {
                        // we will be filled in precomputed case of precompute_G2_component, so do nothing here
                    }

                    precompute_G2_component_coeffs(blueprint<FieldType> &bp) {
                        RX.reset(new typename component_policy::Fqe_variable_type(bp));
                        RY.reset(new typename component_policy::Fqe_variable_type(bp));
                        gamma.reset(new typename component_policy::Fqe_variable_type(bp));
                        gamma_X.reset(new typename component_policy::Fqe_variable_type(bp));
                    }

                    precompute_G2_component_coeffs(blueprint<FieldType> &bp, const element_g2<CurveType> &Q) {
                        RX.reset(new typename component_policy::Fqe_variable_type(*(Q.X)));
                        RY.reset(new typename component_policy::Fqe_variable_type(*(Q.Y)));
                        gamma.reset(new typename component_policy::Fqe_variable_type(bp));
                        gamma_X.reset(new typename component_policy::Fqe_variable_type(bp));
                    }
                };

                /**
                 * Not a component. It only holds values.
                 */
                template<typename CurveType>
                class g2_precomputation {
                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                public:
                    typedef typename CurveType::pairing::fp_type FieldType;

                    std::shared_ptr<element_g2<CurveType>> Q;

                    std::vector<std::shared_ptr<precompute_G2_component_coeffs<CurveType>>> coeffs;

                    g2_precomputation() {
                    }
                    g2_precomputation(blueprint<FieldType> &bp,
                                      const typename CurveType::pairing::pair_curve_type::g2_type::value_type &Q_val) {
                        Q.reset(new element_g2<CurveType>(bp, Q_val));
                        const typename CurveType::pairing::pair_curve_type::pairing::affine_ate_g2_precomp
                            native_precomp =
                                affine_ate_precompute_g2<typename CurveType::pairing::pair_curve_type>(Q_val);

                        coeffs.resize(native_precomp.coeffs.size() +
                                      1);    // the last precomp remains for convenient programming
                        for (std::size_t i = 0; i < native_precomp.coeffs.size(); ++i) {
                            coeffs[i].reset(new precompute_G2_component_coeffs<CurveType>());
                            coeffs[i]->RX.reset(
                                new typename component_policy::Fqe_variable_type(bp, native_precomp.coeffs[i].old_RX));
                            coeffs[i]->RY.reset(
                                new typename component_policy::Fqe_variable_type(bp, native_precomp.coeffs[i].old_RY));
                            coeffs[i]->gamma.reset(
                                new typename component_policy::Fqe_variable_type(bp, native_precomp.coeffs[i].gamma));
                            coeffs[i]->gamma_X.reset(
                                new typename component_policy::Fqe_variable_type(bp, native_precomp.coeffs[i].gamma_X));
                        }
                    }
                };

                /**
                 * Technical note:
                 *
                 * QX and QY -- X and Y coordinates of Q
                 *
                 * initialization:
                 * coeffs[0].RX = QX
                 * coeffs[0].RY = QY
                 *
                 * g2_precompute_doubling_step relates coeffs[i] and coeffs[i+1] as follows
                 *
                 * coeffs[i]
                 * gamma = (3 * RX^2 + twist_coeff_a) * (2*RY).inversed()
                 * gamma_X = gamma * RX
                 *
                 * coeffs[i+1]
                 * RX = prev_gamma^2 - (2*prev_RX)
                 * RY = prev_gamma * (prev_RX - RX) - prev_RY
                 */
                template<typename CurveType>
                class precompute_G2_component_doubling_step : public component<typename CurveType::scalar_field_type> {
                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                public:
                    typedef typename CurveType::pairing::fp_type FieldType;
                    using fqe_type = typename CurveType::pairing::pair_curve_type::pairing::fqe_type;

                    precompute_G2_component_coeffs<CurveType> cur;
                    precompute_G2_component_coeffs<CurveType> next;

                    std::shared_ptr<typename component_policy::Fqe_variable_type> RXsquared;
                    std::shared_ptr<typename component_policy::Fqe_sqr_component_type> compute_RXsquared;
                    std::shared_ptr<typename component_policy::Fqe_variable_type> three_RXsquared_plus_a;
                    std::shared_ptr<typename component_policy::Fqe_variable_type> two_RY;
                    std::shared_ptr<typename component_policy::Fqe_mul_component_type> compute_gamma;
                    std::shared_ptr<typename component_policy::Fqe_mul_component_type> compute_gamma_X;

                    std::shared_ptr<typename component_policy::Fqe_variable_type> next_RX_plus_two_RX;
                    std::shared_ptr<typename component_policy::Fqe_sqr_component_type> compute_next_RX;

                    std::shared_ptr<typename component_policy::Fqe_variable_type> RX_minus_next_RX;
                    std::shared_ptr<typename component_policy::Fqe_variable_type> RY_plus_next_RY;
                    std::shared_ptr<typename component_policy::Fqe_mul_component_type> compute_next_RY;

                    precompute_G2_component_doubling_step(blueprint<FieldType> &bp,
                                                          const precompute_G2_component_coeffs<CurveType> &cur,
                                                          const precompute_G2_component_coeffs<CurveType> &next) :
                        component<FieldType>(bp),
                        cur(cur), next(next) {
                        RXsquared.reset(new typename component_policy::Fqe_variable_type(bp));
                        compute_RXsquared.reset(
                            new typename component_policy::Fqe_sqr_component_type(bp, *(cur.RX), *RXsquared));
                        three_RXsquared_plus_a.reset(new typename component_policy::Fqe_variable_type(
                            (*RXsquared) * typename FieldType::value_type(0x03) +
                            detail::basic_pairing_component_policy<
                                typename CurveType::pairing::pair_curve_type>::g2_coeff_a));

                        two_RY.reset(new typename component_policy::Fqe_variable_type(
                            *(cur.RY) * typename FieldType::value_type(0x02)));

                        compute_gamma.reset(new typename component_policy::Fqe_mul_component_type(
                            bp, *(cur.gamma), *two_RY, *three_RXsquared_plus_a));
                        compute_gamma_X.reset(new typename component_policy::Fqe_mul_component_type(
                            bp, *(cur.gamma), *(cur.RX), *(cur.gamma_X)));

                        next_RX_plus_two_RX.reset(new typename component_policy::Fqe_variable_type(
                            *(next.RX) + *(cur.RX) * typename FieldType::value_type(0x02)));
                        compute_next_RX.reset(new typename component_policy::Fqe_sqr_component_type(
                            bp, *(cur.gamma), *next_RX_plus_two_RX));

                        RX_minus_next_RX.reset(new typename component_policy::Fqe_variable_type(
                            *(cur.RX) + *(next.RX) * (-FieldType::value_type::one())));
                        RY_plus_next_RY.reset(new typename component_policy::Fqe_variable_type(*(cur.RY) + *(next.RY)));
                        compute_next_RY.reset(new typename component_policy::Fqe_mul_component_type(
                            bp, *(cur.gamma), *RX_minus_next_RX, *RY_plus_next_RY));
                    }

                    void generate_r1cs_constraints() {
                        compute_RXsquared->generate_r1cs_constraints();
                        compute_gamma->generate_r1cs_constraints();
                        compute_gamma_X->generate_r1cs_constraints();
                        compute_next_RX->generate_r1cs_constraints();
                        compute_next_RY->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        compute_RXsquared->generate_r1cs_witness();
                        two_RY->evaluate();
                        three_RXsquared_plus_a->evaluate();

                        const typename fqe_type::value_type three_RXsquared_plus_a_val =
                            three_RXsquared_plus_a->get_element();
                        const typename fqe_type::value_type two_RY_val = two_RY->get_element();
                        const typename fqe_type::value_type gamma_val =
                            three_RXsquared_plus_a_val * two_RY_val.inversed();
                        cur.gamma->generate_r1cs_witness(gamma_val);

                        compute_gamma->generate_r1cs_witness();
                        compute_gamma_X->generate_r1cs_witness();

                        const typename fqe_type::value_type RX_val = cur.RX->get_element();
                        const typename fqe_type::value_type RY_val = cur.RY->get_element();
                        const typename fqe_type::value_type next_RX_val = gamma_val.squared() - RX_val - RX_val;
                        const typename fqe_type::value_type next_RY_val = gamma_val * (RX_val - next_RX_val) - RY_val;

                        next.RX->generate_r1cs_witness(next_RX_val);
                        next.RY->generate_r1cs_witness(next_RY_val);

                        RX_minus_next_RX->evaluate();
                        RY_plus_next_RY->evaluate();

                        compute_next_RX->generate_r1cs_witness();
                        compute_next_RY->generate_r1cs_witness();
                    }
                };

                /**
                 * Technical note:
                 *
                 * g2_precompute_addition_step relates coeffs[i] and coeffs[i+1] as follows
                 *
                 * coeffs[i]
                 * gamma = (RY - QY) * (RX - QX).inversed()
                 * gamma_X = gamma * QX
                 *
                 * coeffs[i+1]
                 * RX = prev_gamma^2 + (prev_RX + QX)
                 * RY = prev_gamma * (prev_RX - RX) - prev_RY
                 *
                 * (where prev_ in [i+1] refer to things from [i])
                 *
                 * If invert_Q is set to true: use -QY in place of QY everywhere above.
                 */
                template<typename CurveType>
                class precompute_G2_component_addition_step : public component<typename CurveType::scalar_field_type> {
                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                public:
                    typedef typename CurveType::pairing::fp_type FieldType;
                    using fqe_type = typename CurveType::pairing::pair_curve_type::pairing::fqe_type;

                    bool invert_Q;
                    precompute_G2_component_coeffs<CurveType> cur;
                    precompute_G2_component_coeffs<CurveType> next;
                    element_g2<CurveType> Q;

                    std::shared_ptr<typename component_policy::Fqe_variable_type> RY_minus_QY;
                    std::shared_ptr<typename component_policy::Fqe_variable_type> RX_minus_QX;
                    std::shared_ptr<typename component_policy::Fqe_mul_component_type> compute_gamma;
                    std::shared_ptr<typename component_policy::Fqe_mul_component_type> compute_gamma_X;

                    std::shared_ptr<typename component_policy::Fqe_variable_type> next_RX_plus_RX_plus_QX;
                    std::shared_ptr<typename component_policy::Fqe_sqr_component_type> compute_next_RX;

                    std::shared_ptr<typename component_policy::Fqe_variable_type> RX_minus_next_RX;
                    std::shared_ptr<typename component_policy::Fqe_variable_type> RY_plus_next_RY;
                    std::shared_ptr<typename component_policy::Fqe_mul_component_type> compute_next_RY;

                    precompute_G2_component_addition_step(blueprint<FieldType> &bp,
                                                          const bool invert_Q,
                                                          const precompute_G2_component_coeffs<CurveType> &cur,
                                                          const precompute_G2_component_coeffs<CurveType> &next,
                                                          const element_g2<CurveType> &Q) :
                        component<FieldType>(bp),
                        invert_Q(invert_Q), cur(cur), next(next), Q(Q) {
                        RY_minus_QY.reset(new typename component_policy::Fqe_variable_type(
                            *(cur.RY) +
                            *(Q.Y) * (!invert_Q ? -FieldType::value_type::one() : FieldType::value_type::one())));

                        RX_minus_QX.reset(new typename component_policy::Fqe_variable_type(
                            *(cur.RX) + *(Q.X) * (-FieldType::value_type::one())));
                        compute_gamma.reset(new typename component_policy::Fqe_mul_component_type(
                            bp, *(cur.gamma), *RX_minus_QX, *RY_minus_QY));
                        compute_gamma_X.reset(new typename component_policy::Fqe_mul_component_type(
                            bp, *(cur.gamma), *(Q.X), *(cur.gamma_X)));

                        next_RX_plus_RX_plus_QX.reset(
                            new typename component_policy::Fqe_variable_type(*(next.RX) + *(cur.RX) + *(Q.X)));
                        compute_next_RX.reset(new typename component_policy::Fqe_sqr_component_type(
                            bp, *(cur.gamma), *next_RX_plus_RX_plus_QX));

                        RX_minus_next_RX.reset(new typename component_policy::Fqe_variable_type(
                            *(cur.RX) + *(next.RX) * (-FieldType::value_type::one())));
                        RY_plus_next_RY.reset(new typename component_policy::Fqe_variable_type(*(cur.RY) + *(next.RY)));
                        compute_next_RY.reset(new typename component_policy::Fqe_mul_component_type(
                            bp, *(cur.gamma), *RX_minus_next_RX, *RY_plus_next_RY));
                    }

                    void generate_r1cs_constraints() {
                        compute_gamma->generate_r1cs_constraints();
                        compute_gamma_X->generate_r1cs_constraints();
                        compute_next_RX->generate_r1cs_constraints();
                        compute_next_RY->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        RY_minus_QY->evaluate();
                        RX_minus_QX->evaluate();

                        const typename fqe_type::value_type RY_minus_QY_val = RY_minus_QY->get_element();
                        const typename fqe_type::value_type RX_minus_QX_val = RX_minus_QX->get_element();
                        const typename fqe_type::value_type gamma_val = RY_minus_QY_val * RX_minus_QX_val.inversed();
                        cur.gamma->generate_r1cs_witness(gamma_val);

                        compute_gamma->generate_r1cs_witness();
                        compute_gamma_X->generate_r1cs_witness();

                        const typename fqe_type::value_type RX_val = cur.RX->get_element();
                        const typename fqe_type::value_type RY_val = cur.RY->get_element();
                        const typename fqe_type::value_type QX_val = Q.X->get_element();
                        const typename fqe_type::value_type next_RX_val = gamma_val.squared() - RX_val - QX_val;
                        const typename fqe_type::value_type next_RY_val = gamma_val * (RX_val - next_RX_val) - RY_val;

                        next.RX->generate_r1cs_witness(next_RX_val);
                        next.RY->generate_r1cs_witness(next_RY_val);

                        next_RX_plus_RX_plus_QX->evaluate();
                        RX_minus_next_RX->evaluate();
                        RY_plus_next_RY->evaluate();

                        compute_next_RX->generate_r1cs_witness();
                        compute_next_RY->generate_r1cs_witness();
                    }
                };

                /**
                 * Component that verifies correct precomputation of the G2 element.
                 */
                template<typename CurveType>
                class precompute_G2_component : public component<typename CurveType::scalar_field_type> {
                    using component_policy = detail::basic_pairing_component_policy<CurveType>;

                public:
                    typedef typename CurveType::pairing::fp_type FieldType;

                    std::vector<std::shared_ptr<precompute_G2_component_addition_step<CurveType>>> addition_steps;
                    std::vector<std::shared_ptr<precompute_G2_component_doubling_step<CurveType>>> doubling_steps;

                    std::size_t add_count;
                    std::size_t dbl_count;

                    g2_precomputation<CurveType> &precomp;    // important to have a reference here

                    precompute_G2_component(blueprint<FieldType> &bp,
                                            const element_g2<CurveType> &Q,
                                            g2_precomputation<CurveType> &precomp) :
                        component<FieldType>(bp),
                        precomp(precomp) {
                        precomp.Q.reset(new element_g2<CurveType>(Q));

                        std::size_t coeff_count = 1;    // the last RX/RY are unused in Miller loop, but will need
                                                        // to get allocated somehow
                        this->add_count = 0;
                        this->dbl_count = 0;

                        bool found_nonzero = false;
                        std::vector<long> NAF = find_wnaf(1, CurveType::pairing::pairing_loop_count);

                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            ++dbl_count;
                            ++coeff_count;

                            if (NAF[i] != 0) {
                                ++add_count;
                                ++coeff_count;
                            }
                        }

                        precomp.coeffs.resize(coeff_count);
                        addition_steps.resize(add_count);
                        doubling_steps.resize(dbl_count);

                        precomp.coeffs[0].reset(new precompute_G2_component_coeffs<CurveType>(bp, Q));
                        for (std::size_t i = 1; i < coeff_count; ++i) {
                            precomp.coeffs[i].reset(new precompute_G2_component_coeffs<CurveType>(bp));
                        }

                        std::size_t add_id = 0;
                        std::size_t dbl_id = 0;
                        std::size_t coeff_id = 0;

                        found_nonzero = false;
                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            doubling_steps[dbl_id].reset(new precompute_G2_component_doubling_step<CurveType>(
                                bp, *(precomp.coeffs[coeff_id]), *(precomp.coeffs[coeff_id + 1])));
                            ++dbl_id;
                            ++coeff_id;

                            if (NAF[i] != 0) {
                                addition_steps[add_id].reset(new precompute_G2_component_addition_step<CurveType>(
                                    bp, NAF[i] < 0, *(precomp.coeffs[coeff_id]), *(precomp.coeffs[coeff_id + 1]), Q));
                                ++add_id;
                                ++coeff_id;
                            }
                        }
                    }

                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < dbl_count; ++i) {
                            doubling_steps[i]->generate_r1cs_constraints();
                        }

                        for (std::size_t i = 0; i < add_count; ++i) {
                            addition_steps[i]->generate_r1cs_constraints();
                        }
                    }

                    void generate_r1cs_witness() {
                        precomp.coeffs[0]->RX->generate_r1cs_witness(precomp.Q->X->get_element());
                        precomp.coeffs[0]->RY->generate_r1cs_witness(precomp.Q->Y->get_element());

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
                            ++dbl_id;

                            if (NAF[i] != 0) {
                                addition_steps[add_id]->generate_r1cs_witness();
                                ++add_id;
                            }
                        }
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_AS_WAKSMAN_HPP
