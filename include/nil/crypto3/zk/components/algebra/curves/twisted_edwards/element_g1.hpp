//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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
// @file Declaration of interfaces for G1 components.
//
// The components verify curve arithmetic in G1 = E(F) where E/F: a * x^2 + y^2 = 1 + d * x^2 * y^2
// is an elliptic curve over F in Twisted Edwards form.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_TWISTED_EDWARDS_G1_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_TWISTED_EDWARDS_G1_COMPONENT_HPP

#include <nil/crypto3/zk/components/algebra/curves/element_g1_affine.hpp>
#include <nil/crypto3/zk/components/algebra/fields/field_to_bits.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                /**
                 * @brief Component that creates constraints for the addition of two elements from G1.
                 */
                template<typename Curve>
                struct element_g1_addition<Curve,
                                           algebra::curves::forms::twisted_edwards,
                                           algebra::curves::coordinates::affine>
                    : public component<typename element_g1<Curve,
                                                           algebra::curves::forms::twisted_edwards,
                                                           algebra::curves::coordinates::affine>::field_type> {
                    using curve_type = Curve;
                    using form = algebra::curves::forms::twisted_edwards;
                    using coordinates = algebra::curves::coordinates::affine;

                    using element_component = element_g1<curve_type, form, coordinates>;

                    using field_type = typename element_component::field_type;
                    using group_type = typename element_component::group_type;

                    using result_type = element_component;

                    const element_component p1;
                    const element_component p2;
                    result_type result;

                    // Intermediate variables
                    element_fp<field_type> X1X2;
                    element_fp<field_type> X1Y2;
                    element_fp<field_type> Y1Y2;
                    element_fp<field_type> Y1X2;
                    element_fp<field_type> X1X2Y1Y2;
                    element_fp<field_type> dX1X2Y1Y2;
                    element_fp<field_type> aX1X2;

                private:
                    void init() {
                        detail::blueprint_variable<field_type> X1X2_var, X1Y2_var, Y1Y2_var, Y1X2_var, X1X2Y1Y2_var,
                            dX1X2Y1Y2_var, aX1X2_var;

                        X1X2_var.allocate(this->bp);
                        X1Y2_var.allocate(this->bp);
                        Y1Y2_var.allocate(this->bp);
                        Y1X2_var.allocate(this->bp);
                        X1X2Y1Y2_var.allocate(this->bp);
                        dX1X2Y1Y2_var.allocate(this->bp);
                        aX1X2_var.allocate(this->bp);

                        this->X1X2 = X1X2_var;
                        this->X1Y2 = X1Y2_var;
                        this->Y1Y2 = Y1Y2_var;
                        this->Y1X2 = Y1X2_var;
                        this->X1X2Y1Y2 = X1X2Y1Y2_var;
                        this->dX1X2Y1Y2 = dX1X2Y1Y2_var;
                        this->aX1X2 = aX1X2_var;
                    }

                public:
                    /// Auto allocation of the result
                    element_g1_addition(blueprint<field_type> &bp,
                                        const element_component &in_p1,
                                        const element_component &in_p2) :
                        component<field_type>(bp),
                        p1(in_p1), p2(in_p2), result(bp) {
                        init();
                    }

                    /// Manual allocation of the result
                    element_g1_addition(blueprint<field_type> &bp,
                                        const element_component &in_p1,
                                        const element_component &in_p2,
                                        const result_type &in_result) :
                        component<field_type>(bp),
                        p1(in_p1), p2(in_p2), result(in_result) {
                        init();
                    }

                    void generate_r1cs_constraints() {
                        //  X3 = (X1*Y2 + Y1*X2) / (Fq.ONE + D*X1*X2*Y1*Y2)
                        //  y3 = (Y1*Y2 - A*X1*X2) / (Fq.ONE - D*X1*X2*Y1*Y2)
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->p1.Y}, {this->p2.X}, {this->Y1X2}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->p1.X}, {this->p2.Y}, {this->X1Y2}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->p1.X}, {this->p2.X}, {this->X1X2}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->p1.Y}, {this->p2.Y}, {this->Y1Y2}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->X1X2}, {this->Y1Y2}, {this->X1X2Y1Y2}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            {group_type::params_type::d}, {this->X1X2Y1Y2}, {this->dX1X2Y1Y2}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            {group_type::params_type::a}, {this->X1X2}, {this->aX1X2}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->result.Y},
                                                               {field_type::value_type::one(), -(this->dX1X2Y1Y2)},
                                                               {this->Y1Y2, -(this->aX1X2)}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->result.X},
                                                               {field_type::value_type::one(), this->dX1X2Y1Y2},
                                                               {this->X1Y2, this->Y1X2}));
                    }

                    void generate_r1cs_witness() {
                        const typename field_type::value_type &x1 = this->bp.lc_val(this->p1.X);
                        const typename field_type::value_type &y1 = this->bp.lc_val(this->p1.Y);
                        const typename field_type::value_type &x2 = this->bp.lc_val(this->p2.X);
                        const typename field_type::value_type &y2 = this->bp.lc_val(this->p2.Y);

                        this->bp.lc_val(X1X2) = x1 * x2;
                        this->bp.lc_val(X1Y2) = x1 * y2;
                        this->bp.lc_val(Y1Y2) = y1 * y2;
                        this->bp.lc_val(Y1X2) = y1 * x2;
                        this->bp.lc_val(X1X2Y1Y2) = this->bp.lc_val(X1X2) * this->bp.lc_val(Y1Y2);
                        this->bp.lc_val(dX1X2Y1Y2) =
                            static_cast<typename field_type::value_type>(group_type::params_type::d) *
                            this->bp.lc_val(X1X2Y1Y2);
                        this->bp.lc_val(aX1X2) =
                            static_cast<typename field_type::value_type>(group_type::params_type::a) *
                            this->bp.lc_val(X1X2);
                        this->bp.lc_val(this->result.X) =
                            (this->bp.lc_val(X1Y2) + this->bp.lc_val(Y1X2)) *
                            (field_type::value_type::one() + this->bp.lc_val(dX1X2Y1Y2)).inversed();
                        this->bp.lc_val(this->result.Y) =
                            (this->bp.lc_val(Y1Y2) - this->bp.lc_val(aX1X2)) *
                            (field_type::value_type::one() - this->bp.lc_val(dX1X2Y1Y2)).inversed();
                    }
                };

                /**
                 * @brief Component that creates constraints for the validity of a G1 element. (if element from group G1
                 * lies on the elliptic curve)
                 */
                template<typename Curve>
                struct element_g1_is_well_formed<Curve,
                                                 algebra::curves::forms::twisted_edwards,
                                                 algebra::curves::coordinates::affine>
                    : public component<typename element_g1<Curve,
                                                           algebra::curves::forms::twisted_edwards,
                                                           algebra::curves::coordinates::affine>::field_type> {
                    using curve_type = Curve;
                    using form = algebra::curves::forms::twisted_edwards;
                    using coordinates = algebra::curves::coordinates::affine;

                    using element_component = element_g1<curve_type, form, coordinates>;

                    using field_type = typename element_component::field_type;
                    using group_type = typename element_component::group_type;

                    const element_component p;

                    // Intermediate variables
                    element_fp<field_type> XX;
                    element_fp<field_type> aXX;
                    element_fp<field_type> dXX;
                    element_fp<field_type> YY;
                    element_fp<field_type> dXXYY;
                    element_fp<field_type> lhs;
                    element_fp<field_type> rhs;

                    element_g1_is_well_formed(blueprint<field_type> &bp, const element_component &in_p) :
                        component<field_type>(bp), p(in_p) {
                        detail::blueprint_variable<field_type> XX_var, aXX_var, dXX_var, YY_var, dXXYY_var, lhs_var, rhs_var;

                        XX_var.allocate(this->bp);
                        aXX_var.allocate(this->bp);
                        dXX_var.allocate(this->bp);
                        YY_var.allocate(this->bp);
                        dXXYY_var.allocate(this->bp);
                        lhs_var.allocate(this->bp);
                        rhs_var.allocate(this->bp);

                        this->XX = XX_var;
                        this->aXX = aXX_var;
                        this->dXX = dXX_var;
                        this->YY = YY_var;
                        this->dXXYY = dXXYY_var;
                        this->lhs = lhs_var;
                        this->rhs = rhs_var;
                    }

                    void generate_r1cs_constraints() {
                        // a*X*X + Y*Y = 1 + d*X*X*Y*Y
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->p.X}, {this->p.X}, {this->XX}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->p.Y}, {this->p.Y}, {this->YY}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({group_type::params_type::a}, {this->XX}, {this->aXX}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            {this->aXX, this->YY}, {field_type::value_type::one()}, {this->lhs}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({group_type::params_type::d}, {this->XX}, {this->dXX}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->dXX}, {this->YY}, {this->dXXYY}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->dXXYY, field_type::value_type::one()},
                                                               {field_type::value_type::one()},
                                                               {this->rhs}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            {this->lhs}, {field_type::value_type::one()}, {this->rhs}));
                    }

                    void generate_r1cs_witness() {
                        const typename field_type::value_type &x = this->bp.lc_val(this->p.X);
                        const typename field_type::value_type &y = this->bp.lc_val(this->p.Y);

                        this->bp.lc_val(this->XX) = x * x;
                        this->bp.lc_val(this->YY) = y * y;
                        this->bp.lc_val(this->aXX) =
                            static_cast<typename field_type::value_type>(group_type::params_type::a) *
                            this->bp.lc_val(this->XX);
                        this->bp.lc_val(this->lhs) = this->bp.lc_val(this->aXX) + this->bp.lc_val(this->YY);
                        this->bp.lc_val(this->dXX) =
                            static_cast<typename field_type::value_type>(group_type::params_type::d) *
                            this->bp.lc_val(this->XX);
                        this->bp.lc_val(this->dXXYY) = this->bp.lc_val(this->dXX) * this->bp.lc_val(this->YY);
                        this->bp.lc_val(this->rhs) = this->bp.lc_val(this->dXXYY) + field_type::value_type::one();
                    }
                };

                /**
                 * @brief Component that creates constraints for the point serialization into the bit sequence
                 * according to https://zips.z.cash/protocol/protocol.pdf#concreteextractorjubjub
                 */
                template<typename Curve>
                struct element_g1_to_bits<Curve,
                                          algebra::curves::forms::twisted_edwards,
                                          algebra::curves::coordinates::affine>
                    : public component<typename element_g1<Curve,
                                                           algebra::curves::forms::twisted_edwards,
                                                           algebra::curves::coordinates::affine>::field_type> {
                    using curve_type = Curve;
                    using form = algebra::curves::forms::twisted_edwards;
                    using coordinates = algebra::curves::coordinates::affine;

                    using element_component = element_g1<curve_type, form, coordinates>;

                    using field_type = typename element_component::field_type;
                    using group_type = typename element_component::group_type;

                    using field_to_bits_component = field_to_bits_strict<field_type>;
                    using result_type = typename field_to_bits_component::result_type;

                    field_to_bits_component field_to_bits_converter;
                    result_type &result;

                    /// Auto allocation of the result
                    element_g1_to_bits(blueprint<field_type> &bp, const element_component &in_p) :
                        component<field_type>(bp), field_to_bits_converter(bp, in_p.X),
                        result(field_to_bits_converter.result) {
                    }

                    /// Manual allocation of the result
                    element_g1_to_bits(blueprint<field_type> &bp,
                                       const element_component &in_p,
                                       const result_type &in_result) :
                        component<field_type>(bp),
                        field_to_bits_converter(bp, in_p.X, in_result), result(field_to_bits_converter.result) {
                    }

                    void generate_r1cs_constraints() {
                        this->field_to_bits_converter.generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        this->field_to_bits_converter.generate_r1cs_witness();
                    }
                };

                /**
                 * @brief Component that creates constraints for the addition of two elements from G1.
                 */
                // TODO: fixme
                template<typename Curve>
                struct element_g1_conditional_addition<Curve,
                                                       algebra::curves::forms::twisted_edwards,
                                                       algebra::curves::coordinates::affine>
                    : public component<typename element_g1<Curve,
                                                           algebra::curves::forms::twisted_edwards,
                                                           algebra::curves::coordinates::affine>::field_type> {
                    using curve_type = Curve;
                    using form = algebra::curves::forms::twisted_edwards;
                    using coordinates = algebra::curves::coordinates::affine;

                    using element_component = element_g1<curve_type, form, coordinates>;

                    using field_type = typename element_component::field_type;
                    using group_type = typename element_component::group_type;

                    const element_component p1;
                    const element_component p2;
                    element_component result;

                    const detail::blueprint_variable<field_type> can_add;

                    // intermediate variables
                    element_component p_to_add;
                    element_fp<field_type> Y_intermediate_to_add1;
                    element_fp<field_type> Y_intermediate_to_add2;
                    detail::blueprint_variable<field_type> cannot_add;

                    // TODO: refactor
                    // std::shared_ptr<element_g1_add<CurveType>> el_add;

                    element_g1_conditional_addition(blueprint<field_type> &bp,
                                                    const element_component &in_p1,
                                                    const element_component &in_p2,
                                                    const detail::blueprint_variable<field_type> &in_can_add,
                                                    const element_component &in_result) :
                        component<field_type>(bp),
                        p1(in_p1), p2(in_p2), can_add(in_can_add), p_to_add(bp), result(in_result) {
                        detail::blueprint_variable<field_type> Y_intermediate_to_add1_var, Y_intermediate_to_add2_var;

                        Y_intermediate_to_add1_var.allocate(this->bp);
                        Y_intermediate_to_add2_var.allocate(this->bp);
                        cannot_add.allocate(this->bp);

                        this->Y_intermediate_to_add1 = Y_intermediate_to_add1_var;
                        this->Y_intermediate_to_add2 = Y_intermediate_to_add2_var;

                        // TODO: refactor
                        // el_add.reset(new element_g1_add<CurveType>(this->bp, a, d, p1, P_toAdd, p1pp2));
                    }

                    void generate_r1cs_constraints() {
                        // if coef == 1 then x_ret[i] + x_base
                        // x_add[i] = coef[i] * x_base;
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->p2.X}, {this->can_add}, {this->p_to_add.X}));

                        // else do nothing. Ie add the zero point (0, 1)
                        // y_add[i] = coef[i] * y_base + !coef[i];
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            {this->p2.Y}, {this->can_add}, {this->Y_intermediate_to_add1}));

                        // not coef
                        //  make sure canAdd == 0 or canAdd == 1
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(this->can_add,
                                                               field_type::value_type::one() - this->can_add,
                                                               field_type::value_type::zero()));

                        // make sure not_canAdd == 0 or not_canAdd == 1
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(this->cannot_add,
                                                               field_type::value_type::one() - this->cannot_add,
                                                               field_type::value_type::zero()));

                        // make sure that the sum of canAdd, not_canAdd == 1 which means canAdd!=not_canAdd
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->cannot_add, this->can_add},
                                                               {field_type::value_type::one()},
                                                               {field_type::value_type::one()}));

                        // because the are bool and because they are not equal we know that the inverse of one is the
                        // other.
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            {this->cannot_add}, {field_type::value_type::one()}, {this->Y_intermediate_to_add2}));

                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            {this->Y_intermediate_to_add1, this->Y_intermediate_to_add2},
                            {field_type::value_type::one()},
                            {this->p_to_add.Y}));

                        // TODO: refactor
                        // do the addition of either y1 , y1 plus x2, y2 if canAdd == true else x1 , y1 + 0
                        // el_add->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        this->bp.lc_val(this->p_to_add.X) = this->bp.lc_val(this->p2.X) * this->bp.val(this->can_add);
                        this->bp.lc_val(this->Y_intermediate_to_add1) =
                            this->bp.lc_val(this->p2.Y) * this->bp.val(this->can_add);

                        if (this->bp.val(this->can_add) == field_type::value_type::one()) {
                            this->bp.val(this->cannot_add) = field_type::value_type::zero();
                            this->bp.lc_val(this->Y_intermediate_to_add2) =
                                this->bp.val(this->cannot_add) * field_type::value_type::one();
                            this->bp.lc_val(this->p_to_add.Y) = this->bp.lc_val(this->Y_intermediate_to_add1);
                        } else {
                            this->bp.val(this->cannot_add) = field_type::value_type::one();
                            this->bp.lc_val(this->Y_intermediate_to_add2) =
                                this->bp.val(this->cannot_add) * field_type::value_type::one();
                            this->bp.lc_val(this->p_to_add.Y) = field_type::value_type::one();
                        }

                        // TODO: refactor
                        // el_add->generate_r1cs_witness();
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_TWISTED_EDWARDS_G1_COMPONENT_HPP
