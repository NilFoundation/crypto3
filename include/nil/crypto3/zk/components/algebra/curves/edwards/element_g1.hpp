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
// @file Declaration of interfaces for G1 components.
//
// TODO: Change the curve equation
// The components verify curve arithmetic in G1 = E(F) where E/F: y^2 = x^3 + A * X + B
// is an elliptic curve over F in short Weierstrass form.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_TWISTED_EDWARDS_G1_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_TWISTED_EDWARDS_G1_COMPONENT_HPP

#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/algebra/fields/element_fp.hpp>

#include <nil/crypto3/zk/components/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                /**
                 * Component that represents a G1 element for JubJub/Bls12-381 and BabyJubJub/Alt-BN128.
                 *
                 * CurveType is BLS12-381 or BN128
                 */
                template<typename CurveType>
                class element_g1 : public component<typename CurveType::scalar_field_type> {
                    using underlying_field_type = typename CurveType::scalar_field_type;
                    using underlying_element_type = element_fp<scalar_field_type>;

                public:
                    underlying_element_type X;
                    underlying_element_type Y;

                    blueprint_linear_combination_vector<scalar_field_type> all_vars;

                    element_g1(blueprint<scalar_field_type> &bp) : component<scalar_field_type>(bp) {
                        blueprint_variable<scalar_field_type> X_var, Y_var;

                        X_var.allocate(bp);
                        Y_var.allocate(bp);

                        X = underlying_element_type(X_var);
                        Y = underlying_element_type(Y_var);

                        all_vars.emplace_back(X);
                        all_vars.emplace_back(Y);
                    }

                    element_g1(blueprint<scalar_field_type> &bp,
                               const typename CurveType::pairing::chained_curve_type::g1_type::value_type &P) :
                        component<scalar_field_type>(bp) {

                        // typename CurveType::pairing::chained_curve_type::g1_type::value_type Pcopy =
                        //     P.to_affine();

                        X.assign(bp, P.X);
                        Y.assign(bp, P.Y);
                        X.evaluate(bp);
                        Y.evaluate(bp);
                        all_vars.emplace_back(X);
                        all_vars.emplace_back(Y);
                    }

                    void generate_r1cs_witness(
                        const typename CurveType::pairing::chained_curve_type::g1_type::value_type &el) {
                        typename CurveType::pairing::chained_curve_type::g1_type::value_type el_normalized =
                            el.to_affine();

                        this->bp.lc_val(X) = el_normalized.X;
                        this->bp.lc_val(Y) = el_normalized.Y;
                    }

                    // (See a comment in r1cs_ppzksnark_verifier_component.hpp about why
                    // we mark this function noinline.) TODO: remove later
                    static std::size_t __attribute__((noinline)) size_in_bits() {
                        return 2 * scalar_field_type::modulus_bits;    // This probably should be value_bits, not
                                                                       // modulus_bits
                    }
                    static std::size_t num_variables() {
                        return 2;
                    }
                };

                /**
                 * Component that creates constraints for the validity of a G1 element.
                 * (if element from group G1 lies on the elliptic curve)
                 */
                template<typename CurveType>
                class element_g1_is_well_formed : public component<typename CurveType::scalar_field_type> {
                    typedef typename CurveType::scalar_field_type scalar_field_type;

                public:
                    element_g1<CurveType> P;

                    blueprint_variable<scalar_field_type> a;
                    blueprint_variable<scalar_field_type> d;

                    // Intermeditate variables:
                    blueprint_variable<scalar_field_type> XX;
                    blueprint_variable<scalar_field_type> aXX;
                    blueprint_variable<scalar_field_type> dXX;
                    blueprint_variable<scalar_field_type> YY;
                    blueprint_variable<scalar_field_type> dXXYY;
                    blueprint_variable<scalar_field_type> lhs;
                    blueprint_variable<scalar_field_type> rhs;

                    element_g1_is_well_formed(blueprint<scalar_field_type> &bp,
                                              blueprint_variable<scalar_field_type>
                                                  a,
                                              blueprint_variable<scalar_field_type>
                                                  d,
                                              const element_g1<CurveType> &P) :
                        component<scalar_field_type>(bp),
                        P(P), a(a), d(d) {

                        XX.allocate(this->bp);
                        aXX.allocate(this->bp);
                        dXX.allocate(this->bp);
                        YY.allocate(this->bp);
                        dXXYY.allocate(this->bp);
                        lhs.allocate(this->bp);
                        rhs.allocate(this->bp);
                    }
                    void generate_r1cs_constraints() {
                        // A check, that a*X*X + Y*Y = 1 + d*X*X*Y*Y

                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>({P.X}, {P.X}, {XX}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>({P.Y}, {P.Y}, {YY}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>({a}, {XX}, {aXX}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>(
                            {aXX, YY}, {scalar_field_type::value_type::one()}, {lhs}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>({d}, {XX}, {dXX}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>({dXX}, {YY}, {dXXYY}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<scalar_field_type>({dXXYY, scalar_field_type::value_type::one()},
                                                                      {scalar_field_type::value_type::one()},
                                                                      {rhs}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>(
                            {lhs}, {scalar_field_type::value_type::one()}, {rhs}));
                    }
                    void generate_r1cs_witness() {
                        typename scalar_field_type::value_type x = this->bp.lc_val(this->P.X);
                        typename scalar_field_type::value_type y = this->bp.lc_val(this->P.Y);
                        typename scalar_field_type::value_type temp_a = this->bp.val(this->a);
                        typename scalar_field_type::value_type temp_d = this->bp.val(this->d);

                        // this->bp.val(this->P.X) = x;
                        // this->bp.val(this->P.Y) = y;
                        // this->bp.val(this->a) = temp_a;
                        // this->bp.val(this->d) = temp_d;

                        this->bp.val(this->XX) = x * x;
                        this->bp.val(this->YY) = y * y;
                        this->bp.val(this->aXX) = temp_a * x * x;
                        this->bp.val(this->lhs) = temp_a * x * x + y * y;
                        this->bp.val(this->dXX) = x * x * temp_d;
                        this->bp.val(this->dXXYY) = temp_d * x * x * y * y;

                        this->bp.val(this->rhs) = temp_d * x * x * y * y + scalar_field_type::value_type::one();
                    }
                };

                /**
                 * Component that creates constraints for the validity of a G1 element.
                 * (if element from group G1 lies on the elliptic curve)
                 */
                template<typename CurveType>
                class element_g1_add : public component<typename CurveType::scalar_field_type> {
                    typedef typename CurveType::scalar_field_type scalar_field_type;

                public:
                    blueprint_variable<scalar_field_type> a;
                    blueprint_variable<scalar_field_type> d;

                    element_g1<CurveType> P1;
                    element_g1<CurveType> P2;
                    element_g1<CurveType> P1pP2;

                    // std::shared_ptr<element_g1_is_well_formed<CurveType>> el_is_well_formed;

                    // intermeditate variables
                    blueprint_variable<scalar_field_type> X1X2;
                    blueprint_variable<scalar_field_type> X1Y2;
                    blueprint_variable<scalar_field_type> Y1Y2;
                    blueprint_variable<scalar_field_type> Y1X2;
                    blueprint_variable<scalar_field_type> X1X2Y1Y2;
                    blueprint_variable<scalar_field_type> dX1X2Y1Y2;
                    blueprint_variable<scalar_field_type> aX1X2;

                    element_g1_add(blueprint<scalar_field_type> &bp,
                                   blueprint_variable<scalar_field_type>
                                       a,
                                   blueprint_variable<scalar_field_type>
                                       d,
                                   const element_g1<CurveType> &P1,
                                   const element_g1<CurveType> &P2,
                                   const element_g1<CurveType> &P1pP2) :
                        component<scalar_field_type>(bp),
                        P1(P1), P2(P2), P1pP2(P1pP2), a(a), d(d) {

                        // el_is_well_formed.reset(
                        //     new element_g1_is_well_formed <CurveType> (
                        //         this->bp, a, d, P1pP2));

                        X1X2.allocate(this->bp);
                        X1Y2.allocate(this->bp);
                        Y1Y2.allocate(this->bp);
                        Y1X2.allocate(this->bp);
                        X1X2Y1Y2.allocate(this->bp);
                        dX1X2Y1Y2.allocate(this->bp);
                        aX1X2.allocate(this->bp);
                    }
                    void generate_r1cs_constraints() {
                        // A check, that
                        //  X3 = (X1*Y2 + Y1*X2) / (Fq.ONE + D*X1*X2*Y1*Y2)
                        //  y3 = (Y1*Y2 - A*X1*X2) / (Fq.ONE - D*X1*X2*Y1*Y2)

                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>({P1.Y}, {P2.X}, {Y1X2}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>({P1.X}, {P2.Y}, {X1Y2}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>({P1.X}, {P2.X}, {X1X2}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>({P1.Y}, {P2.Y}, {Y1Y2}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<scalar_field_type>({X1X2}, {Y1Y2}, {X1X2Y1Y2}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<scalar_field_type>({d}, {X1X2Y1Y2}, {dX1X2Y1Y2}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>({a}, {X1X2}, {aX1X2}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>(
                            {P1pP2.Y}, {scalar_field_type::value_type::one(), -dX1X2Y1Y2}, {Y1Y2, -aX1X2}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>(
                            {P1pP2.X}, {scalar_field_type::value_type::one(), dX1X2Y1Y2}, {X1Y2, Y1X2}));
                    }
                    void generate_r1cs_witness() {

                        typename scalar_field_type::value_type x1 = this->bp.lc_val(this->P1.X);
                        typename scalar_field_type::value_type y1 = this->bp.lc_val(this->P1.Y);
                        typename scalar_field_type::value_type x2 = this->bp.lc_val(this->P2.X);
                        typename scalar_field_type::value_type y2 = this->bp.lc_val(this->P2.Y);
                        typename scalar_field_type::value_type temp_a = this->bp.lc_val(this->a);
                        typename scalar_field_type::value_type temp_d = this->bp.lc_val(this->d);

                        this->bp.val(X1X2) = x1 * x2;
                        this->bp.val(X1Y2) = x1 * y2;
                        this->bp.val(Y1Y2) = y1 * y2;
                        this->bp.val(Y1X2) = y1 * x2;
                        this->bp.val(X1X2Y1Y2) = x1 * x2 * y1 * y2;
                        this->bp.val(dX1X2Y1Y2) = temp_d * x1 * x2 * y1 * y2;
                        this->bp.val(aX1X2) = temp_a * x1 * x2;

                        this->bp.lc_val(P1pP2.X) =
                            (x1 * y2 + y1 * x2) *
                            ((scalar_field_type::value_type::one() + (temp_d * x1 * x2 * y1 * y2)).inversed());
                        this->bp.lc_val(P1pP2.Y) =
                            (y1 * y2 - temp_a * x1 * x2) *
                            ((scalar_field_type::value_type::one() - (temp_d * x1 * x2 * y1 * y2)).inversed());

                        // el_is_well_formed->generate_r1cs_witness();
                    }
                };

                /**
                 * Component that creates constraints for the validity of a G1 element.
                 */
                template<typename CurveType>
                class element_g1_conditional_add : public component<typename CurveType::scalar_field_type> {
                    typedef typename CurveType::scalar_field_type scalar_field_type;

                public:
                    blueprint_variable<scalar_field_type> a;
                    blueprint_variable<scalar_field_type> d;

                    element_g1<CurveType> P1;
                    element_g1<CurveType> P2;
                    element_g1<CurveType> P1pP2;

                    blueprint_variable<scalar_field_type> canAdd;

                    // intermeditate variables
                    element_g1<CurveType> P_toAdd;
                    // blueprint_variable<scalar_field_type> x_toAdd;
                    // blueprint_variable<scalar_field_type> y_toAdd;
                    blueprint_variable<scalar_field_type> Y_intermediate_toAdd1;
                    blueprint_variable<scalar_field_type> Y_intermediate_toAdd2;
                    blueprint_variable<scalar_field_type> not_canAdd;

                    std::shared_ptr<element_g1_add<CurveType>> el_add;

                    element_g1_conditional_add(blueprint<scalar_field_type> &bp,
                                               blueprint_variable<scalar_field_type>
                                                   a,
                                               blueprint_variable<scalar_field_type>
                                                   d,
                                               const element_g1<CurveType> &P1,
                                               const element_g1<CurveType> &P2,
                                               const element_g1<CurveType> &P1pP2,
                                               blueprint_variable<scalar_field_type>
                                                   canAdd) :
                        component<scalar_field_type>(bp),
                        P1(P1), P2(P2), P1pP2(P1pP2), a(a), d(d), canAdd(canAdd), P_toAdd() {

                        Y_intermediate_toAdd1.allocate(this->bp);
                        Y_intermediate_toAdd2.allocate(this->bp);

                        not_canAdd.allocate(this->bp);

                        el_add.reset(new element_g1_add<CurveType>(this->bp, a, d, P1, P_toAdd, P1pP2));
                    }

                    void generate_r1cs_constraints() {
                        // if coef == 1 then x_ret[i] + x_base
                        // x_add[i] = coef[i] * x_base;
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<scalar_field_type>({P2.X}, {canAdd}, {P_toAdd.X}));

                        // else do nothing. Ie add the zero point (0, 1)
                        // y_add[i] = coef[i] * y_base + !coef[i];
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<scalar_field_type>({P2.Y}, {canAdd}, {Y_intermediate_toAdd1}));

                        // not coef
                        //  make sure canAdd == 0 or canAdd == 1
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<scalar_field_type>(canAdd,
                                                                      scalar_field_type::value_type::one() - canAdd,
                                                                      scalar_field_type::value_type::zero()));

                        // make sure not_canAdd == 0 or not_canAdd == 1
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<scalar_field_type>(not_canAdd,
                                                                      scalar_field_type::value_type::one() - not_canAdd,
                                                                      scalar_field_type::value_type::zero()));

                        // make sure that the sum of canAdd, not_canAdd == 1 which means canAdd!=not_canAdd
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<scalar_field_type>({not_canAdd, canAdd},
                                                                      {scalar_field_type::value_type::one()},
                                                                      {scalar_field_type::value_type::one()}));

                        // because the are bool and because they are not equal we know that the inverse of one
                        // is the other.
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<scalar_field_type>(
                            {not_canAdd}, {scalar_field_type::value_type::one()}, {Y_intermediate_toAdd2}));

                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<scalar_field_type>({Y_intermediate_toAdd1, Y_intermediate_toAdd2},
                                                                      {scalar_field_type::value_type::one()},
                                                                      {P_toAdd.Y}));

                        // do the addition of either y1 , y1 plus x2, y2 if canAdd == true else x1 , y1 + 0
                        el_add->generate_r1cs_constraints();
                    }
                    void generate_r1cs_witness() {
                        this->bp.lc_val(P_toAdd.X) = this->bp.lc_val(this->P2.X) * this->bp.val(this->canAdd);

                        this->bp.val(this->Y_intermediate_toAdd1) =
                            this->bp.lc_val(this->P2.Y) * this->bp.val(this->canAdd);

                        if (this->bp.val(this->canAdd) == scalar_field_type::value_type::one()) {

                            this->bp.val(this->not_canAdd) = scalar_field_type::value_type::zero();
                            this->bp.val(this->Y_intermediate_toAdd2) =
                                this->bp.val(this->not_canAdd) * scalar_field_type::value_type::one();
                            this->bp.lc_val(this->P_toAdd.Y) = this->bp.val(this->Y_intermediate_toAdd1);

                        } else {

                            this->bp.val(this->not_canAdd) = scalar_field_type::value_type::one();
                            this->bp.val(this->Y_intermediate_toAdd2) =
                                this->bp.val(this->not_canAdd) * scalar_field_type::value_type::one();
                            this->bp.lc_val(this->P_toAdd.Y) = scalar_field_type::value_type::one();
                            // this->bp.lc_val(this->Y_intermediate_toAdd2));
                        }

                        el_add->generate_r1cs_witness();
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_TWISTED_EDWARDS_G1_COMPONENT_HPP
