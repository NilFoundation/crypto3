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

#ifndef CRYPTO3_ZK_TWISTED_EDWARDS_G1_COMPONENT_HPP
#define CRYPTO3_ZK_TWISTED_EDWARDS_G1_COMPONENT_HPP

#include <nil/crypto3/zk/snark/component.hpp>

#include <nil/crypto3/zk/snark/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace components {

                    /**
                     * Component that represents a G1 variable for JubJub/Bls12-381 and BabyJubJub/Alt-BN128.
                     * 
                     * CurveType is BLS12-381 or BN128
                     */
                    template<typename CurveType>
                    class element_g1 : public component<typename CurveType::scalar_field_type> {
                        typedef typename CurveType::scalar_field_type scalar_field_type;

                    public:
                        blueprint_linear_combination<scalar_field_type> X;
                        blueprint_linear_combination<scalar_field_type> Y;

                        blueprint_linear_combination_vector<scalar_field_type> all_vars;

                        element_g1(blueprint<scalar_field_type> &bp) : component<scalar_field_type>(bp) {
                            blueprint_variable<scalar_field_type> X_var, Y_var;

                            X_var.allocate(bp);
                            Y_var.allocate(bp);

                            X = blueprint_linear_combination<scalar_field_type>(X_var);
                            Y = blueprint_linear_combination<scalar_field_type>(Y_var);

                            all_vars.emplace_back(X);
                            all_vars.emplace_back(Y);
                        }

                        element_g1(blueprint<scalar_field_type> &bp,
                                    const typename CurveType::pairing::chained_curve_type::g1_type::value_type &P) :
                            component<scalar_field_type>(bp) {
                            typename CurveType::pairing::chained_curve_type::g1_type::value_type Pcopy =
                                P.to_affine();

                            X.assign(bp, Pcopy.X);
                            Y.assign(bp, Pcopy.Y);
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
                            return 2 * scalar_field_type::modulus_bits; //This probably should be value_bits, not modulus_bits
                        }
                        static std::size_t num_variables() {
                            return 2;
                        }
                    };

                    /**
                     * Component that creates constraints for the validity of a G1 variable.
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
                            blueprint_variable<scalar_field_type> a, 
                            blueprint_variable<scalar_field_type> d,
                            const element_g1<CurveType> &P) :
                            component<scalar_field_type>(bp), P(P), a(a), d(d) {

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

                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {X}, {X}, {XX}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {Y}, {Y}, {YY}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {a}, {XX}, {aXX}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {aXX, YY}, 
                                {scalar_field_type::value_type::one()}, 
                                {lhs}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {d}, {XX}, {dXX}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {dXX}, {YY}, {dXXYY}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {dXXYY, scalar_field_type::value_type::one()}, 
                                {scalar_field_type::value_type::one()}, 
                                {rhs}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {lhs}, {scalar_field_type::value_type::one()}, {rhs}));
                        }
                        void generate_r1cs_witness() {
                            typename scalar_field_type::value_type x = 
                                this->bp.lc_val(this->X);
                            typename scalar_field_type::value_type y = 
                                this->bp.lc_val(this->Y);
                            typename scalar_field_type::value_type temp_a = 
                                this->bp.val(this->a);
                            typename scalar_field_type::value_type temp_d = 
                                this->bp.val(this->d);

                            // this->bp.val(this->X) = x;
                            // this->bp.val(this->Y) = y;
                            // this->bp.val(this->A) = temp_a;
                            // this->bp.val(this->D) = temp_d;

                            this->bp.val(this->XX) = x*x;
                            this->bp.val(this->YY) = y*y;
                            this->bp.val(this->aXX) = temp_a*x*x;
                            this->bp.val(this->lhs) = temp_a*x*x + y*y;
                            this->bp.val(this->dXX) = x*x*temp_d;
                            this->bp.val(this->dXXYY) = temp_d*x*x*y*y;

                            this->bp.val(this->rhs) = temp_d*x*x*y*y + scalar_field_type::value_type::one();
                        }
                    };

                    /**
                     * Component that creates constraints for the validity of a G1 variable.
                     * (if element from group G1 lies on the elliptic curve)
                     */
                    template<typename CurveType>
                    class element_g1_add : public component<typename CurveType::scalar_field_type> {
                        typedef typename CurveType::scalar_field_type scalar_field_type;

                    public:
                        element_g1<CurveType> P1;
                        element_g1<CurveType> P2;
                        element_g1<CurveType> P1pP2;

                        blueprint_variable<scalar_field_type> A;
                        blueprint_variable<scalar_field_type> D;

                        std::shared_ptr<element_g1_is_well_formed<CurveType>> el_is_well_formed;

                        //intermeditate variables 
                        blueprint_variable<scalar_field_type> X1X2;
                        blueprint_variable<scalar_field_type> X1Y2;
                        blueprint_variable<scalar_field_type> Y1Y2;
                        blueprint_variable<scalar_field_type> Y1X2;
                        blueprint_variable<scalar_field_type> X1X2Y1Y2;
                        blueprint_variable<scalar_field_type> dX1X2Y1Y2;
                        blueprint_variable<scalar_field_type> aX1X2;

                        element_g1_add(blueprint<scalar_field_type> &bp,
                            blueprint_variable<scalar_field_type> A, 
                            blueprint_variable<scalar_field_type> D,
                            const element_g1<CurveType> &P1,
                            const element_g1<CurveType> &P2,
                            const element_g1<CurveType> &P1pP2) :
                            component<scalar_field_type>(bp), P1(P1), P2(P2), P1pP2(P1pP2), 
                                A(A), D(D) {

                            el_is_well_formed.reset( 
                                new element_g1_is_well_formed <CurveType> (
                                    this->bp, a, d, P1pP2));

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

                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {P1.Y}, {P2.X}, {Y1X2}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {P1.X}, {P2.Y}, {X1Y2}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {P1.X}, {P2.X}, {X1X2}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {P1.Y}, {P2.Y}, {Y1Y2}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {X1X2}, {Y1Y2}, {X1X2Y1Y2}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {d}, {X1X2Y1Y2}, {dX1X2Y1Y2}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {a}, {X1X2}, {aX1X2}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {P1pP2.Y}, 
                                {scalar_field_type::value_type::one(), -dX1X2Y1Y2} ,  
                                {Y1Y2, -aX1X2}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<scalar_field_type>(
                                {P1pP2.X}, 
                                {scalar_field_type::value_type::one(), dX1X2Y1Y2}, 
                                {X1Y2, Y1X2}));
                        }
                        void generate_r1cs_witness() {

                            typename scalar_field_type::value_type x1 = 
                                this->bp.lc_val(this->P1.X); 
                            typename scalar_field_type::value_type y1 = 
                                this->bp.lc_val(this->P1.Y); 
                            typename scalar_field_type::value_type x2 = 
                                this->bp.lc_val(this->P2.X);
                            typename scalar_field_type::value_type y2 = 
                                this->bp.lc_val(this->P2.Y);
                            typename scalar_field_type::value_type temp_a = 
                                this->bp.lc_val(this->a);
                            typename scalar_field_type::value_type temp_d = 
                                this->bp.lc_val(this->d);


                            this->bp.val(X1X2) = x1*x2;
                            this->bp.val(X1Y2) = x1*y2;
                            this->bp.val(Y1Y2) = y1*y2;
                            this->bp.val(Y1X2) = y1*x2;
                            this->bp.val(X1X2Y1Y2) = x1*x2*y1*y2;
                            this->bp.val(dX1X2Y1Y2) = temp_d*x1*x2*y1*y2;
                            this->bp.val(aX1X2) = temp_a*x1*x2;

                            this->bp.lc_val(P1pP2.X) = (x1*y2 + y1*x2) * 
                                ((scalar_field_type::value_type::one() +  
                                    (temp_d*x1*x2*y1*y2)).inversed()); 
                            this->bp.lc_val(P1pP2.Y) = (y1*y2 - temp_a*x1*x2) * 
                                ((scalar_field_type::value_type::one() -  
                                    (temp_d*x1*x2*y1*y2)).inversed());

                            //el_is_well_formed->generate_r1cs_witness();
                        }
                    };

                }    // namespace components
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TWISTED_EDWARDS_G1_COMPONENT_HPP
