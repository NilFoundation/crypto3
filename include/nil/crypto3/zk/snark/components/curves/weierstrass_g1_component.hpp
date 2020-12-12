//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
// The components verify curve arithmetic in G1 = E(F) where E/F: y^2 = x^3 + A * X + B
// is an elliptic curve over F in short Weierstrass form.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_WEIERSTRASS_G1_COMPONENT_HPP
#define CRYPTO3_ZK_WEIERSTRASS_G1_COMPONENT_HPP

#include <nil/crypto3/zk/snark/component.hpp>
#include <nil/crypto3/zk/snark/components/pairing/pairing_params.hpp>

#include <nil/crypto3/zk/snark/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace components {

                    /**
                     * Gadget that represents a G1 variable.
                     */
                    template<typename CurveType>
                    struct G1_variable : public component<typename CurveType::scalar_field_type> {
                        typedef typename CurveType::scalar_field_type FieldType;

                        blueprint_linear_combination<FieldType> X;
                        blueprint_linear_combination<FieldType> Y;

                        blueprint_linear_combination_vector<FieldType> all_vars;

                        G1_variable(blueprint<FieldType> &bp) : component<FieldType>(bp) {
                            blueprint_variable<FieldType> X_var, Y_var;

                            X_var.allocate(bp);
                            Y_var.allocate(bp);

                            X = blueprint_linear_combination<FieldType>(X_var);
                            Y = blueprint_linear_combination<FieldType>(Y_var);

                            all_vars.emplace_back(X);
                            all_vars.emplace_back(Y);
                        }

                        G1_variable(blueprint<FieldType> &bp,
                                    const typename other_curve<CurveType>::g1_type::value_type &P) :
                            component<FieldType>(bp) {
                            typename other_curve<CurveType>::g1_type::value_type Pcopy = P.to_affine_coordinates();

                            X.assign(bp, Pcopy.X());
                            Y.assign(bp, Pcopy.Y());
                            X.evaluate(bp);
                            Y.evaluate(bp);
                            all_vars.emplace_back(X);
                            all_vars.emplace_back(Y);
                        }

                        void generate_r1cs_witness(const typename other_curve<CurveType>::g1_type::value_type &el) {
                            typename other_curve<CurveType>::g1_type::value_type el_normalized = el.to_affine_coordinates();

                            this->bp.lc_val(X) = el_normalized.X();
                            this->bp.lc_val(Y) = el_normalized.Y();
                        }

                        // (See a comment in r1cs_ppzksnark_verifier_component.hpp about why
                        // we mark this function noinline.) TODO: remove later
                        static std::size_t __attribute__((noinline)) size_in_bits() {
                            return 2 * FieldType::modulus_bits;
                        }
                        static std::size_t num_variables() {
                            return 2;
                        }
                    };

                    /**
                     * Gadget that creates constraints for the validity of a G1 variable.
                     */
                    template<typename CurveType>
                    struct G1_checker_component : public component<typename CurveType::scalar_field_type> {
                        typedef typename CurveType::scalar_field_type FieldType;

                        G1_variable<CurveType> P;
                        blueprint_variable<FieldType> P_X_squared;
                        blueprint_variable<FieldType> P_Y_squared;

                        G1_checker_component(blueprint<FieldType> &bp, const G1_variable<CurveType> &P) :
                            component<FieldType>(bp), P(P) {
                            P_X_squared.allocate(bp);
                            P_Y_squared.allocate(bp);
                        }
                        void generate_r1cs_constraints() {
                            this->bp.add_r1cs_constraint(r1cs_constraint<FieldType>({P.X}, {P.X}, {P_X_squared}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<FieldType>({P.Y}, {P.Y}, {P_Y_squared}));
                            this->bp.add_r1cs_constraint(r1cs_constraint<FieldType>(
                                {P.X},
                                {P_X_squared, blueprint_variable<FieldType>(0) * other_curve<CurveType>::g1_type::a},
                                {P_Y_squared, blueprint_variable<FieldType>(0) * (-other_curve<CurveType>::g1_type::b)}));
                        }
                        void generate_r1cs_witness() {
                            this->bp.val(P_X_squared) = this->bp.lc_val(P.X).squared();
                            this->bp.val(P_Y_squared) = this->bp.lc_val(P.Y).squared();
                        }
                    };

                    /**
                     * Gadget that creates constraints for G1 addition.
                     */
                    template<typename CurveType>
                    struct G1_add_component : public component<typename CurveType::scalar_field_type> {
                        typedef typename CurveType::scalar_field_type FieldType;

                        blueprint_variable<FieldType> lambda;
                        blueprint_variable<FieldType> inv;

                        G1_variable<CurveType> A;
                        G1_variable<CurveType> B;
                        G1_variable<CurveType> C;

                        G1_add_component(blueprint<FieldType> &bp,
                                         const G1_variable<CurveType> &A,
                                         const G1_variable<CurveType> &B,
                                         const G1_variable<CurveType> &C) :
                            component<FieldType>(bp),
                            A(A), B(B), C(C) {
                            /*
                              lambda = (B.y - A.y)/(B.x - A.x)
                              C.x = lambda^2 - A.x - B.x
                              C.y = lambda(A.x - C.x) - A.y

                              Special cases:

                              doubling: if B.y = A.y and B.x = A.x then lambda is unbound and
                              C = (lambda^2, lambda^3)

                              addition of negative point: if B.y = -A.y and B.x = A.x then no
                              lambda can satisfy the first equation unless B.y - A.y = 0. But
                              then this reduces to doubling.

                              So we need to check that A.x - B.x != 0, which can be done by
                              enforcing I * (B.x - A.x) = 1
                            */
                            lambda.allocate(bp);
                            inv.allocate(bp);
                        }
                        void generate_r1cs_constraints() {
                            this->bp.add_r1cs_constraint(
                                r1cs_constraint<FieldType>({lambda}, {B.X, A.X * (-1)}, {B.Y, A.Y * (-1)}));

                            this->bp.add_r1cs_constraint(r1cs_constraint<FieldType>({lambda}, {lambda}, {C.X, A.X, B.X}));

                            this->bp.add_r1cs_constraint(
                                r1cs_constraint<FieldType>({lambda}, {A.X, C.X * (-1)}, {C.Y, A.Y}));

                            this->bp.add_r1cs_constraint(
                                r1cs_constraint<FieldType>({inv}, {B.X, A.X * (-1)}, {blueprint_variable<FieldType>(0)}));
                        }
                        void generate_r1cs_witness() {
                            this->bp.val(inv) = (this->bp.lc_val(B.X) - this->bp.lc_val(A.X)).inversed();
                            this->bp.val(lambda) = (this->bp.lc_val(B.Y) - this->bp.lc_val(A.Y)) * this->bp.val(inv);
                            this->bp.lc_val(C.X) =
                                this->bp.val(lambda).squared() - this->bp.lc_val(A.X) - this->bp.lc_val(B.X);
                            this->bp.lc_val(C.Y) =
                                this->bp.val(lambda) * (this->bp.lc_val(A.X) - this->bp.lc_val(C.X)) - this->bp.lc_val(A.Y);
                        }
                    };

                    /**
                     * Gadget that creates constraints for G1 doubling.
                     */
                    template<typename CurveType>
                    struct G1_dbl_component : public component<typename CurveType::scalar_field_type> {
                        typedef typename CurveType::scalar_field_type FieldType;

                        blueprint_variable<FieldType> Xsquared;
                        blueprint_variable<FieldType> lambda;

                        G1_variable<CurveType> A;
                        G1_variable<CurveType> B;

                        G1_dbl_component(blueprint<FieldType> &bp,
                                         const G1_variable<CurveType> &A,
                                         const G1_variable<CurveType> &B) :
                            component<FieldType>(bp),
                            A(A), B(B) {
                            Xsquared.allocate(bp);
                            lambda.allocate(bp);
                        }
                        void generate_r1cs_constraints() {
                            this->bp.add_r1cs_constraint(r1cs_constraint<FieldType>({A.X}, {A.X}, {Xsquared}));

                            this->bp.add_r1cs_constraint(r1cs_constraint<FieldType>(
                                {lambda * 2},
                                {A.Y},
                                {Xsquared * 3, blueprint_variable<FieldType>(0x00) * other_curve<CurveType>::g1_type::a}));

                            this->bp.add_r1cs_constraint(r1cs_constraint<FieldType>({lambda}, {lambda}, {B.X, A.X * 2}));

                            this->bp.add_r1cs_constraint(
                                r1cs_constraint<FieldType>({lambda}, {A.X, B.X * (-1)}, {B.Y, A.Y}));
                        }
                        void generate_r1cs_witness() {
                            this->bp.val(Xsquared) = this->bp.lc_val(A.X).squared();
                            this->bp.val(lambda) = (typename FieldType::value_type(0x03) * this->bp.val(Xsquared) +
                                                    other_curve<CurveType>::g1_type::a) *
                                                   (typename FieldType::value_type(0x02) * this->bp.lc_val(A.Y)).inversed();
                            this->bp.lc_val(B.X) = this->bp.val(lambda).squared() -
                                                   typename FieldType::value_type(0x02) * this->bp.lc_val(A.X);
                            this->bp.lc_val(B.Y) =
                                this->bp.val(lambda) * (this->bp.lc_val(A.X) - this->bp.lc_val(B.X)) - this->bp.lc_val(A.Y);
                        }
                    };

                    /**
                     * Gadget that creates constraints for G1 multi-scalar multiplication.
                     */
                    template<typename CurveType>
                    struct G1_multiscalar_mul_component : public component<typename CurveType::scalar_field_type> {
                        typedef typename CurveType::scalar_field_type FieldType;

                        std::vector<G1_variable<CurveType>> computed_results;
                        std::vector<G1_variable<CurveType>> chosen_results;
                        std::vector<G1_add_component<CurveType>> adders;
                        std::vector<G1_dbl_component<CurveType>> doublers;

                        G1_variable<CurveType> base;
                        blueprint_variable_vector<FieldType> scalars;
                        std::vector<G1_variable<CurveType>> points;
                        std::vector<G1_variable<CurveType>> points_and_powers;
                        G1_variable<CurveType> result;

                        const std::size_t elt_size;
                        const std::size_t num_points;
                        const std::size_t scalar_size;

                        G1_multiscalar_mul_component(blueprint<FieldType> &bp,
                                                     const G1_variable<CurveType> &base,
                                                     const blueprint_variable_vector<FieldType> &scalars,
                                                     const std::size_t elt_size,
                                                     const std::vector<G1_variable<CurveType>> &points,
                                                     const G1_variable<CurveType> &result) :
                            component<FieldType>(bp),
                            base(base), scalars(scalars), points(points), result(result), elt_size(elt_size),
                            num_points(points.size()), scalar_size(scalars.size()) {
                            assert(num_points >= 1);
                            assert(num_points * elt_size == scalar_size);

                            for (std::size_t i = 0; i < num_points; ++i) {
                                points_and_powers.emplace_back(points[i]);
                                for (std::size_t j = 0; j < elt_size - 1; ++j) {
                                    points_and_powers.emplace_back(G1_variable<CurveType>(bp));
                                    doublers.emplace_back(G1_dbl_component<CurveType>(
                                        bp, points_and_powers[i * elt_size + j], points_and_powers[i * elt_size + j + 1]));
                                }
                            }

                            chosen_results.emplace_back(base);
                            for (std::size_t i = 0; i < scalar_size; ++i) {
                                computed_results.emplace_back(G1_variable<CurveType>(bp));
                                if (i < scalar_size - 1) {
                                    chosen_results.emplace_back(G1_variable<CurveType>(bp));
                                } else {
                                    chosen_results.emplace_back(result);
                                }

                                adders.emplace_back(G1_add_component<CurveType>(
                                    bp, chosen_results[i], points_and_powers[i], computed_results[i]));
                            }
                        }

                        void generate_r1cs_constraints() {
                            const std::size_t num_constraints_before = this->bp.num_constraints();

                            for (std::size_t i = 0; i < scalar_size - num_points; ++i) {
                                doublers[i].generate_r1cs_constraints();
                            }

                            for (std::size_t i = 0; i < scalar_size; ++i) {
                                adders[i].generate_r1cs_constraints();

                                /*
                                  chosen_results[i+1].X = scalars[i] * computed_results[i].X + (1-scalars[i]) *
                                  chosen_results[i].X chosen_results[i+1].X - chosen_results[i].X = scalars[i] *
                                  (computed_results[i].X - chosen_results[i].X)
                                */
                                this->bp.add_r1cs_constraint(
                                    r1cs_constraint<FieldType>(scalars[i],
                                                               computed_results[i].X - chosen_results[i].X,
                                                               chosen_results[i + 1].X - chosen_results[i].X));
                                this->bp.add_r1cs_constraint(
                                    r1cs_constraint<FieldType>(scalars[i],
                                                               computed_results[i].Y - chosen_results[i].Y,
                                                               chosen_results[i + 1].Y - chosen_results[i].Y));
                            }

                            const std::size_t num_constraints_after = this->bp.num_constraints();
                            assert(num_constraints_after - num_constraints_before ==
                                   4 * (scalar_size - num_points) + (4 + 2) * scalar_size);
                        }

                        void generate_r1cs_witness() {
                            for (std::size_t i = 0; i < scalar_size - num_points; ++i) {
                                doublers[i].generate_r1cs_witness();
                            }

                            for (std::size_t i = 0; i < scalar_size; ++i) {
                                adders[i].generate_r1cs_witness();
                                this->bp.lc_val(chosen_results[i + 1].X) =
                                    (this->bp.val(scalars[i]) == typename CurveType::scalar_field_type::value_type::zero() ?
                                         this->bp.lc_val(chosen_results[i].X) :
                                         this->bp.lc_val(computed_results[i].X));
                                this->bp.lc_val(chosen_results[i + 1].Y) =
                                    (this->bp.val(scalars[i]) == typename CurveType::scalar_field_type::value_type::zero() ?
                                         this->bp.lc_val(chosen_results[i].Y) :
                                         this->bp.lc_val(computed_results[i].Y));
                            }
                        }
                    };
                }    // namespace components
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_WEIERSTRASS_G1_COMPONENT_HPP
