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
// The components verify curve arithmetic in G1 = E(F) where E/F: y^2 = x^3 + A * X + B
// is an elliptic curve over F in short Weierstrass form.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_WEIERSTRASS_G1_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_WEIERSTRASS_G1_COMPONENT_HPP

#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/algebra/fields/element_fp.hpp>

#include <nil/crypto3/zk/components/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                /**
                 * Component that represents a G1 element.
                 */
                template<typename CurveType>
                class element_g1 : public component<typename CurveType::scalar_field_type> {

                    using underlying_field_type = typename CurveType::scalar_field_type;
                    using underlying_element_type = element_fp<underlying_field_type>;

                public:
                    underlying_element_type X;
                    underlying_element_type Y;

                    blueprint_linear_combination_vector<underlying_field_type> all_vars;

                    element_g1(blueprint<underlying_field_type> &bp) : component<underlying_field_type>(bp) {

                        blueprint_variable<underlying_field_type> X_var, Y_var;

                        X_var.allocate(bp);
                        Y_var.allocate(bp);

                        X = underlying_element_type(X_var);
                        Y = underlying_element_type(Y_var);

                        all_vars.emplace_back(X);
                        all_vars.emplace_back(Y);
                    }

                    element_g1(blueprint<underlying_field_type> &bp,
                               const typename CurveType::pairing::pair_curve_type::g1_type::value_type &P) :
                        component<underlying_field_type>(bp) {
                        typename CurveType::pairing::pair_curve_type::g1_type::value_type Pcopy = P.to_affine();

                        X.assign(bp, Pcopy.X);
                        Y.assign(bp, Pcopy.Y);
                        X.evaluate(bp);
                        Y.evaluate(bp);
                        all_vars.emplace_back(X);
                        all_vars.emplace_back(Y);
                    }

                    void generate_r1cs_witness(
                        const typename CurveType::pairing::pair_curve_type::g1_type::value_type &el) {
                        typename CurveType::pairing::pair_curve_type::g1_type::value_type el_normalized =
                            el.to_affine();

                        this->bp.lc_val(X) = el_normalized.X;
                        this->bp.lc_val(Y) = el_normalized.Y;
                    }

                    // (See a comment in r1cs_ppzksnark_verifier_component.hpp about why
                    // we mark this function noinline.) TODO: remove later
                    static std::size_t __attribute__((noinline)) size_in_bits() {
                        return 2 * underlying_field_type::modulus_bits;
                    }
                    static std::size_t num_variables() {
                        return 2;
                    }
                };

                /**
                 * Component that creates constraints for the validity of a G1 element.
                 */
                template<typename CurveType>
                class element_g1_is_well_formed : public component<typename CurveType::scalar_field_type> {

                    using underlying_field_type = typename CurveType::scalar_field_type;

                public:
                    element_g1<CurveType> P;
                    blueprint_variable<underlying_field_type> P_X_squared;
                    blueprint_variable<underlying_field_type> P_Y_squared;

                    element_g1_is_well_formed(blueprint<underlying_field_type> &bp, const element_g1<CurveType> &P) :
                        component<underlying_field_type>(bp), P(P) {
                        P_X_squared.allocate(bp);
                        P_Y_squared.allocate(bp);
                    }
                    void generate_r1cs_constraints() {
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<underlying_field_type>({P.X}, {P.X}, {P_X_squared}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<underlying_field_type>({P.Y}, {P.Y}, {P_Y_squared}));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<underlying_field_type>(
                            {P.X},
                            {P_X_squared,
                             blueprint_variable<underlying_field_type>(0) * CurveType::pairing::pair_curve_type::a},
                            {P_Y_squared, blueprint_variable<underlying_field_type>(0) *
                                              (-CurveType::pairing::pair_curve_type::b)}));
                    }
                    void generate_r1cs_witness() {
                        this->bp.val(P_X_squared) = this->bp.lc_val(P.X).squared();
                        this->bp.val(P_Y_squared) = this->bp.lc_val(P.Y).squared();
                    }
                };

                /**
                 * Component that creates constraints for G1 addition.
                 */
                template<typename CurveType>
                class element_g1_add : public component<typename CurveType::scalar_field_type> {

                    using underlying_field_type = typename CurveType::scalar_field_type;

                public:
                    blueprint_variable<underlying_field_type> lambda;
                    blueprint_variable<underlying_field_type> inv;

                    element_g1<CurveType> A;
                    element_g1<CurveType> B;
                    element_g1<CurveType> C;

                    element_g1_add(blueprint<underlying_field_type> &bp,
                                   const element_g1<CurveType> &A,
                                   const element_g1<CurveType> &B,
                                   const element_g1<CurveType> &C) :
                        component<underlying_field_type>(bp),
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
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<underlying_field_type>(
                            {lambda}, {B.X, A.X * (-1)}, {B.Y, A.Y * (-1)}));

                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<underlying_field_type>({lambda}, {lambda}, {C.X, A.X, B.X}));

                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<underlying_field_type>({lambda}, {A.X, C.X * (-1)}, {C.Y, A.Y}));

                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<underlying_field_type>(
                            {inv}, {B.X, A.X * (-1)}, {blueprint_variable<underlying_field_type>(0)}));
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
                 * Component that creates constraints for G1 doubling.
                 */
                template<typename CurveType>
                class element_g1_doubled : public component<typename CurveType::scalar_field_type> {

                    using underlying_field_type = typename CurveType::scalar_field_type;

                public:
                    blueprint_variable<underlying_field_type> Xsquared;
                    blueprint_variable<underlying_field_type> lambda;

                    element_g1<CurveType> A;
                    element_g1<CurveType> B;

                    element_g1_doubled(blueprint<underlying_field_type> &bp,
                                       const element_g1<CurveType> &A,
                                       const element_g1<CurveType> &B) :
                        component<underlying_field_type>(bp),
                        A(A), B(B) {
                        Xsquared.allocate(bp);
                        lambda.allocate(bp);
                    }
                    void generate_r1cs_constraints() {
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<underlying_field_type>({A.X}, {A.X}, {Xsquared}));

                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<underlying_field_type>(
                            {lambda * 2},
                            {A.Y},
                            {Xsquared * 3, blueprint_variable<underlying_field_type>(0x00) *
                                               CurveType::pairing::pair_curve_type::a}));

                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<underlying_field_type>({lambda}, {lambda}, {B.X, A.X * 2}));

                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<underlying_field_type>({lambda}, {A.X, B.X * (-1)}, {B.Y, A.Y}));
                    }
                    void generate_r1cs_witness() {
                        this->bp.val(Xsquared) = this->bp.lc_val(A.X).squared();
                        this->bp.val(lambda) =
                            (typename underlying_field_type::value_type(0x03) * this->bp.val(Xsquared) +
                             CurveType::pairing::pair_curve_type::a) *
                            (typename underlying_field_type::value_type(0x02) * this->bp.lc_val(A.Y)).inversed();
                        this->bp.lc_val(B.X) = this->bp.val(lambda).squared() -
                                               typename underlying_field_type::value_type(0x02) * this->bp.lc_val(A.X);
                        this->bp.lc_val(B.Y) =
                            this->bp.val(lambda) * (this->bp.lc_val(A.X) - this->bp.lc_val(B.X)) - this->bp.lc_val(A.Y);
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_WEIERSTRASS_G1_COMPONENT_HPP
