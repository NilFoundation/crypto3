//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for G1 gadgets.
//
// The gadgets verify curve arithmetic in G1 = E(F) where E/F: y^2 = x^3 + A * X + B
// is an elliptic curve over F in short Weierstrass form.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_WEIERSTRASS_G1_GADGET_HPP_
#define CRYPTO3_ZK_WEIERSTRASS_G1_GADGET_HPP_

#include <nil/crypto3/zk/snark/component.hpp>
#include <nil/crypto3/zk/snark/components/pairing/pairing_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Gadget that represents a G1 variable.
                 */
                template<typename CurveType>
                struct G1_variable : public component<typename CurveType::scalar_field_type> {
                    typedef typename CurveType::scalar_field_type FieldType;

                    pb_linear_combination<FieldType> X;
                    pb_linear_combination<FieldType> Y;

                    pb_linear_combination_array<FieldType> all_vars;

                    G1_variable(blueprint<FieldType> &pb) : component<FieldType>(pb) {
                        variable<FieldType> X_var, Y_var;

                        X_var.allocate(pb);
                        Y_var.allocate(pb);

                        X = pb_linear_combination<FieldType>(X_var);
                        Y = pb_linear_combination<FieldType>(Y_var);

                        all_vars.emplace_back(X);
                        all_vars.emplace_back(Y);
                    }

                    G1_variable(blueprint<FieldType> &pb, const other_curve<CurveType>::g1_type &P) :
                        component<FieldType>(pb) {
                        other_curve<CurveType>::g1_type Pcopy = P.to_affine_coordinates();

                        X.assign(pb, Pcopy.X());
                        Y.assign(pb, Pcopy.Y());
                        X.evaluate(pb);
                        Y.evaluate(pb);
                        all_vars.emplace_back(X);
                        all_vars.emplace_back(Y);
                    }

                    template<typename CurveType1>
                    void generate_r1cs_witness(const CurveType1::g1_type &elt) {
                        other_curve<CurveType>::g1_type el_normalized = el.to_affine_coordinates();

                        this->pb.lc_val(X) = el_normalized.X();
                        this->pb.lc_val(Y) = el_normalized.Y();
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
                class G1_checker_component : public component<typename CurveType::scalar_field_type> {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

                    G1_variable<CurveType> P;
                    variable<FieldType> P_X_squared;
                    variable<FieldType> P_Y_squared;

                    G1_checker_component(blueprint<FieldType> &pb, const G1_variable<CurveType> &P) :
                        component<FieldType>(pb), P(P) {
                        P_X_squared.allocate(pb);
                        P_Y_squared.allocate(pb);
                    }
                    void generate_r1cs_constraints() {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>({P.X}, {P.X}, {P_X_squared}));
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>({P.Y}, {P.Y}, {P_Y_squared}));
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            {P.X},
                            {P_X_squared, variable<FieldType>(0) * other_curve<CurveType>::g1_type::a},
                            {P_Y_squared, variable<FieldType>(0) * (-other_curve<CurveType>::g1_type::b)}));
                    }
                    void generate_r1cs_witness() {
                        this->pb.val(P_X_squared) = this->pb.lc_val(P.X).squared();
                        this->pb.val(P_Y_squared) = this->pb.lc_val(P.Y).squared();
                    }
                };

                /**
                 * Gadget that creates constraints for G1 addition.
                 */
                template<typename CurveType>
                class G1_add_component : public component<typename CurveType::scalar_field_type> {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

                    variable<FieldType> lambda;
                    variable<FieldType> inv;

                    G1_variable<CurveType> A;
                    G1_variable<CurveType> B;
                    G1_variable<CurveType> C;

                    G1_add_component(blueprint<FieldType> &pb,
                                  const G1_variable<CurveType> &A,
                                  const G1_variable<CurveType> &B,
                                  const G1_variable<CurveType> &C) :
                        component<FieldType>(pb),
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
                        lambda.allocate(pb);
                        inv.allocate(pb);
                    }
                    void generate_r1cs_constraints() {
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>({lambda}, {B.X, A.X * (-1)}, {B.Y, A.Y * (-1)}));

                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>({lambda}, {lambda}, {C.X, A.X, B.X}));

                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>({lambda}, {A.X, C.X * (-1)}, {C.Y, A.Y}));

                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>({inv}, {B.X, A.X * (-1)}, {variable<FieldType>(0)}));
                    }
                    void generate_r1cs_witness() {
                        this->pb.val(inv) = (this->pb.lc_val(B.X) - this->pb.lc_val(A.X)).inverse();
                        this->pb.val(lambda) = (this->pb.lc_val(B.Y) - this->pb.lc_val(A.Y)) * this->pb.val(inv);
                        this->pb.lc_val(C.X) =
                            this->pb.val(lambda).squared() - this->pb.lc_val(A.X) - this->pb.lc_val(B.X);
                        this->pb.lc_val(C.Y) =
                            this->pb.val(lambda) * (this->pb.lc_val(A.X) - this->pb.lc_val(C.X)) - this->pb.lc_val(A.Y);
                    }
                };

                /**
                 * Gadget that creates constraints for G1 doubling.
                 */
                template<typename CurveType>
                class G1_dbl_component : public component<typename CurveType::scalar_field_type> {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

                    variable<FieldType> Xsquared;
                    variable<FieldType> lambda;

                    G1_variable<CurveType> A;
                    G1_variable<CurveType> B;

                    G1_dbl_component(blueprint<FieldType> &pb,
                                  const G1_variable<CurveType> &A,
                                  const G1_variable<CurveType> &B) :
                        component<FieldType>(pb),
                        A(A), B(B) {
                        Xsquared.allocate(pb);
                        lambda.allocate(pb);
                    }
                    void generate_r1cs_constraints() {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>({A.X}, {A.X}, {Xsquared}));

                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            {lambda * 2},
                            {A.Y},
                            {Xsquared * 3, variable<FieldType>(0x00) * other_curve<CurveType>::g1_type::a}));

                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>({lambda}, {lambda}, {B.X, A.X * 2}));

                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>({lambda}, {A.X, B.X * (-1)}, {B.Y, A.Y}));
                    }
                    void generate_r1cs_witness() {
                        this->pb.val(Xsquared) = this->pb.lc_val(A.X).squared();
                        this->pb.val(lambda) = (typename FieldType::value_type(0x03) * this->pb.val(Xsquared) +
                                                other_curve<CurveType>::g1_type::a) *
                                               (typename FieldType::value_type(0x02) * this->pb.lc_val(A.Y)).inverse();
                        this->pb.lc_val(B.X) =
                            this->pb.val(lambda).squared() - typename FieldType::value_type(0x02) * this->pb.lc_val(A.X);
                        this->pb.lc_val(B.Y) =
                            this->pb.val(lambda) * (this->pb.lc_val(A.X) - this->pb.lc_val(B.X)) - this->pb.lc_val(A.Y);
                    }
                };

                /**
                 * Gadget that creates constraints for G1 multi-scalar multiplication.
                 */
                template<typename CurveType>
                class G1_multiscalar_mul_component : public component<typename CurveType::scalar_field_type> {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

                    std::vector<G1_variable<CurveType>> computed_results;
                    std::vector<G1_variable<CurveType>> chosen_results;
                    std::vector<G1_add_component<CurveType>> adders;
                    std::vector<G1_dbl_component<CurveType>> doublers;

                    G1_variable<CurveType> base;
                    pb_variable_array<FieldType> scalars;
                    std::vector<G1_variable<CurveType>> points;
                    std::vector<G1_variable<CurveType>> points_and_powers;
                    G1_variable<CurveType> result;

                    const std::size_t elt_size;
                    const std::size_t num_points;
                    const std::size_t scalar_size;

                    G1_multiscalar_mul_component(blueprint<FieldType> &pb,
                                              const G1_variable<CurveType> &base,
                                              const pb_variable_array<FieldType> &scalars,
                                              const std::size_t elt_size,
                                              const std::vector<G1_variable<CurveType>> &points,
                                              const G1_variable<CurveType> &result) :
                        component<FieldType>(pb),
                        base(base), scalars(scalars), points(points), result(result), elt_size(elt_size),
                        num_points(points.size()), scalar_size(scalars.size()) {
                        assert(num_points >= 1);
                        assert(num_points * elt_size == scalar_size);

                        for (std::size_t i = 0; i < num_points; ++i) {
                            points_and_powers.emplace_back(points[i]);
                            for (std::size_t j = 0; j < elt_size - 1; ++j) {
                                points_and_powers.emplace_back(G1_variable<CurveType>(pb));
                                doublers.emplace_back(G1_dbl_component<CurveType>(
                                    pb, points_and_powers[i * elt_size + j], points_and_powers[i * elt_size + j + 1]));
                            }
                        }

                        chosen_results.emplace_back(base);
                        for (std::size_t i = 0; i < scalar_size; ++i) {
                            computed_results.emplace_back(G1_variable<CurveType>(pb));
                            if (i < scalar_size - 1) {
                                chosen_results.emplace_back(G1_variable<CurveType>(pb));
                            } else {
                                chosen_results.emplace_back(result);
                            }

                            adders.emplace_back(G1_add_component<CurveType>(
                                pb, chosen_results[i], points_and_powers[i], computed_results[i]));
                        }
                    }

                    void generate_r1cs_constraints() {
                        const std::size_t num_constraints_before = this->pb.num_constraints();

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
                            this->pb.add_r1cs_constraint(
                                r1cs_constraint<FieldType>(scalars[i],
                                                           computed_results[i].X - chosen_results[i].X,
                                                           chosen_results[i + 1].X - chosen_results[i].X));
                            this->pb.add_r1cs_constraint(
                                r1cs_constraint<FieldType>(scalars[i],
                                                           computed_results[i].Y - chosen_results[i].Y,
                                                           chosen_results[i + 1].Y - chosen_results[i].Y));
                        }

                        const std::size_t num_constraints_after = this->pb.num_constraints();
                        assert(num_constraints_after - num_constraints_before ==
                               4 * (scalar_size - num_points) + (4 + 2) * scalar_size);
                    }

                    void generate_r1cs_witness() {
                        for (std::size_t i = 0; i < scalar_size - num_points; ++i) {
                            doublers[i].generate_r1cs_witness();
                        }

                        for (std::size_t i = 0; i < scalar_size; ++i) {
                            adders[i].generate_r1cs_witness();
                            this->pb.lc_val(chosen_results[i + 1].X) =
                                (this->pb.val(scalars[i]) == typename CurveType::scalar_field_type::zero() ?
                                     this->pb.lc_val(chosen_results[i].X) :
                                     this->pb.lc_val(computed_results[i].X));
                            this->pb.lc_val(chosen_results[i + 1].Y) =
                                (this->pb.val(scalars[i]) == typename CurveType::scalar_field_type::zero() ?
                                     this->pb.lc_val(chosen_results[i].Y) :
                                     this->pb.lc_val(computed_results[i].Y));
                        }
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // WEIERSTRASS_G1_GADGET_TCC_
