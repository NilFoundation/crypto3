//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for Fp2 components.
//
// The components verify field arithmetic in Fp2 = Fp[U]/(U^2-non_residue),
// where non_residue is in Fp.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_FP2_COMPONENTS_HPP
#define CRYPTO3_ZK_FP2_COMPONENTS_HPP

#include <memory>

#include <nil/crypto3/zk/snark/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Component that represents an Fp2 variable.
                 */
                template<typename Fp2T>
                class Fp2_variable : public component<typename Fp2T::underlying_field_type> {
                public:
                    using field_type = typename Fp2T::underlying_field_type;

                    blueprint_linear_combination<field_type> c0;
                    blueprint_linear_combination<field_type> c1;

                    blueprint_linear_combination_vector<field_type> all_vars;

                    Fp2_variable(blueprint<field_type> &pb) : component<field_type>(pb) {
                        variable<field_type> c0_var, c1_var;
                        c0_var.allocate(pb);
                        c1_var.allocate(pb);

                        c0 = blueprint_linear_combination<field_type>(c0_var);
                        c1 = blueprint_linear_combination<field_type>(c1_var);

                        all_vars.emplace_back(c0);
                        all_vars.emplace_back(c1);
                    }

                    Fp2_variable(blueprint<field_type> &pb, const Fp2T &el) : component<field_type>(pb) {
                        c0.assign(pb, el.c0);
                        c1.assign(pb, el.c1);

                        c0.evaluate(pb);
                        c1.evaluate(pb);

                        all_vars.emplace_back(c0);
                        all_vars.emplace_back(c1);
                    }

                    Fp2_variable(blueprint<field_type> &pb,
                                 const Fp2T &el,
                                 const blueprint_linear_combination<field_type> &coeff) :
                        component<field_type>(pb) {
                        c0.assign(pb, el.c0 * coeff);
                        c1.assign(pb, el.c1 * coeff);

                        all_vars.emplace_back(c0);
                        all_vars.emplace_back(c1);
                    }

                    Fp2_variable(blueprint<field_type> &pb,
                                 const blueprint_linear_combination<field_type> &c0,
                                 const blueprint_linear_combination<field_type> &c1) :
                        component<field_type>(pb),
                        c0(c0), c1(c1) {
                        all_vars.emplace_back(c0);
                        all_vars.emplace_back(c1);
                    }

                    void generate_r1cs_equals_const_constraints(const Fp2T &el) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(1, el.c0, c0));
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(1, el.c1, c1));
                    }

                    void generate_r1cs_witness(const Fp2T &el) {
                        this->pb.lc_val(c0) = el.c0;
                        this->pb.lc_val(c1) = el.c1;
                    }

                    Fp2T get_element() {
                        Fp2T el;
                        el.c0 = this->pb.lc_val(c0);
                        el.c1 = this->pb.lc_val(c1);
                        return el;
                    }

                    Fp2_variable operator*(const typename field_type::value_type &coeff) const {
                        blueprint_linear_combination<field_type> new_c0, new_c1;
                        new_c0.assign(this->pb, this->c0 * coeff);
                        new_c1.assign(this->pb, this->c1 * coeff);
                        return Fp2_variable<Fp2T>(this->pb, new_c0, new_c1);
                    }

                    Fp2_variable operator+(const Fp2_variable &other) const {
                        blueprint_linear_combination<field_type> new_c0, new_c1;
                        new_c0.assign(this->pb, this->c0 + other.c0);
                        new_c1.assign(this->pb, this->c1 + other.c1);
                        return Fp2_variable<Fp2T>(this->pb, new_c0, new_c1);
                    }

                    Fp2_variable operator+(const Fp2T &other) const {
                        blueprint_linear_combination<field_type> new_c0, new_c1;
                        new_c0.assign(this->pb, this->c0 + other.c0);
                        new_c1.assign(this->pb, this->c1 + other.c1);
                        return Fp2_variable<Fp2T>(this->pb, new_c0, new_c1);
                    }

                    Fp2_variable mul_by_X() const {
                        blueprint_linear_combination<field_type> new_c0, new_c1;
                        new_c0.assign(this->pb, this->c1 * Fp2T::non_residue);
                        new_c1.assign(this->pb, this->c0);
                        return Fp2_variable<Fp2T>(this->pb, new_c0, new_c1);
                    }

                    void evaluate() const {
                        c0.evaluate(this->pb);
                        c1.evaluate(this->pb);
                    }

                    bool is_constant() const {
                        return (c0.is_constant() && c1.is_constant());
                    }

                    static std::size_t size_in_bits() {
                        return 2 * field_type::value_bits;
                    }

                    static std::size_t num_variables() {
                        return 2;
                    }
                };

                /**
                 * Component that creates constraints for Fp2 by Fp2 multiplication.
                 */
                template<typename Fp2T>
                class Fp2_mul_component : public component<typename Fp2T::underlying_field_type> {
                public:
                    using field_type = typename Fp2T::underlying_field_type;

                    Fp2_variable<Fp2T> A;
                    Fp2_variable<Fp2T> B;
                    Fp2_variable<Fp2T> result;

                    variable<field_type> v1;

                    Fp2_mul_component(blueprint<field_type> &pb,
                                   const Fp2_variable<Fp2T> &A,
                                   const Fp2_variable<Fp2T> &B,
                                   const Fp2_variable<Fp2T> &result) :
                        component<field_type>(pb),
                        A(A), B(B), result(result) {
                        v1.allocate(pb);
                    }

                    void generate_r1cs_constraints() {
                        /*
                            Karatsuba multiplication for Fp2:
                                v0 = A.c0 * B.c0
                                v1 = A.c1 * B.c1
                                result.c0 = v0 + non_residue * v1
                                result.c1 = (A.c0 + A.c1) * (B.c0 + B.c1) - v0 - v1

                            Enforced with 3 constraints:
                                A.c1 * B.c1 = v1
                                A.c0 * B.c0 = result.c0 - non_residue * v1
                                (A.c0+A.c1)*(B.c0+B.c1) = result.c1 + result.c0 + (1 - non_residue) * v1

                            Reference:
                                "Multiplication and Squaring on Pairing-Friendly Fields"
                                Devegili, OhEigeartaigh, Scott, Dahab
                        */
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(A.c1, B.c1, v1));
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<field_type>(A.c0, B.c0, result.c0 + v1 * (-Fp2T::non_residue)));
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(
                            A.c0 + A.c1, B.c0 + B.c1, result.c1 + result.c0 + v1 * (field_type::value_type::zero() - Fp2T::non_residue)));
                    }

                    void generate_r1cs_witness() {
                        const typename field_type::value_type aA = this->pb.lc_val(A.c0) * this->pb.lc_val(B.c0);
                        this->pb.val(v1) = this->pb.lc_val(A.c1) * this->pb.lc_val(B.c1);
                        this->pb.lc_val(result.c0) = aA + Fp2T::non_residue * this->pb.val(v1);
                        this->pb.lc_val(result.c1) = (this->pb.lc_val(A.c0) + this->pb.lc_val(A.c1)) *
                                                         (this->pb.lc_val(B.c0) + this->pb.lc_val(B.c1)) -
                                                     aA - this->pb.lc_val(v1);
                    }
                };

                /**
                 * Component that creates constraints for Fp2 multiplication by a linear combination.
                 */
                template<typename Fp2T>
                class Fp2_mul_by_lc_component : public component<typename Fp2T::underlying_field_type> {
                public:
                    using field_type = typename Fp2T::underlying_field_type;

                    Fp2_variable<Fp2T> A;
                    blueprint_linear_combination<field_type> lc;
                    Fp2_variable<Fp2T> result;

                    Fp2_mul_by_lc_component(blueprint<field_type> &pb,
                                         const Fp2_variable<Fp2T> &A,
                                         const blueprint_linear_combination<field_type> &lc,
                                         const Fp2_variable<Fp2T> &result) :
                        component<field_type>(pb),
                        A(A), lc(lc), result(result) {
                    }

                    void generate_r1cs_constraints() {
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(A.c0, lc, result.c0));
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(A.c1, lc, result.c1));
                    }

                    void generate_r1cs_witness() {
                        this->pb.lc_val(result.c0) = this->pb.lc_val(A.c0) * this->pb.lc_val(lc);
                        this->pb.lc_val(result.c1) = this->pb.lc_val(A.c1) * this->pb.lc_val(lc);
                    }
                };

                /**
                 * Component that creates constraints for Fp2 squaring.
                 */
                template<typename Fp2T>
                class Fp2_sqr_component : public component<typename Fp2T::underlying_field_type> {
                public:
                    using field_type = typename Fp2T::underlying_field_type;

                    Fp2_variable<Fp2T> A;
                    Fp2_variable<Fp2T> result;

                    Fp2_sqr_component(blueprint<field_type> &pb,
                                   const Fp2_variable<Fp2T> &A,
                                   const Fp2_variable<Fp2T> &result) :
                        component<field_type>(pb),
                        A(A), result(result) {
                    }

                    void generate_r1cs_constraints() {
                        /*
                            Complex multiplication for Fp2:
                                v0 = A.c0 * A.c1
                                result.c0 = (A.c0 + A.c1) * (A.c0 + non_residue * A.c1) - (1 + non_residue) * v0
                                result.c1 = 2 * v0

                            Enforced with 2 constraints:
                                (2*A.c0) * A.c1 = result.c1
                                (A.c0 + A.c1) * (A.c0 + non_residue * A.c1) = result.c0 + result.c1 * (1 + non_residue)/2

                            Reference:
                                "Multiplication and Squaring on Pairing-Friendly Fields"
                                Devegili, OhEigeartaigh, Scott, Dahab
                        */
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(2 * A.c0, A.c1, result.c1));
                        this->pb.add_r1cs_constraint(r1cs_constraint<field_type>(
                            A.c0 + A.c1,
                            A.c0 + Fp2T::non_residue * A.c1,
                            result.c0 + result.c1 * (field_type::value_type::zero() + Fp2T::non_residue) * typename field_type::value_type(2).inversed()));
                    }

                    void generate_r1cs_witness() {
                        const typename field_type::value_type a = this->pb.lc_val(A.c0);
                        const typename field_type::value_type b = this->pb.lc_val(A.c1);
                        this->pb.lc_val(result.c1) = typename field_type::value_type(2) * a * b;
                        this->pb.lc_val(result.c0) =
                            (a + b) * (a + Fp2T::non_residue * b) - a * b - Fp2T::non_residue * a * b;
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_FP2_COMPONENTS_HPP
