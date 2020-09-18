//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for Fp3 gadgets.
//
// The gadgets verify field arithmetic in Fp3 = Fp[U]/(U^3-non_residue),
// where non_residue is in Fp.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_FP3_GADGETS_HPP_
#define CRYPTO3_ZK_FP3_GADGETS_HPP_

#include <memory>

#include <nil/crypto3/zk/snark/gadget.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Gadget that represents an Fp3 variable.
                 */
                template<typename Fp3T>
                class Fp3_variable : public gadget<typename Fp3T::my_Fp> {
                public:
                    typedef typename Fp3T::my_Fp FieldType;

                    pb_linear_combination<FieldType> c0;
                    pb_linear_combination<FieldType> c1;
                    pb_linear_combination<FieldType> c2;

                    pb_linear_combination_array<FieldType> all_vars;

                    Fp3_variable(protoboard<FieldType> &pb);
                    Fp3_variable(protoboard<FieldType> &pb, const Fp3T &el);
                    Fp3_variable(protoboard<FieldType> &pb,
                                 const Fp3T &el,
                                 const pb_linear_combination<FieldType> &coeff);
                    Fp3_variable(protoboard<FieldType> &pb,
                                 const pb_linear_combination<FieldType> &c0,
                                 const pb_linear_combination<FieldType> &c1,
                                 const pb_linear_combination<FieldType> &c2);

                    void generate_r1cs_equals_const_constraints(const Fp3T &el);
                    void generate_r1cs_witness(const Fp3T &el);
                    Fp3T get_element();

                    Fp3_variable<Fp3T> operator*(const FieldType::value_type &coeff) const;
                    Fp3_variable<Fp3T> operator+(const Fp3_variable<Fp3T> &other) const;
                    Fp3_variable<Fp3T> operator+(const Fp3T &other) const;
                    Fp3_variable<Fp3T> mul_by_X() const;
                    void evaluate() const;
                    bool is_constant() const;

                    static std::size_t size_in_bits();
                    static std::size_t num_variables();
                };

                /**
                 * Gadget that creates constraints for Fp3 by Fp3 multiplication.
                 */
                template<typename Fp3T>
                class Fp3_mul_gadget : public gadget<typename Fp3T::my_Fp> {
                public:
                    typedef typename Fp3T::my_Fp FieldType;

                    Fp3_variable<Fp3T> A;
                    Fp3_variable<Fp3T> B;
                    Fp3_variable<Fp3T> result;

                    pb_variable<FieldType> v0;
                    pb_variable<FieldType> v4;

                    Fp3_mul_gadget(protoboard<FieldType> &pb,
                                   const Fp3_variable<Fp3T> &A,
                                   const Fp3_variable<Fp3T> &B,
                                   const Fp3_variable<Fp3T> &result);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                /**
                 * Gadget that creates constraints for Fp3 multiplication by a linear combination.
                 */
                template<typename Fp3T>
                class Fp3_mul_by_lc_gadget : public gadget<typename Fp3T::my_Fp> {
                public:
                    typedef typename Fp3T::my_Fp FieldType;

                    Fp3_variable<Fp3T> A;
                    pb_linear_combination<FieldType> lc;
                    Fp3_variable<Fp3T> result;

                    Fp3_mul_by_lc_gadget(protoboard<FieldType> &pb,
                                         const Fp3_variable<Fp3T> &A,
                                         const pb_linear_combination<FieldType> &lc,
                                         const Fp3_variable<Fp3T> &result);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                /**
                 * Gadget that creates constraints for Fp3 squaring.
                 */
                template<typename Fp3T>
                class Fp3_sqr_gadget : public gadget<typename Fp3T::my_Fp> {
                public:
                    typedef typename Fp3T::my_Fp FieldType;

                    Fp3_variable<Fp3T> A;
                    Fp3_variable<Fp3T> result;

                    std::shared_ptr<Fp3_mul_gadget<Fp3T>> mul;

                    Fp3_sqr_gadget(protoboard<FieldType> &pb,
                                   const Fp3_variable<Fp3T> &A,
                                   const Fp3_variable<Fp3T> &result);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename Fp3T>
                Fp3_variable<Fp3T>::Fp3_variable(protoboard<FieldType> &pb) : gadget<FieldType>(pb) {
                    pb_variable<FieldType> c0_var, c1_var, c2_var;
                    c0_var.allocate(pb);
                    c1_var.allocate(pb);
                    c2_var.allocate(pb);

                    c0 = pb_linear_combination<FieldType>(c0_var);
                    c1 = pb_linear_combination<FieldType>(c1_var);
                    c2 = pb_linear_combination<FieldType>(c2_var);

                    all_vars.emplace_back(c0);
                    all_vars.emplace_back(c1);
                    all_vars.emplace_back(c2);
                }

                template<typename Fp3T>
                Fp3_variable<Fp3T>::Fp3_variable(protoboard<FieldType> &pb, const Fp3T &el) : gadget<FieldType>(pb) {
                    c0.assign(pb, el.c0);
                    c1.assign(pb, el.c1);
                    c2.assign(pb, el.c2);

                    c0.evaluate(pb);
                    c1.evaluate(pb);
                    c2.evaluate(pb);

                    all_vars.emplace_back(c0);
                    all_vars.emplace_back(c1);
                    all_vars.emplace_back(c2);
                }

                template<typename Fp3T>
                Fp3_variable<Fp3T>::Fp3_variable(protoboard<FieldType> &pb,
                                                 const Fp3T &el,
                                                 const pb_linear_combination<FieldType> &coeff) :
                    gadget<FieldType>(pb) {
                    c0.assign(pb, el.c0 * coeff);
                    c1.assign(pb, el.c1 * coeff);
                    c2.assign(pb, el.c2 * coeff);

                    all_vars.emplace_back(c0);
                    all_vars.emplace_back(c1);
                    all_vars.emplace_back(c2);
                }

                template<typename Fp3T>
                Fp3_variable<Fp3T>::Fp3_variable(protoboard<FieldType> &pb,
                                                 const pb_linear_combination<FieldType> &c0,
                                                 const pb_linear_combination<FieldType> &c1,
                                                 const pb_linear_combination<FieldType> &c2) :
                    gadget<FieldType>(pb),
                    c0(c0), c1(c1), c2(c2) {
                    all_vars.emplace_back(c0);
                    all_vars.emplace_back(c1);
                    all_vars.emplace_back(c2);
                }

                template<typename Fp3T>
                void Fp3_variable<Fp3T>::generate_r1cs_equals_const_constraints(const Fp3T &el) {
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(1, el.c0, c0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(1, el.c1, c1));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(1, el.c2, c2));
                }

                template<typename Fp3T>
                void Fp3_variable<Fp3T>::generate_r1cs_witness(const Fp3T &el) {
                    this->pb.lc_val(c0) = el.c0;
                    this->pb.lc_val(c1) = el.c1;
                    this->pb.lc_val(c2) = el.c2;
                }

                template<typename Fp3T>
                Fp3T Fp3_variable<Fp3T>::get_element() {
                    Fp3T el;
                    el.c0 = this->pb.lc_val(c0);
                    el.c1 = this->pb.lc_val(c1);
                    el.c2 = this->pb.lc_val(c2);
                    return el;
                }

                template<typename Fp3T>
                Fp3_variable<Fp3T> Fp3_variable<Fp3T>::operator*(const FieldType::value_type &coeff) const {
                    pb_linear_combination<FieldType> new_c0, new_c1, new_c2;
                    new_c0.assign(this->pb, this->c0 * coeff);
                    new_c1.assign(this->pb, this->c1 * coeff);
                    new_c2.assign(this->pb, this->c2 * coeff);
                    return Fp3_variable<Fp3T>(this->pb, new_c0, new_c1, new_c2);
                }

                template<typename Fp3T>
                Fp3_variable<Fp3T> Fp3_variable<Fp3T>::operator+(const Fp3_variable<Fp3T> &other) const {
                    pb_linear_combination<FieldType> new_c0, new_c1, new_c2;
                    new_c0.assign(this->pb, this->c0 + other.c0);
                    new_c1.assign(this->pb, this->c1 + other.c1);
                    new_c2.assign(this->pb, this->c2 + other.c2);
                    return Fp3_variable<Fp3T>(this->pb, new_c0, new_c1, new_c2);
                }

                template<typename Fp3T>
                Fp3_variable<Fp3T> Fp3_variable<Fp3T>::operator+(const Fp3T &other) const {
                    pb_linear_combination<FieldType> new_c0, new_c1, new_c2;
                    new_c0.assign(this->pb, this->c0 + other.c0);
                    new_c1.assign(this->pb, this->c1 + other.c1);
                    new_c2.assign(this->pb, this->c2 + other.c2);
                    return Fp3_variable<Fp3T>(this->pb, new_c0, new_c1, new_c2);
                }

                template<typename Fp3T>
                Fp3_variable<Fp3T> Fp3_variable<Fp3T>::mul_by_X() const {
                    pb_linear_combination<FieldType> new_c0, new_c1, new_c2;
                    new_c0.assign(this->pb, this->c2 * Fp3T::non_residue);
                    new_c1.assign(this->pb, this->c0);
                    new_c2.assign(this->pb, this->c1);
                    return Fp3_variable<Fp3T>(this->pb, new_c0, new_c1, new_c2);
                }

                template<typename Fp3T>
                void Fp3_variable<Fp3T>::evaluate() const {
                    c0.evaluate(this->pb);
                    c1.evaluate(this->pb);
                    c2.evaluate(this->pb);
                }

                template<typename Fp3T>
                bool Fp3_variable<Fp3T>::is_constant() const {
                    return (c0.is_constant() && c1.is_constant() && c2.is_constant());
                }

                template<typename Fp3T>
                std::size_t Fp3_variable<Fp3T>::size_in_bits() {
                    return 3 * FieldType::size_in_bits();
                }

                template<typename Fp3T>
                std::size_t Fp3_variable<Fp3T>::num_variables() {
                    return 3;
                }

                template<typename Fp3T>
                Fp3_mul_gadget<Fp3T>::Fp3_mul_gadget(protoboard<FieldType> &pb,
                                                     const Fp3_variable<Fp3T> &A,
                                                     const Fp3_variable<Fp3T> &B,
                                                     const Fp3_variable<Fp3T> &result) :
                    gadget<FieldType>(pb),
                    A(A), B(B), result(result) {
                    v0.allocate(pb);
                    v4.allocate(pb);
                }

                template<typename Fp3T>
                void Fp3_mul_gadget<Fp3T>::generate_r1cs_constraints() {
                    /*
                        Tom-Cook-3x for Fp3:
                            v0 = A.c0 * B.c0
                            v1 = (A.c0 + A.c1 + A.c2) * (B.c0 + B.c1 + B.c2)
                            v2 = (A.c0 - A.c1 + A.c2) * (B.c0 - B.c1 + B.c2)
                            v3 = (A.c0 + 2*A.c1 + 4*A.c2) * (B.c0 + 2*B.c1 + 4*B.c2)
                            v4 = A.c2 * B.c2
                            result.c0 = v0 + non_residue * (v0/2 - v1/2 - v2/6 + v3/6 - 2*v4)
                            result.c1 = -(1/2) v0 +  v1 - (1/3) v2 - (1/6) v3 + 2 v4 + non_residue*v4
                            result.c2 = -v0 + (1/2) v1 + (1/2) v2 - v4

                        Enforced with 5 constraints. Doing so requires some care, as we first
                        compute two of the v_i explicitly, and then "inline" result.c1/c2/c3
                        in computations of teh remaining three v_i.

                        Concretely, we first compute v0 and v4 explicitly, via 2 constraints:
                            A.c0 * B.c0 = v0
                            A.c2 * B.c2 = v4
                        Then we use the following 3 additional constraints:
                            v1 = result.c1 + result.c2 + (result.c0 - v0)/non_residue + v0 + v4 - non_residue v4
                            v2 = -result.c1 + result.c2 + v0 + (-result.c0 + v0)/non_residue + v4 + non_residue v4
                            v3 = 2 * result.c1 + 4 result.c2 + (8*(result.c0 - v0))/non_residue + v0 + 16 * v4 - 2 *
                       non_residue * v4

                        Reference:
                            "Multiplication and Squaring on Pairing-Friendly Fields"
                            Devegili, OhEigeartaigh, Scott, Dahab

                        NOTE: the expressions above were cherry-picked from the Mathematica result
                        of the following command:

                        (# -> Solve[{c0 == v0 + non_residue*(v0/2 - v1/2 - v2/6 + v3/6 - 2 v4),
                                    c1 == -(1/2) v0 + v1 - (1/3) v2 - (1/6) v3 + 2 v4 + non_residue*v4,
                                    c2 == -v0 + (1/2) v1 + (1/2) v2 - v4}, #] // FullSimplify) & /@
                        Subsets[{v0, v1, v2, v3, v4}, {3}]
                    */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(A.c0, B.c0, v0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(A.c2, B.c2, v4));

                    const typename FieldType::value_type beta = Fp3T::non_residue;

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        A.c0 + A.c1 + A.c2,
                        B.c0 + B.c1 + B.c2,
                        result.c1 + result.c2 + result.c0 * beta.inverse() + v0 * (typename FieldType::value_type(1) - beta.inverse()) +
                            v4 * (typename FieldType::value_type(1) - beta)));
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(A.c0 - A.c1 + A.c2,
                                                   B.c0 - B.c1 + B.c2,
                                                   -result.c1 + result.c2 + v0 * (typename FieldType::value_type(1) + beta.inverse()) -
                                                       result.c0 * beta.inverse() + v4 * (typename FieldType::value_type(1) + beta)));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        A.c0 + 2 * A.c1 + 4 * A.c2,
                        B.c0 + 2 * B.c1 + 4 * B.c2,
                        2 * result.c1 + 4 * result.c2 + result.c0 * (typename FieldType::value_type(8) * beta.inverse()) +
                            v0 * (typename FieldType::value_type(1) - typename FieldType::value_type(8) * beta.inverse()) +
                            v4 * (typename FieldType::value_type(16) - typename FieldType::value_type(2) * beta)));
                }

                template<typename Fp3T>
                void Fp3_mul_gadget<Fp3T>::generate_r1cs_witness() {
                    this->pb.val(v0) = this->pb.lc_val(A.c0) * this->pb.lc_val(B.c0);
                    this->pb.val(v4) = this->pb.lc_val(A.c2) * this->pb.lc_val(B.c2);

                    const Fp3T Aval = A.get_element();
                    const Fp3T Bval = B.get_element();
                    const Fp3T Rval = Aval * Bval;
                    result.generate_r1cs_witness(Rval);
                }

                template<typename Fp3T>
                Fp3_mul_by_lc_gadget<Fp3T>::Fp3_mul_by_lc_gadget(protoboard<FieldType> &pb,
                                                                 const Fp3_variable<Fp3T> &A,
                                                                 const pb_linear_combination<FieldType> &lc,
                                                                 const Fp3_variable<Fp3T> &result) :
                    gadget<FieldType>(pb),
                    A(A), lc(lc), result(result) {
                }

                template<typename Fp3T>
                void Fp3_mul_by_lc_gadget<Fp3T>::generate_r1cs_constraints() {
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(A.c0, lc, result.c0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(A.c1, lc, result.c1));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(A.c2, lc, result.c2));
                }

                template<typename Fp3T>
                void Fp3_mul_by_lc_gadget<Fp3T>::generate_r1cs_witness() {
                    this->pb.lc_val(result.c0) = this->pb.lc_val(A.c0) * this->pb.lc_val(lc);
                    this->pb.lc_val(result.c1) = this->pb.lc_val(A.c1) * this->pb.lc_val(lc);
                    this->pb.lc_val(result.c2) = this->pb.lc_val(A.c2) * this->pb.lc_val(lc);
                }

                template<typename Fp3T>
                Fp3_sqr_gadget<Fp3T>::Fp3_sqr_gadget(protoboard<FieldType> &pb,
                                                     const Fp3_variable<Fp3T> &A,
                                                     const Fp3_variable<Fp3T> &result) :
                    gadget<FieldType>(pb),
                    A(A), result(result) {
                    mul.reset(new Fp3_mul_gadget<Fp3T>(pb, A, A, result));
                }

                template<typename Fp3T>
                void Fp3_sqr_gadget<Fp3T>::generate_r1cs_constraints() {
                    // We can't do better than 5 constraints for squaring, so we just use multiplication.
                    mul->generate_r1cs_constraints();
                }

                template<typename Fp3T>
                void Fp3_sqr_gadget<Fp3T>::generate_r1cs_witness() {
                    mul->generate_r1cs_witness();
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // FP3_GADGETS_HPP_
