//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for Fp4 components.
//
// The components verify field arithmetic in Fp4 = Fp2[V]/(V^2-U) where
// Fp2 = Fp[U]/(U^2-non_residue) and non_residue is in Fp.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_FP4_COMPONENTS_HPP
#define CRYPTO3_ZK_FP4_COMPONENTS_HPP

#include <nil/crypto3/zk/snark/component.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp2_components.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /******************************** Fp4_variable ************************************/

                /**
                 * Component that represents an Fp4 variable.
                 */
                template<typename Fp4T>
                struct Fp4_variable : public component<typename Fp4T::base_field_type> {
                    typedef typename Fp4T::base_field_type FieldType;
                    typedef typename Fp4T::underlying_field_type Fp2T;

                    Fp2_variable<Fp2T> c0;
                    Fp2_variable<Fp2T> c1;

                    Fp4_variable(blueprint<FieldType> &pb) : component<FieldType>(pb), c0(pb), c1(pb) {}
                    Fp4_variable(blueprint<FieldType> &pb, const Fp4T &el) :
                        component<FieldType>(pb), c0(pb, el.c0), c1(pb, el.c1) {}
                    Fp4_variable(blueprint<FieldType> &pb, const Fp2_variable<Fp2T> &c0, const Fp2_variable<Fp2T> &c1) :
                        component<FieldType>(pb), c0(c0), c1(c1) {}

                    void generate_r1cs_equals_const_constraints(const Fp4T &el) {
                        c0.generate_r1cs_equals_const_constraints(el.c0);
                        c1.generate_r1cs_equals_const_constraints(el.c1);
                    }

                    void generate_r1cs_witness(const Fp4T &el) {
                        c0.generate_r1cs_witness(el.c0);
                        c1.generate_r1cs_witness(el.c1);
                    }

                    Fp4T get_element() {
                        Fp4T el;
                        el.c0 = c0.get_element();
                        el.c1 = c1.get_element();
                        return el;
                    }

                    Fp4_variable<Fp4T> Frobenius_map(const std::size_t power) const {
                        blueprint_linear_combination<FieldType> new_c0c0, new_c0c1, new_c1c0, new_c1c1;
                        new_c0c0.assign(this->pb, c0.c0);
                        new_c0c1.assign(this->pb, c0.c1 * Fp2T::Frobenius_coeffs_c1[power % 2]);
                        new_c1c0.assign(this->pb, c1.c0 * Fp4T::Frobenius_coeffs_c1[power % 4]);
                        new_c1c1.assign(
                            this->pb, c1.c1 * Fp4T::Frobenius_coeffs_c1[power % 4] * Fp2T::Frobenius_coeffs_c1[power % 2]);

                        return Fp4_variable<Fp4T>(this->pb,
                                                  Fp2_variable<Fp2T>(this->pb, new_c0c0, new_c0c1),
                                                  Fp2_variable<Fp2T>(this->pb, new_c1c0, new_c1c1));
                    }

                    void evaluate() const {
                        c0.evaluate();
                        c1.evaluate();
                    }
                };

                /******************************** Fp4_tower_mul_component ************************************/

                /**
                 * Component that creates constraints for Fp4 multiplication (towering formulas).
                 */
                template<typename Fp4T>
                class Fp4_tower_mul_component : public component<typename Fp4T::base_field_type> {
                public:
                    typedef typename Fp4T::base_field_type FieldType;
                    typedef typename Fp4T::underlying_field_type Fp2T;

                    Fp4_variable<Fp4T> A;
                    Fp4_variable<Fp4T> B;
                    Fp4_variable<Fp4T> result;

                    blueprint_linear_combination<FieldType> v0_c0;
                    blueprint_linear_combination<FieldType> v0_c1;

                    blueprint_linear_combination<FieldType> Ac0_plus_Ac1_c0;
                    blueprint_linear_combination<FieldType> Ac0_plus_Ac1_c1;
                    std::shared_ptr<Fp2_variable<Fp2T>> Ac0_plus_Ac1;

                    std::shared_ptr<Fp2_variable<Fp2T>> v0;
                    std::shared_ptr<Fp2_variable<Fp2T>> v1;

                    blueprint_linear_combination<FieldType> Bc0_plus_Bc1_c0;
                    blueprint_linear_combination<FieldType> Bc0_plus_Bc1_c1;
                    std::shared_ptr<Fp2_variable<Fp2T>> Bc0_plus_Bc1;

                    blueprint_linear_combination<FieldType> result_c1_plus_v0_plus_v1_c0;
                    blueprint_linear_combination<FieldType> result_c1_plus_v0_plus_v1_c1;

                    std::shared_ptr<Fp2_variable<Fp2T>> result_c1_plus_v0_plus_v1;

                    std::shared_ptr<Fp2_mul_component<Fp2T>> compute_v0;
                    std::shared_ptr<Fp2_mul_component<Fp2T>> compute_v1;
                    std::shared_ptr<Fp2_mul_component<Fp2T>> compute_result_c1;

                    Fp4_tower_mul_component(blueprint<FieldType> &pb,
                                        const Fp4_variable<Fp4T> &A,
                                        const Fp4_variable<Fp4T> &B,
                                        const Fp4_variable<Fp4T> &result) :
                                        component<FieldType>(pb),
                                        A(A), B(B), result(result) {
                        /*
                          Karatsuba multiplication for Fp4 as a quadratic extension of Fp2:
                          v0 = A.c0 * B.c0
                          v1 = A.c1 * B.c1
                          result.c0 = v0 + non_residue * v1
                          result.c1 = (A.c0 + A.c1) * (B.c0 + B.c1) - v0 - v1
                          where "non_residue * elem" := (non_residue * elt.c1, elt.c0)

                          Enforced with 3 Fp2_mul_component's that ensure that:
                          A.c1 * B.c1 = v1
                          A.c0 * B.c0 = v0
                          (A.c0+A.c1)*(B.c0+B.c1) = result.c1 + v0 + v1

                          Reference:
                          "Multiplication and Squaring on Pairing-Friendly Fields"
                          Devegili, OhEigeartaigh, Scott, Dahab
                        */
                        v1.reset(new Fp2_variable<Fp2T>(pb));

                        compute_v1.reset(new Fp2_mul_component<Fp2T>(pb, A.c1, B.c1, *v1));

                        v0_c0.assign(pb, result.c0.c0 - Fp4T::non_residue * v1->c1);
                        v0_c1.assign(pb, result.c0.c1 - v1->c0);
                        v0.reset(new Fp2_variable<Fp2T>(pb, v0_c0, v0_c1));

                        compute_v0.reset(new Fp2_mul_component<Fp2T>(pb, A.c0, B.c0, *v0));

                        Ac0_plus_Ac1_c0.assign(pb, A.c0.c0 + A.c1.c0);
                        Ac0_plus_Ac1_c1.assign(pb, A.c0.c1 + A.c1.c1);
                        Ac0_plus_Ac1.reset(new Fp2_variable<Fp2T>(pb, Ac0_plus_Ac1_c0, Ac0_plus_Ac1_c1));

                        Bc0_plus_Bc1_c0.assign(pb, B.c0.c0 + B.c1.c0);
                        Bc0_plus_Bc1_c1.assign(pb, B.c0.c1 + B.c1.c1);
                        Bc0_plus_Bc1.reset(new Fp2_variable<Fp2T>(pb, Bc0_plus_Bc1_c0, Bc0_plus_Bc1_c1));

                        result_c1_plus_v0_plus_v1_c0.assign(pb, result.c1.c0 + v0->c0 + v1->c0);
                        result_c1_plus_v0_plus_v1_c1.assign(pb, result.c1.c1 + v0->c1 + v1->c1);
                        result_c1_plus_v0_plus_v1.reset(
                            new Fp2_variable<Fp2T>(pb, result_c1_plus_v0_plus_v1_c0, result_c1_plus_v0_plus_v1_c1));

                        compute_result_c1.reset(
                            new Fp2_mul_component<Fp2T>(pb, *Ac0_plus_Ac1, *Bc0_plus_Bc1, *result_c1_plus_v0_plus_v1));
                    }

                    void generate_r1cs_constraints() {
                        compute_v0->generate_r1cs_constraints();
                        compute_v1->generate_r1cs_constraints();
                        compute_result_c1->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        compute_v0->generate_r1cs_witness();
                        compute_v1->generate_r1cs_witness();

                        Ac0_plus_Ac1_c0.evaluate(this->pb);
                        Ac0_plus_Ac1_c1.evaluate(this->pb);

                        Bc0_plus_Bc1_c0.evaluate(this->pb);
                        Bc0_plus_Bc1_c1.evaluate(this->pb);

                        compute_result_c1->generate_r1cs_witness();

                        const Fp4T Aval = A.get_element();
                        const Fp4T Bval = B.get_element();
                        const Fp4T Rval = Aval * Bval;

                        result.generate_r1cs_witness(Rval);
                    }
                };

                /******************************** Fp4_direct_mul_component ************************************/

                /**
                 * Component that creates constraints for Fp4 multiplication (direct formulas).
                 */
                template<typename Fp4T>
                class Fp4_direct_mul_component : public component<typename Fp4T::base_field_type> {
                public:
                    typedef typename Fp4T::base_field_type FieldType;
                    typedef typename Fp4T::underlying_field_type Fp2T;

                    Fp4_variable<Fp4T> A;
                    Fp4_variable<Fp4T> B;
                    Fp4_variable<Fp4T> result;

                    variable<FieldType> v1;
                    variable<FieldType> v2;
                    variable<FieldType> v6;

                    Fp4_direct_mul_component(blueprint<FieldType> &pb,
                                          const Fp4_variable<Fp4T> &A,
                                          const Fp4_variable<Fp4T> &B,
                                          const Fp4_variable<Fp4T> &result) :
                                          component<FieldType>(pb),
                                          A(A), B(B), result(result) {
                        /*
                            Tom-Cook-4x for Fp4 (beta is the quartic non-residue):
                                v0 = a0*b0,
                                v1 = (a0+a1+a2+a3)*(b0+b1+b2+b3),
                                v2 = (a0-a1+a2-a3)*(b0-b1+b2-b3),
                                v3 = (a0+2a1+4a2+8a3)*(b0+2b1+4b2+8b3),
                                v4 = (a0-2a1+4a2-8a3)*(b0-2b1+4b2-8b3),
                                v5 = (a0+3a1+9a2+27a3)*(b0+3b1+9b2+27b3),
                                v6 = a3*b3

                                result.c0 = v0+beta((1/4)v0-(1/6)(v1+v2)+(1/24)(v3+v4)-5v6),
                                result.c1 =
                           -(1/3)v0+v1-(1/2)v2-(1/4)v3+(1/20)v4+(1/30)v5-12v6+beta(-(1/12)(v0-v1)+(1/24)(v2-v3)-(1/120)(v4-v5)-3v6),
                                result.c2 = -(5/4)v0+(2/3)(v1+v2)-(1/24)(v3+v4)+4v6+beta v6,
                                result.c3 = (1/12)(5v0-7v1)-(1/24)(v2-7v3+v4+v5)+15v6

                            Enforced with 7 constraints. Doing so requires some care, as we first
                            compute three of the v_i explicitly, and then "inline" result.c0/c1/c2/c3
                            in computations of the remaining four v_i.

                            Concretely, we first compute v1, v2 and v6 explicitly, via 3 constraints as above.
                                v1 = (a0+a1+a2+a3)*(b0+b1+b2+b3),
                                v2 = (a0-a1+a2-a3)*(b0-b1+b2-b3),
                                v6 = a3*b3

                            Then we use the following 4 additional constraints:
                                (1-beta) v0 = c0 + beta c2 - (beta v1)/2 - (beta v2)/ 2 - (-1 + beta) beta v6
                                (1-beta) v3 = -15 c0 - 30 c1 - 3 (4 + beta) c2 - 6 (4 + beta) c3 + (24 - (3 beta)/2) v1 +
                           (-8 + beta/2) v2 + 3 (-16 + beta) (-1 + beta) v6 (1-beta) v4 = -15 c0 + 30 c1 - 3 (4 + beta) c2 +
                           6 (4 + beta) c3 + (-8 + beta/2) v1 + (24 - (3 beta)/2) v2 + 3 (-16 + beta) (-1 + beta) v6
                           (1-beta) v5 = -80 c0 - 240 c1 - 8 (9 + beta) c2 - 24 (9 + beta) c3 - 2 (-81 + beta) v1 + (-81 +
                           beta) v2 + 8 (-81 + beta) (-1 + beta) v6

                            The isomorphism between the representation above and towering is:
                                (a0, a1, a2, a3) <-> (a.c0.c0, a.c1.c0, a.c0.c1, a.c1.c1)

                            Reference:
                                "Multiplication and Squaring on Pairing-Friendly Fields"
                                Devegili, OhEigeartaigh, Scott, Dahab

                            NOTE: the expressions above were cherry-picked from the Mathematica result
                            of the following command:

                            (# -> Solve[{c0 == v0+beta((1/4)v0-(1/6)(v1+v2)+(1/24)(v3+v4)-5v6),
                            c1 ==
                           -(1/3)v0+v1-(1/2)v2-(1/4)v3+(1/20)v4+(1/30)v5-12v6+beta(-(1/12)(v0-v1)+(1/24)(v2-v3)-(1/120)(v4-v5)-3v6),
                           c2
                           == -(5/4)v0+(2/3)(v1+v2)-(1/24)(v3+v4)+4v6+beta v6, c3 ==
                           (1/12)(5v0-7v1)-(1/24)(v2-7v3+v4+v5)+15v6}, #] // FullSimplify) & /@ Subsets[{v0, v1, v2, v3, v4,
                           v5}, {4}]

                            and simplified by multiplying the selected result by (1-beta)
                        */
                        v1.allocate(pb);
                        v2.allocate(pb);
                        v6.allocate(pb);
                    }

                    void generate_r1cs_constraints() {
                        const typename FieldType::value_type beta = Fp4T::non_residue;
                        const typename FieldType::value_type u = (FieldType::value_type::zero() - beta).inversed();

                        const blueprint_linear_combination<FieldType> &a0 = A.c0.c0, &a1 = A.c1.c0, &a2 = A.c0.c1, &a3 = A.c1.c1,
                                                               &b0 = B.c0.c0, &b1 = B.c1.c0, &b2 = B.c0.c1, &b3 = B.c1.c1,
                                                               &c0 = result.c0.c0, &c1 = result.c1.c0, &c2 = result.c0.c1,
                                                               &c3 = result.c1.c1;

                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a0 + a1 + a2 + a3, b0 + b1 + b2 + b3, v1));
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a0 - a1 + a2 - a3, b0 - b1 + b2 - b3, v2));
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a3, b3, v6));

                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            a0,
                            b0,
                            u * c0 + beta * u * c2 - beta * u * typename FieldType::value_type(0x02).inversed() * v1 -
                                beta * u * typename FieldType::value_type(0x02).inversed() * v2 + beta * v6));
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            a0 + typename FieldType::value_type(0x02) * a1 + typename FieldType::value_type(0x04) * a2 +
                                typename FieldType::value_type(0x08) * a3,
                            b0 + typename FieldType::value_type(0x02) * b1 + typename FieldType::value_type(0x04) * b2 +
                                typename FieldType::value_type(0x08) * b3,
                            -typename FieldType::value_type(15) * u * c0 - typename FieldType::value_type(30) * u * c1 -
                                typename FieldType::value_type(0x03) * (typename FieldType::value_type(0x04) + beta) * u * c2 -
                                typename FieldType::value_type(6) * (typename FieldType::value_type(0x04) + beta) * u * c3 +
                                (typename FieldType::value_type(24) -
                                 typename FieldType::value_type(0x03) * beta * typename FieldType::value_type(0x02).inversed()) *
                                    u * v1 +
                                (-typename FieldType::value_type(0x08) + beta * typename FieldType::value_type(0x02).inversed()) *
                                    u * v2 -
                                typename FieldType::value_type(0x03) * (-typename FieldType::value_type(16) + beta) * v6));
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            a0 - typename FieldType::value_type(0x02) * a1 + typename FieldType::value_type(0x04) * a2 -
                                typename FieldType::value_type(0x08) * a3,
                            b0 - typename FieldType::value_type(0x02) * b1 + typename FieldType::value_type(0x04) * b2 -
                                typename FieldType::value_type(0x08) * b3,
                            -typename FieldType::value_type(15) * u * c0 + typename FieldType::value_type(30) * u * c1 -
                                typename FieldType::value_type(0x03) * (typename FieldType::value_type(0x04) + beta) * u * c2 +
                                typename FieldType::value_type(6) * (typename FieldType::value_type(0x04) + beta) * u * c3 +
                                (typename FieldType::value_type(24) -
                                 typename FieldType::value_type(0x03) * beta * typename FieldType::value_type(0x02).inversed()) *
                                    u * v2 +
                                (-typename FieldType::value_type(0x08) + beta * typename FieldType::value_type(0x02).inversed()) *
                                    u * v1 -
                                typename FieldType::value_type(0x03) * (-typename FieldType::value_type(16) + beta) * v6));
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            a0 + typename FieldType::value_type(0x03) * a1 + typename FieldType::value_type(0x09) * a2 +
                                typename FieldType::value_type(27) * a3,
                            b0 + typename FieldType::value_type(0x03) * b1 + typename FieldType::value_type(0x09) * b2 +
                                typename FieldType::value_type(27) * b3,
                            -typename FieldType::value_type(80) * u * c0 - typename FieldType::value_type(240) * u * c1 -
                                typename FieldType::value_type(0x08) * (typename FieldType::value_type(0x09) + beta) * u * c2 -
                                typename FieldType::value_type(24) * (typename FieldType::value_type(0x09) + beta) * u * c3 -
                                typename FieldType::value_type(0x02) * (-typename FieldType::value_type(81) + beta) * u * v1 +
                                (-typename FieldType::value_type(81) + beta) * u * v2 -
                                typename FieldType::value_type(0x08) * (-typename FieldType::value_type(81) + beta) * v6));
                    }

                    void generate_r1cs_witness() {
                        const blueprint_linear_combination<FieldType> &a0 = A.c0.c0, &a1 = A.c1.c0, &a2 = A.c0.c1, &a3 = A.c1.c1,
                                                               &b0 = B.c0.c0, &b1 = B.c1.c0, &b2 = B.c0.c1, &b3 = B.c1.c1;

                        this->pb.val(v1) =
                            ((this->pb.lc_val(a0) + this->pb.lc_val(a1) + this->pb.lc_val(a2) + this->pb.lc_val(a3)) *
                             (this->pb.lc_val(b0) + this->pb.lc_val(b1) + this->pb.lc_val(b2) + this->pb.lc_val(b3)));
                        this->pb.val(v2) =
                            ((this->pb.lc_val(a0) - this->pb.lc_val(a1) + this->pb.lc_val(a2) - this->pb.lc_val(a3)) *
                             (this->pb.lc_val(b0) - this->pb.lc_val(b1) + this->pb.lc_val(b2) - this->pb.lc_val(b3)));
                        this->pb.val(v6) = this->pb.lc_val(a3) * this->pb.lc_val(b3);

                        const Fp4T Aval = A.get_element();
                        const Fp4T Bval = B.get_element();
                        const Fp4T Rval = Aval * Bval;

                        result.generate_r1cs_witness(Rval);
                    }
                };

                /**
                 * Alias default multiplication component
                 */
                template<typename Fp4T>
                using Fp4_mul_component = Fp4_direct_mul_component<Fp4T>;

                /******************************** Fp4_sqr_component ************************************/

                /**
                 * Component that creates constraints for Fp4 squaring.
                 */
                template<typename Fp4T>
                class Fp4_sqr_component : public component<typename Fp4T::base_field_type> {
                public:
                    typedef typename Fp4T::base_field_type FieldType;
                    typedef typename Fp4T::underlying_field_type Fp2T;

                    Fp4_variable<Fp4T> A;
                    Fp4_variable<Fp4T> result;

                    std::shared_ptr<Fp2_variable<Fp2T>> v1;

                    blueprint_linear_combination<FieldType> v0_c0;
                    blueprint_linear_combination<FieldType> v0_c1;
                    std::shared_ptr<Fp2_variable<Fp2T>> v0;

                    std::shared_ptr<Fp2_sqr_component<Fp2T>> compute_v0;
                    std::shared_ptr<Fp2_sqr_component<Fp2T>> compute_v1;

                    blueprint_linear_combination<FieldType> Ac0_plus_Ac1_c0;
                    blueprint_linear_combination<FieldType> Ac0_plus_Ac1_c1;
                    std::shared_ptr<Fp2_variable<Fp2T>> Ac0_plus_Ac1;

                    blueprint_linear_combination<FieldType> result_c1_plus_v0_plus_v1_c0;
                    blueprint_linear_combination<FieldType> result_c1_plus_v0_plus_v1_c1;

                    std::shared_ptr<Fp2_variable<Fp2T>> result_c1_plus_v0_plus_v1;

                    std::shared_ptr<Fp2_sqr_component<Fp2T>> compute_result_c1;

                    Fp4_sqr_component(blueprint<FieldType> &pb,
                                   const Fp4_variable<Fp4T> &A,
                                   const Fp4_variable<Fp4T> &result) :
                                   component<FieldType>(pb),
                                   A(A), result(result) {
                        /*
                          Karatsuba squaring for Fp4 as a quadratic extension of Fp2:
                          v0 = A.c0^2
                          v1 = A.c1^2
                          result.c0 = v0 + non_residue * v1
                          result.c1 = (A.c0 + A.c1)^2 - v0 - v1
                          where "non_residue * elem" := (non_residue * elt.c1, elt.c0)

                          Enforced with 3 Fp2_sqr_component's that ensure that:
                          A.c1^2 = v1
                          A.c0^2 = v0
                          (A.c0+A.c1)^2 = result.c1 + v0 + v1

                          Reference:
                          "Multiplication and Squaring on Pairing-Friendly Fields"
                          Devegili, OhEigeartaigh, Scott, Dahab
                        */

                        v1.reset(new Fp2_variable<Fp2T>(pb));
                        compute_v1.reset(new Fp2_sqr_component<Fp2T>(pb, A.c1, *v1));

                        v0_c0.assign(pb, result.c0.c0 - Fp4T::non_residue * v1->c1);
                        v0_c1.assign(pb, result.c0.c1 - v1->c0);
                        v0.reset(new Fp2_variable<Fp2T>(pb, v0_c0, v0_c1));

                        compute_v0.reset(new Fp2_sqr_component<Fp2T>(pb, A.c0, *v0));

                        Ac0_plus_Ac1_c0.assign(pb, A.c0.c0 + A.c1.c0);
                        Ac0_plus_Ac1_c1.assign(pb, A.c0.c1 + A.c1.c1);
                        Ac0_plus_Ac1.reset(new Fp2_variable<Fp2T>(pb, Ac0_plus_Ac1_c0, Ac0_plus_Ac1_c1));

                        result_c1_plus_v0_plus_v1_c0.assign(pb, result.c1.c0 + v0->c0 + v1->c0);
                        result_c1_plus_v0_plus_v1_c1.assign(pb, result.c1.c1 + v0->c1 + v1->c1);
                        result_c1_plus_v0_plus_v1.reset(
                            new Fp2_variable<Fp2T>(pb, result_c1_plus_v0_plus_v1_c0, result_c1_plus_v0_plus_v1_c1));

                        compute_result_c1.reset(new Fp2_sqr_component<Fp2T>(pb, *Ac0_plus_Ac1, *result_c1_plus_v0_plus_v1));
                    }

                    void generate_r1cs_constraints() {
                        compute_v1->generate_r1cs_constraints();
                        compute_v0->generate_r1cs_constraints();
                        compute_result_c1->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        compute_v1->generate_r1cs_witness();

                        v0_c0.evaluate(this->pb);
                        v0_c1.evaluate(this->pb);
                        compute_v0->generate_r1cs_witness();

                        Ac0_plus_Ac1_c0.evaluate(this->pb);
                        Ac0_plus_Ac1_c1.evaluate(this->pb);
                        compute_result_c1->generate_r1cs_witness();

                        const Fp4T Aval = A.get_element();
                        const Fp4T Rval = Aval.squared();
                        result.generate_r1cs_witness(Rval);
                    }
                };

                /******************************** Fp4_cyclotomic_sqr_component ************************************/

                /**
                 * Component that creates constraints for Fp4 cyclotomic squaring
                 */
                template<typename Fp4T>
                class Fp4_cyclotomic_sqr_component : public component<typename Fp4T::base_field_type> {
                public:
                    /*
                     */
                    typedef typename Fp4T::base_field_type FieldType;
                    typedef typename Fp4T::underlying_field_type Fp2T;

                    Fp4_variable<Fp4T> A;
                    Fp4_variable<Fp4T> result;

                    blueprint_linear_combination<FieldType> c0_expr_c0;
                    blueprint_linear_combination<FieldType> c0_expr_c1;
                    std::shared_ptr<Fp2_variable<Fp2T>> c0_expr;
                    std::shared_ptr<Fp2_sqr_component<Fp2T>> compute_c0_expr;

                    blueprint_linear_combination<FieldType> A_c0_plus_A_c1_c0;
                    blueprint_linear_combination<FieldType> A_c0_plus_A_c1_c1;
                    std::shared_ptr<Fp2_variable<Fp2T>> A_c0_plus_A_c1;

                    blueprint_linear_combination<FieldType> c1_expr_c0;
                    blueprint_linear_combination<FieldType> c1_expr_c1;
                    std::shared_ptr<Fp2_variable<Fp2T>> c1_expr;
                    std::shared_ptr<Fp2_sqr_component<Fp2T>> compute_c1_expr;

                    Fp4_cyclotomic_sqr_component(blueprint<FieldType> &pb,
                                              const Fp4_variable<Fp4T> &A,
                                              const Fp4_variable<Fp4T> &result) :
                                              component<FieldType>(pb),
                                              A(A), result(result) {
                        /*
                          A = elt.c1 ^ 2
                          B = elt.c1 + elt.c0;
                          C = B ^ 2 - A
                          D = Fp2(A.c1 * non_residue, A.c0)
                          E = C - D
                          F = D + D + Fp2::one()
                          G = E - Fp2::one()

                          return Fp4(F, G);

                          Enforced with 2 Fp2_sqr_component's that ensure that:

                          elt.c1 ^ 2 = Fp2(result.c0.c1 / 2, (result.c0.c0 - 1) / (2 * non_residue)) = A
                          (elt.c1 + elt.c0) ^ 2 = A + result.c1 + Fp2(A.c1 * non_residue + 1, A.c0)

                          (elt.c1 + elt.c0) ^ 2 = Fp2(result.c0.c1 / 2 + result.c1.c0 + (result.c0.c0 - 1) / 2 + 1,
                                                      (result.c0.c0 - 1) / (2 * non_residue) + result.c1.c1 + result.c0.c1 /
                          2)
                        */
                        c0_expr_c0.assign(pb, result.c0.c1 * typename FieldType::value_type(0x02).inversed());
                        c0_expr_c1.assign(pb,
                                          (result.c0.c0 - typename FieldType::value_type(0x01)) *
                                              (typename FieldType::value_type(0x02) * Fp4T::non_residue).inversed());
                        c0_expr.reset(new Fp2_variable<Fp2T>(pb, c0_expr_c0, c0_expr_c1));
                        compute_c0_expr.reset(new Fp2_sqr_component<Fp2T>(pb, A.c1, *c0_expr));

                        A_c0_plus_A_c1_c0.assign(pb, A.c0.c0 + A.c1.c0);
                        A_c0_plus_A_c1_c1.assign(pb, A.c0.c1 + A.c1.c1);
                        A_c0_plus_A_c1.reset(new Fp2_variable<Fp2T>(pb, A_c0_plus_A_c1_c0, A_c0_plus_A_c1_c1));

                        c1_expr_c0.assign(pb,
                                          (result.c0.c1 + result.c0.c0 - typename FieldType::value_type(0x01)) *
                                                  typename FieldType::value_type(0x02).inversed() +
                                              result.c1.c0 + typename FieldType::value_type(0x01));
                        c1_expr_c1.assign(pb,
                                          (result.c0.c0 - typename FieldType::value_type(0x01)) *
                                                  (typename FieldType::value_type(0x02) * Fp4T::non_residue).inversed() +
                                              result.c1.c1 + result.c0.c1 * typename FieldType::value_type(0x02).inversed());
                        c1_expr.reset(new Fp2_variable<Fp2T>(pb, c1_expr_c0, c1_expr_c1));

                        compute_c1_expr.reset(new Fp2_sqr_component<Fp2T>(pb, *A_c0_plus_A_c1, *c1_expr));
                    }

                    void generate_r1cs_constraints() {
                        compute_c0_expr->generate_r1cs_constraints();
                        compute_c1_expr->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        compute_c0_expr->generate_r1cs_witness();

                        A_c0_plus_A_c1_c0.evaluate(this->pb);
                        A_c0_plus_A_c1_c1.evaluate(this->pb);
                        compute_c1_expr->generate_r1cs_witness();

                        const Fp4T Aval = A.get_element();
                        const Fp4T Rval = Aval.squared();
                        result.generate_r1cs_witness(Rval);
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_FP4_COMPONENTS_HPP
