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
// @file Declaration of interfaces for Fp4 components.
//
// The components verify field arithmetic in Fp4 = Fp2[V]/(V^2-U) where
// Fp2 = Fp[U]/(U^2-non_residue) and non_residue is in Fp.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_FP4_COMPONENTS_HPP
#define CRYPTO3_ZK_FP4_COMPONENTS_HPP

#include <nil/crypto3/zk/snark/component.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp2_components.hpp>

#include <nil/crypto3/zk/snark/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace components {

                    /******************************** Fp4_variable ************************************/

                    /**
                     * Component that represents an Fp4 variable.
                     */
                    template<typename Fp4T>
                    struct Fp4_variable : public component<typename Fp4T::base_field_type> {
                        typedef typename Fp4T::base_field_type base_field_type;
                        typedef typename Fp4T::underlying_field_type Fp2T;

                        using underlying_type = Fp2_variable<Fp2T>;

                        using data_type = std::array<underlying_type, Fp4T::arity / Fp4T::underlying_field_type::arity>;

                        data_type data;

                        Fp4_variable(blueprint<base_field_type> &bp) :
                            component<base_field_type>(bp), data({underlying_type(bp), underlying_type(bp)}) {
                        }

                        Fp4_variable(blueprint<base_field_type> &bp, const typename Fp4T::value_type &el) :
                            component<base_field_type>(bp),
                            data({underlying_type(bp, el.data[0]), underlying_type(bp, el.data[1])}) {
                        }

                        Fp4_variable(blueprint<base_field_type> &bp, const Fp2_variable<Fp2T> &in_data0,
                                     const Fp2_variable<Fp2T> &in_data1) :
                            component<base_field_type>(bp),
                            data({underlying_type(in_data0), underlying_type(in_data1)}) {
                        }

                        void generate_r1cs_equals_const_constraints(const typename Fp4T::value_type &el) {
                            data[0].generate_r1cs_equals_const_constraints(el.data[0]);
                            data[1].generate_r1cs_equals_const_constraints(el.data[1]);
                        }

                        void generate_r1cs_witness(const typename Fp4T::value_type &el) {
                            data[0].generate_r1cs_witness(el.data[0]);
                            data[1].generate_r1cs_witness(el.data[1]);
                        }

                        typename Fp4T::value_type get_element() {
                            typename Fp4T::value_type el;
                            el.data[0] = data[0].get_element();
                            el.data[1] = data[1].get_element();
                            return el;
                        }

                        Fp4_variable<Fp4T> Frobenius_map(const std::size_t power) const {
                            blueprint_linear_combination<base_field_type> new_c0c0, new_c0c1, new_c1c0, new_c1c1;
                            new_c0c0.assign(this->bp, data[0].data[0]);
                            new_c0c1.assign(this->bp, data[0].data[1] * Fp2T::Frobenius_coeffs_c1[power % 2]);
                            new_c1c0.assign(this->bp, data[1].data[0] * Fp4T::Frobenius_coeffs_c1[power % 4]);
                            new_c1c1.assign(this->bp,
                                            data[1].data[1] * Fp4T::Frobenius_coeffs_c1[power % 4] *
                                                Fp2T::Frobenius_coeffs_c1[power % 2]);

                            return Fp4_variable<Fp4T>(this->bp,
                                                      Fp2_variable<Fp2T>(this->bp, new_c0c0, new_c0c1),
                                                      Fp2_variable<Fp2T>(this->bp, new_c1c0, new_c1c1));
                        }

                        void evaluate() const {
                            data[0].evaluate();
                            data[1].evaluate();
                        }
                    };

                    /******************************** Fp4_tower_mul_component ************************************/

                    /**
                     * Component that creates constraints for Fp4 multiplication (towering formulas).
                     */
                    template<typename Fp4T>
                    class Fp4_tower_mul_component : public component<typename Fp4T::base_field_type> {
                    public:
                        typedef typename Fp4T::base_field_type base_field_type;
                        typedef typename Fp4T::underlying_field_type Fp2T;

                        Fp4_variable<Fp4T> A;
                        Fp4_variable<Fp4T> B;
                        Fp4_variable<Fp4T> result;

                        blueprint_linear_combination<base_field_type> v0_c0;
                        blueprint_linear_combination<base_field_type> v0_c1;

                        blueprint_linear_combination<base_field_type> Ac0_plus_Ac1_c0;
                        blueprint_linear_combination<base_field_type> Ac0_plus_Ac1_c1;
                        std::shared_ptr<Fp2_variable<Fp2T>> Ac0_plus_Ac1;

                        std::shared_ptr<Fp2_variable<Fp2T>> v0;
                        std::shared_ptr<Fp2_variable<Fp2T>> v1;

                        blueprint_linear_combination<base_field_type> Bc0_plus_Bc1_c0;
                        blueprint_linear_combination<base_field_type> Bc0_plus_Bc1_c1;
                        std::shared_ptr<Fp2_variable<Fp2T>> Bc0_plus_Bc1;

                        blueprint_linear_combination<base_field_type> result_c1_plus_v0_plus_v1_c0;
                        blueprint_linear_combination<base_field_type> result_c1_plus_v0_plus_v1_c1;

                        std::shared_ptr<Fp2_variable<Fp2T>> result_c1_plus_v0_plus_v1;

                        std::shared_ptr<Fp2_mul_component<Fp2T>> compute_v0;
                        std::shared_ptr<Fp2_mul_component<Fp2T>> compute_v1;
                        std::shared_ptr<Fp2_mul_component<Fp2T>> compute_result_c1;

                        Fp4_tower_mul_component(blueprint<base_field_type> &bp,
                                                const Fp4_variable<Fp4T> &A,
                                                const Fp4_variable<Fp4T> &B,
                                                const Fp4_variable<Fp4T> &result) :
                            component<base_field_type>(bp),
                            A(A), B(B), result(result) {
                            /*
                              Karatsuba multiplication for Fp4 as a quadratic extension of Fp2:
                              v0 = A.data[0] * B.data[0]
                              v1 = A.data[1] * B.data[1]
                              result.data[0] = v0 + non_residue * v1
                              result.data[1] = (A.data[0] + A.data[1]) * (B.data[0] + B.data[1]) - v0 - v1
                              where "non_residue * elem" := (non_residue * elt.data[1], elt.data[0])

                              Enforced with 3 Fp2_mul_component's that ensure that:
                              A.data[1] * B.data[1] = v1
                              A.data[0] * B.data[0] = v0
                              (A.data[0]+A.data[1])*(B.data[0]+B.data[1]) = result.data[1] + v0 + v1

                              Reference:
                              "Multiplication and Squaring on Pairing-Friendly Fields"
                              Devegili, OhEigeartaigh, Scott, Dahab
                            */
                            v1.reset(new Fp2_variable<Fp2T>(bp));

                            compute_v1.reset(new Fp2_mul_component<Fp2T>(bp, A.data[1], B.data[1], *v1));

                            v0_c0.assign(bp, result.data[0].data[0] - Fp4T::value_type::non_residue * v1->data[1]);

                            v0_c1.assign(bp, result.data[0].data[1] - v1->data[0]);
                            v0.reset(new Fp2_variable<Fp2T>(bp, v0_c0, v0_c1));

                            compute_v0.reset(new Fp2_mul_component<Fp2T>(bp, A.data[0], B.data[0], *v0));

                            Ac0_plus_Ac1_c0.assign(bp, A.data[0].data[0] + A.data[1].data[0]);
                            Ac0_plus_Ac1_c1.assign(bp, A.data[0].data[1] + A.data[1].data[1]);
                            Ac0_plus_Ac1.reset(new Fp2_variable<Fp2T>(bp, Ac0_plus_Ac1_c0, Ac0_plus_Ac1_c1));

                            Bc0_plus_Bc1_c0.assign(bp, B.data[0].data[0] + B.data[1].data[0]);
                            Bc0_plus_Bc1_c1.assign(bp, B.data[0].data[1] + B.data[1].data[1]);
                            Bc0_plus_Bc1.reset(new Fp2_variable<Fp2T>(bp, Bc0_plus_Bc1_c0, Bc0_plus_Bc1_c1));

                            result_c1_plus_v0_plus_v1_c0.assign(bp, result.data[1].data[0] + v0->data[0] + v1->data[0]);
                            result_c1_plus_v0_plus_v1_c1.assign(bp, result.data[1].data[1] + v0->data[1] + v1->data[1]);
                            result_c1_plus_v0_plus_v1.reset(
                                new Fp2_variable<Fp2T>(bp, result_c1_plus_v0_plus_v1_c0, result_c1_plus_v0_plus_v1_c1));

                            compute_result_c1.reset(new Fp2_mul_component<Fp2T>(bp, *Ac0_plus_Ac1, *Bc0_plus_Bc1,
                                                                                *result_c1_plus_v0_plus_v1));
                        }

                        void generate_r1cs_constraints() {
                            compute_v0->generate_r1cs_constraints();
                            compute_v1->generate_r1cs_constraints();
                            compute_result_c1->generate_r1cs_constraints();
                        }

                        void generate_r1cs_witness() {
                            compute_v0->generate_r1cs_witness();
                            compute_v1->generate_r1cs_witness();

                            Ac0_plus_Ac1_c0.evaluate(this->bp);
                            Ac0_plus_Ac1_c1.evaluate(this->bp);

                            Bc0_plus_Bc1_c0.evaluate(this->bp);
                            Bc0_plus_Bc1_c1.evaluate(this->bp);

                            compute_result_c1->generate_r1cs_witness();

                            const typename Fp4T::value_type Aval = A.get_element();
                            const typename Fp4T::value_type Bval = B.get_element();
                            const typename Fp4T::value_type Rval = Aval * Bval;

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
                        typedef typename Fp4T::base_field_type base_field_type;
                        typedef typename Fp4T::underlying_field_type Fp2T;

                        using base_field_value_type = typename base_field_type::value_type;

                        Fp4_variable<Fp4T> A;
                        Fp4_variable<Fp4T> B;
                        Fp4_variable<Fp4T> result;

                        blueprint_variable<base_field_type> v1;
                        blueprint_variable<base_field_type> v2;
                        blueprint_variable<base_field_type> v6;

                        Fp4_direct_mul_component(blueprint<base_field_type> &bp,
                                                 const Fp4_variable<Fp4T> &A,
                                                 const Fp4_variable<Fp4T> &B,
                                                 const Fp4_variable<Fp4T> &result) :
                            component<base_field_type>(bp),
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

                                    result.data[0] = v0+beta((1/4)v0-(1/6)(v1+v2)+(1/24)(v3+v4)-5v6),
                                    result.data[1] =
                               -(1/3)v0+v1-(1/2)v2-(1/4)v3+(1/20)v4+(1/30)v5-12v6+beta(-(1/12)(v0-v1)+(1/24)(v2-v3)-(1/120)(v4-v5)-3v6),
                                    result.c2 = -(5/4)v0+(2/3)(v1+v2)-(1/24)(v3+v4)+4v6+beta v6,
                                    result.c3 = (1/12)(5v0-7v1)-(1/24)(v2-7v3+v4+v5)+15v6

                                Enforced with 7 constraints. Doing so requires some care, as we first
                                compute three of the v_i explicitly, and then "inline" result.data[0]/c1/c2/c3
                                in computations of the remaining four v_i.

                                Concretely, we first compute v1, v2 and v6 explicitly, via 3 constraints as above.
                                    v1 = (a0+a1+a2+a3)*(b0+b1+b2+b3),
                                    v2 = (a0-a1+a2-a3)*(b0-b1+b2-b3),
                                    v6 = a3*b3

                                Then we use the following 4 additional constraints:
                                    (1-beta) v0 = c0 + beta c2 - (beta v1)/2 - (beta v2)/ 2 - (-1 + beta) beta v6
                                    (1-beta) v3 = -15 c0 - 30 c1 - 3 (4 + beta) c2 - 6 (4 + beta) c3 + (24 - (3 beta)/2)
                               v1
                               +
                               (-8 + beta/2) v2 + 3 (-16 + beta) (-1 + beta) v6 (1-beta) v4 = -15 c0 + 30 c1 - 3 (4 +
                               beta) c2 + 6 (4 + beta) c3 + (-8 + beta/2) v1 + (24 - (3 beta)/2) v2 + 3 (-16 + beta) (-1
                               + beta) v6 (1-beta) v5 = -80 c0 - 240 c1 - 8 (9 + beta) c2 - 24 (9 + beta) c3 - 2 (-81 +
                               beta) v1 +
                               (-81 + beta) v2 + 8 (-81 + beta) (-1 + beta) v6

                                The isomorphism between the representation above and towering is:
                                    (a0, a1, a2, a3) <-> (a.data[0].data[0], a.data[1].data[0], a.data[0].data[1],
                               a.data[1].data[1])

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
                               (1/12)(5v0-7v1)-(1/24)(v2-7v3+v4+v5)+15v6}, #] // FullSimplify) & /@ Subsets[{v0, v1, v2,
                               v3, v4, v5}, {4}]

                                and simplified by multiplying the selected result by (1-beta)
                            */
                            v1.allocate(bp);
                            v2.allocate(bp);
                            v6.allocate(bp);
                        }

                        void generate_r1cs_constraints() {
                            const base_field_value_type beta = Fp4T::value_type::non_residue;

                            const base_field_value_type u = (base_field_value_type::one() - beta).inversed();

                            const blueprint_linear_combination<base_field_type> &a0 = A.data[0].data[0],
                                                                                &a1 = A.data[1].data[0],
                                                                                &a2 = A.data[0].data[1],
                                                                                &a3 = A.data[1].data[1],
                                                                                &b0 = B.data[0].data[0],
                                                                                &b1 = B.data[1].data[0],
                                                                                &b2 = B.data[0].data[1],
                                                                                &b3 = B.data[1].data[1],
                                                                                &c0 = result.data[0].data[0],
                                                                                &c1 = result.data[1].data[0],
                                                                                &c2 = result.data[0].data[1],
                                                                                &c3 = result.data[1].data[1];

                            this->bp.add_r1cs_constraint(
                                r1cs_constraint<base_field_type>(a0 + a1 + a2 + a3, b0 + b1 + b2 + b3, v1));
                            this->bp.add_r1cs_constraint(
                                r1cs_constraint<base_field_type>(a0 - a1 + a2 - a3, b0 - b1 + b2 - b3, v2));
                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(a3, b3, v6));

                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(
                                a0,
                                b0,
                                u * c0 + beta * u * c2 - beta * u * base_field_value_type(0x02).inversed() * v1 -
                                    beta * u * base_field_value_type(0x02).inversed() * v2 + beta * v6));
                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(
                                a0 + base_field_value_type(0x02) * a1 + base_field_value_type(0x04) * a2 +
                                    base_field_value_type(0x08) * a3,
                                b0 + base_field_value_type(0x02) * b1 + base_field_value_type(0x04) * b2 +
                                    base_field_value_type(0x08) * b3,
                                -base_field_value_type(15) * u * c0 - base_field_value_type(30) * u * c1 -
                                    base_field_value_type(0x03) * (base_field_value_type(0x04) + beta) * u * c2 -
                                    base_field_value_type(6) * (base_field_value_type(0x04) + beta) * u * c3 +
                                    (base_field_value_type(24) -
                                     base_field_value_type(0x03) * beta * base_field_value_type(0x02).inversed()) *
                                        u * v1 +
                                    (-base_field_value_type(0x08) + beta * base_field_value_type(0x02).inversed()) * u *
                                        v2 -
                                    base_field_value_type(0x03) * (-base_field_value_type(16) + beta) * v6));
                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(
                                a0 - base_field_value_type(0x02) * a1 + base_field_value_type(0x04) * a2 -
                                    base_field_value_type(0x08) * a3,
                                b0 - base_field_value_type(0x02) * b1 + base_field_value_type(0x04) * b2 -
                                    base_field_value_type(0x08) * b3,
                                -base_field_value_type(15) * u * c0 + base_field_value_type(30) * u * c1 -
                                    base_field_value_type(0x03) * (base_field_value_type(0x04) + beta) * u * c2 +
                                    base_field_value_type(6) * (base_field_value_type(0x04) + beta) * u * c3 +
                                    (base_field_value_type(24) -
                                     base_field_value_type(0x03) * beta * base_field_value_type(0x02).inversed()) *
                                        u * v2 +
                                    (-base_field_value_type(0x08) + beta * base_field_value_type(0x02).inversed()) * u *
                                        v1 -
                                    base_field_value_type(0x03) * (-base_field_value_type(16) + beta) * v6));
                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(
                                a0 + base_field_value_type(0x03) * a1 + base_field_value_type(0x09) * a2 +
                                    base_field_value_type(27) * a3,
                                b0 + base_field_value_type(0x03) * b1 + base_field_value_type(0x09) * b2 +
                                    base_field_value_type(27) * b3,
                                -base_field_value_type(80) * u * c0 - base_field_value_type(240) * u * c1 -
                                    base_field_value_type(0x08) * (base_field_value_type(0x09) + beta) * u * c2 -
                                    base_field_value_type(24) * (base_field_value_type(0x09) + beta) * u * c3 -
                                    base_field_value_type(0x02) * (-base_field_value_type(81) + beta) * u * v1 +
                                    (-base_field_value_type(81) + beta) * u * v2 -
                                    base_field_value_type(0x08) * (-base_field_value_type(81) + beta) * v6));
                        }

                        void generate_r1cs_witness() {
                            const blueprint_linear_combination<base_field_type> &a0 = A.data[0].data[0],
                                                                                &a1 = A.data[1].data[0],
                                                                                &a2 = A.data[0].data[1],
                                                                                &a3 = A.data[1].data[1],
                                                                                &b0 = B.data[0].data[0],
                                                                                &b1 = B.data[1].data[0],
                                                                                &b2 = B.data[0].data[1],
                                                                                &b3 = B.data[1].data[1];

                            this->bp.val(v1) = ((this->bp.lc_val(a0) + this->bp.lc_val(a1) + this->bp.lc_val(a2) +
                                                 this->bp.lc_val(a3)) *
                                                (this->bp.lc_val(b0) + this->bp.lc_val(b1) + this->bp.lc_val(b2) +
                                                 this->bp.lc_val(b3)));
                            this->bp.val(v2) = ((this->bp.lc_val(a0) - this->bp.lc_val(a1) + this->bp.lc_val(a2) -
                                                 this->bp.lc_val(a3)) *
                                                (this->bp.lc_val(b0) - this->bp.lc_val(b1) + this->bp.lc_val(b2) -
                                                 this->bp.lc_val(b3)));
                            this->bp.val(v6) = this->bp.lc_val(a3) * this->bp.lc_val(b3);

                            const typename Fp4T::value_type Aval = A.get_element();
                            const typename Fp4T::value_type Bval = B.get_element();
                            const typename Fp4T::value_type Rval = Aval * Bval;

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
                        typedef typename Fp4T::base_field_type base_field_type;
                        typedef typename Fp4T::underlying_field_type Fp2T;

                        Fp4_variable<Fp4T> A;
                        Fp4_variable<Fp4T> result;

                        std::shared_ptr<Fp2_variable<Fp2T>> v1;

                        blueprint_linear_combination<base_field_type> v0_c0;
                        blueprint_linear_combination<base_field_type> v0_c1;
                        std::shared_ptr<Fp2_variable<Fp2T>> v0;

                        std::shared_ptr<Fp2_sqr_component<Fp2T>> compute_v0;
                        std::shared_ptr<Fp2_sqr_component<Fp2T>> compute_v1;

                        blueprint_linear_combination<base_field_type> Ac0_plus_Ac1_c0;
                        blueprint_linear_combination<base_field_type> Ac0_plus_Ac1_c1;
                        std::shared_ptr<Fp2_variable<Fp2T>> Ac0_plus_Ac1;

                        blueprint_linear_combination<base_field_type> result_c1_plus_v0_plus_v1_c0;
                        blueprint_linear_combination<base_field_type> result_c1_plus_v0_plus_v1_c1;

                        std::shared_ptr<Fp2_variable<Fp2T>> result_c1_plus_v0_plus_v1;

                        std::shared_ptr<Fp2_sqr_component<Fp2T>> compute_result_c1;

                        Fp4_sqr_component(blueprint<base_field_type> &bp,
                                          const Fp4_variable<Fp4T> &A,
                                          const Fp4_variable<Fp4T> &result) :
                            component<base_field_type>(bp),
                            A(A), result(result) {
                            /*
                              Karatsuba squaring for Fp4 as a quadratic extension of Fp2:
                              v0 = A.data[0]^2
                              v1 = A.data[1]^2
                              result.data[0] = v0 + non_residue * v1
                              result.data[1] = (A.data[0] + A.data[1])^2 - v0 - v1
                              where "non_residue * elem" := (non_residue * elt.data[1], elt.data[0])

                              Enforced with 3 Fp2_sqr_component's that ensure that:
                              A.data[1]^2 = v1
                              A.data[0]^2 = v0
                              (A.data[0]+A.data[1])^2 = result.data[1] + v0 + v1

                              Reference:
                              "Multiplication and Squaring on Pairing-Friendly Fields"
                              Devegili, OhEigeartaigh, Scott, Dahab
                            */

                            v1.reset(new Fp2_variable<Fp2T>(bp));
                            compute_v1.reset(new Fp2_sqr_component<Fp2T>(bp, A.data[1], *v1));

                            v0_c0.assign(bp, result.data[0].data[0] - Fp4T::value_type::non_residue * v1->data[1]);

                            v0_c1.assign(bp, result.data[0].data[1] - v1->data[0]);
                            v0.reset(new Fp2_variable<Fp2T>(bp, v0_c0, v0_c1));

                            compute_v0.reset(new Fp2_sqr_component<Fp2T>(bp, A.data[0], *v0));

                            Ac0_plus_Ac1_c0.assign(bp, A.data[0].data[0] + A.data[1].data[0]);
                            Ac0_plus_Ac1_c1.assign(bp, A.data[0].data[1] + A.data[1].data[1]);
                            Ac0_plus_Ac1.reset(new Fp2_variable<Fp2T>(bp, Ac0_plus_Ac1_c0, Ac0_plus_Ac1_c1));

                            result_c1_plus_v0_plus_v1_c0.assign(bp, result.data[1].data[0] + v0->data[0] + v1->data[0]);
                            result_c1_plus_v0_plus_v1_c1.assign(bp, result.data[1].data[1] + v0->data[1] + v1->data[1]);
                            result_c1_plus_v0_plus_v1.reset(
                                new Fp2_variable<Fp2T>(bp, result_c1_plus_v0_plus_v1_c0, result_c1_plus_v0_plus_v1_c1));

                            compute_result_c1.reset(
                                new Fp2_sqr_component<Fp2T>(bp, *Ac0_plus_Ac1, *result_c1_plus_v0_plus_v1));
                        }

                        void generate_r1cs_constraints() {
                            compute_v1->generate_r1cs_constraints();
                            compute_v0->generate_r1cs_constraints();
                            compute_result_c1->generate_r1cs_constraints();
                        }

                        void generate_r1cs_witness() {
                            compute_v1->generate_r1cs_witness();

                            v0_c0.evaluate(this->bp);
                            v0_c1.evaluate(this->bp);
                            compute_v0->generate_r1cs_witness();

                            Ac0_plus_Ac1_c0.evaluate(this->bp);
                            Ac0_plus_Ac1_c1.evaluate(this->bp);
                            compute_result_c1->generate_r1cs_witness();

                            const typename Fp4T::value_type Aval = A.get_element();
                            const typename Fp4T::value_type Rval = Aval.squared();
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
                        typedef typename Fp4T::base_field_type base_field_type;
                        typedef typename Fp4T::underlying_field_type Fp2T;

                        using base_field_value_type = typename base_field_type::value_type;

                        Fp4_variable<Fp4T> A;
                        Fp4_variable<Fp4T> result;

                        blueprint_linear_combination<base_field_type> c0_expr_c0;
                        blueprint_linear_combination<base_field_type> c0_expr_c1;
                        std::shared_ptr<Fp2_variable<Fp2T>> c0_expr;
                        std::shared_ptr<Fp2_sqr_component<Fp2T>> compute_c0_expr;

                        blueprint_linear_combination<base_field_type> A_c0_plus_A_c1_c0;
                        blueprint_linear_combination<base_field_type> A_c0_plus_A_c1_c1;
                        std::shared_ptr<Fp2_variable<Fp2T>> A_c0_plus_A_c1;

                        blueprint_linear_combination<base_field_type> c1_expr_c0;
                        blueprint_linear_combination<base_field_type> c1_expr_c1;
                        std::shared_ptr<Fp2_variable<Fp2T>> c1_expr;
                        std::shared_ptr<Fp2_sqr_component<Fp2T>> compute_c1_expr;

                        Fp4_cyclotomic_sqr_component(blueprint<base_field_type> &bp,
                                                     const Fp4_variable<Fp4T> &A,
                                                     const Fp4_variable<Fp4T> &result) :
                            component<base_field_type>(bp),
                            A(A), result(result) {
                            /*
                              A = elt.data[1] ^ 2
                              B = elt.data[1] + elt.data[0];
                              C = B ^ 2 - A
                              D = Fp2(A.data[1] * non_residue, A.data[0])
                              E = C - D
                              F = D + D + Fp2::one()
                              G = E - Fp2::one()

                              return Fp4(F, G);

                              Enforced with 2 Fp2_sqr_component's that ensure that:

                              elt.data[1] ^ 2 = Fp2(result.data[0].data[1] / 2, (result.data[0].data[0] - 1) / (2 *
                              non_residue)) = A (elt.data[1] + elt.data[0]) ^ 2 = A + result.data[1] + Fp2(A.data[1] *
                              non_residue + 1, A.data[0])

                              (elt.data[1] + elt.data[0]) ^ 2 = Fp2(result.data[0].data[1] / 2 + result.data[1].data[0]
                              + (result.data[0].data[0] - 1) / 2 + 1, (result.data[0].data[0] - 1) / (2 * non_residue) +
                              result.data[1].data[1] + result.data[0].data[1] / 2)
                            */
                            c0_expr_c0.assign(bp, result.data[0].data[1] * base_field_value_type(0x02).inversed());
                            c0_expr_c1.assign(
                                bp,
                                (result.data[0].data[0] - base_field_value_type(0x01)) *
                                    (base_field_value_type(0x02) * Fp4T::value_type::non_residue).inversed());

                            c0_expr.reset(new Fp2_variable<Fp2T>(bp, c0_expr_c0, c0_expr_c1));
                            compute_c0_expr.reset(new Fp2_sqr_component<Fp2T>(bp, A.data[1], *c0_expr));

                            A_c0_plus_A_c1_c0.assign(bp, A.data[0].data[0] + A.data[1].data[0]);
                            A_c0_plus_A_c1_c1.assign(bp, A.data[0].data[1] + A.data[1].data[1]);
                            A_c0_plus_A_c1.reset(new Fp2_variable<Fp2T>(bp, A_c0_plus_A_c1_c0, A_c0_plus_A_c1_c1));

                            c1_expr_c0.assign(
                                bp,
                                (result.data[0].data[1] + result.data[0].data[0] - base_field_value_type(0x01)) *
                                        base_field_value_type(0x02).inversed() +
                                    result.data[1].data[0] + base_field_value_type(0x01));
                            c1_expr_c1.assign(
                                bp,
                                (result.data[0].data[0] - base_field_value_type(0x01)) *
                                        (base_field_value_type(0x02) * Fp4T::value_type::non_residue).inversed() +
                                    result.data[1].data[1] +
                                    result.data[0].data[1] * base_field_value_type(0x02).inversed());

                            c1_expr.reset(new Fp2_variable<Fp2T>(bp, c1_expr_c0, c1_expr_c1));

                            compute_c1_expr.reset(new Fp2_sqr_component<Fp2T>(bp, *A_c0_plus_A_c1, *c1_expr));
                        }

                        void generate_r1cs_constraints() {
                            compute_c0_expr->generate_r1cs_constraints();
                            compute_c1_expr->generate_r1cs_constraints();
                        }

                        void generate_r1cs_witness() {
                            compute_c0_expr->generate_r1cs_witness();

                            A_c0_plus_A_c1_c0.evaluate(this->bp);
                            A_c0_plus_A_c1_c1.evaluate(this->bp);
                            compute_c1_expr->generate_r1cs_witness();

                            const typename Fp4T::value_type Aval = A.get_element();
                            const typename Fp4T::value_type Rval = Aval.squared();
                            result.generate_r1cs_witness(Rval);
                        }
                    };

                }    // namespace components
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_FP4_COMPONENTS_HPP
