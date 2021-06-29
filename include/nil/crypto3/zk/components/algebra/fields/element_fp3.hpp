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
// @file Declaration of interfaces for Fp3 components.
//
// The components verify field arithmetic in Fp3 = Fp[U]/(U^3-non_residue),
// where non_residue is in Fp.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_FP3_COMPONENTS_HPP
#define CRYPTO3_ZK_BLUEPRINT_FP3_COMPONENTS_HPP

#include <memory>

#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/algebra/fields/element_fp.hpp>

#include <nil/crypto3/zk/components/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                /******************************** element_fp3 ************************************/

                /**
                 * Component that represents an Fp3 element.
                 */
                template<typename Fp3T>
                struct element_fp3 : public component<typename Fp3T::underlying_field_type> {

                    using field_type = Fp3T;
                    using base_field_type = typename field_type::base_field_type;
                    using underlying_field_type = typename field_type::underlying_field_type;

                    using underlying_element_type = element_fp<underlying_field_type>;

                    using base_field_value_type = typename base_field_type::value_type;

                    using data_type =
                        std::array<underlying_element_type, field_type::arity / underlying_field_type::arity>;

                    data_type data;

                    blueprint_linear_combination_vector<base_field_type> all_vars;

                    element_fp3(blueprint<base_field_type> &bp) : component<base_field_type>(bp) {
                        blueprint_variable<base_field_type> c0_var, c1_var, c2_var;

                        c0_var.allocate(bp);
                        c1_var.allocate(bp);
                        c2_var.allocate(bp);

                        data = data_type({underlying_element_type(c0_var), underlying_element_type(c1_var),
                                          underlying_element_type(c2_var)});

                        all_vars.emplace_back(data[0]);
                        all_vars.emplace_back(data[1]);
                        all_vars.emplace_back(data[2]);
                    }

                    element_fp3(blueprint<base_field_type> &bp, const typename Fp3T::value_type &el) :
                        component<base_field_type>(bp) {
                        underlying_element_type c0_lc;
                        underlying_element_type c1_lc;
                        underlying_element_type c2_lc;

                        c0_lc.assign(bp, el.data[0]);
                        c1_lc.assign(bp, el.data[1]);
                        c2_lc.assign(bp, el.data[2]);

                        c0_lc.evaluate(bp);
                        c1_lc.evaluate(bp);
                        c2_lc.evaluate(bp);

                        data = data_type({underlying_element_type(c0_lc), underlying_element_type(c1_lc),
                                          underlying_element_type(c2_lc)});

                        all_vars.emplace_back(data[0]);
                        all_vars.emplace_back(data[1]);
                        all_vars.emplace_back(data[2]);
                    }

                    element_fp3(blueprint<base_field_type> &bp,
                                const typename Fp3T::value_type &el,
                                const blueprint_linear_combination<base_field_type> &coeff) :
                        component<base_field_type>(bp) {

                        underlying_element_type c0_lc;
                        underlying_element_type c1_lc;
                        underlying_element_type c2_lc;

                        c0_lc.assign(bp, el.data[0] * coeff);
                        c1_lc.assign(bp, el.data[1] * coeff);
                        c2_lc.assign(bp, el.data[2] * coeff);

                        data = data_type({underlying_element_type(c0_lc), underlying_element_type(c1_lc),
                                          underlying_element_type(c2_lc)});

                        all_vars.emplace_back(data[0]);
                        all_vars.emplace_back(data[1]);
                        all_vars.emplace_back(data[2]);
                    }

                    element_fp3(blueprint<base_field_type> &bp,
                                const underlying_element_type &c0_lc,
                                const underlying_element_type &c1_lc,
                                const underlying_element_type &c2_lc) :
                        component<base_field_type>(bp) {

                        data = data_type({underlying_element_type(c0_lc), underlying_element_type(c1_lc),
                                          underlying_element_type(c2_lc)});

                        all_vars.emplace_back(data[0]);
                        all_vars.emplace_back(data[1]);
                        all_vars.emplace_back(data[2]);
                    }

                    void generate_r1cs_equals_const_constraints(const typename Fp3T::value_type &el) {
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<base_field_type>(1, el.data[0], data[0]));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<base_field_type>(1, el.data[1], data[1]));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<base_field_type>(1, el.data[2], data[2]));
                    }

                    void generate_r1cs_witness(const typename Fp3T::value_type &el) {
                        this->bp.lc_val(data[0]) = el.data[0];
                        this->bp.lc_val(data[1]) = el.data[1];
                        this->bp.lc_val(data[2]) = el.data[2];
                    }

                    typename Fp3T::value_type get_element() {
                        typename Fp3T::value_type el;
                        el.data[0] = this->bp.lc_val(data[0]);
                        el.data[1] = this->bp.lc_val(data[1]);
                        el.data[2] = this->bp.lc_val(data[2]);
                        return el;
                    }

                    element_fp3<Fp3T> operator*(const typename base_field_type::value_type &coeff) const {
                        underlying_element_type new_c0, new_c1, new_c2;
                        new_c0.assign(this->bp, this->data[0] * coeff);
                        new_c1.assign(this->bp, this->data[1] * coeff);
                        new_c2.assign(this->bp, this->data[2] * coeff);
                        return element_fp3<Fp3T>(this->bp, new_c0, new_c1, new_c2);
                    }

                    element_fp3<Fp3T> operator+(const element_fp3<Fp3T> &other) const {
                        underlying_element_type new_c0, new_c1, new_c2;
                        new_c0.assign(this->bp, this->data[0] + other.data[0]);
                        new_c1.assign(this->bp, this->data[1] + other.data[1]);
                        new_c2.assign(this->bp, this->data[2] + other.data[2]);
                        return element_fp3<Fp3T>(this->bp, new_c0, new_c1, new_c2);
                    }

                    element_fp3<Fp3T> operator+(const typename Fp3T::value_type &other) const {
                        underlying_element_type new_c0, new_c1, new_c2;
                        new_c0.assign(this->bp, this->data[0] + other.data[0]);
                        new_c1.assign(this->bp, this->data[1] + other.data[1]);
                        new_c2.assign(this->bp, this->data[2] + other.data[2]);
                        return element_fp3<Fp3T>(this->bp, new_c0, new_c1, new_c2);
                    }

                    element_fp3<Fp3T> mul_by_X() const {
                        underlying_element_type new_c0, new_c1, new_c2;
                        new_c0.assign(this->bp, this->data[2] * Fp3T::value_type::non_residue);

                        new_c1.assign(this->bp, this->data[0]);
                        new_c2.assign(this->bp, this->data[1]);
                        return element_fp3<Fp3T>(this->bp, new_c0, new_c1, new_c2);
                    }

                    void evaluate() const {
                        data[0].evaluate(this->bp);
                        data[1].evaluate(this->bp);
                        data[2].evaluate(this->bp);
                    }

                    bool is_constant() const {
                        return (data[0].is_constant() && data[1].is_constant() && data[2].is_constant());
                    }

                    static std::size_t size_in_bits() {
                        return 3 * base_field_type::value_bits;
                    }

                    static std::size_t num_variables() {
                        return 3;
                    }
                };

                /******************************** element_fp3_mul ************************************/

                /**
                 * Component that creates constraints for Fp3 by Fp3 multiplication.
                 */
                template<typename Fp3T>
                struct element_fp3_mul : public component<typename Fp3T::base_field_type> {
                    using base_field_type = typename Fp3T::base_field_type;

                    element_fp3<Fp3T> A;
                    element_fp3<Fp3T> B;
                    element_fp3<Fp3T> result;

                    blueprint_variable<base_field_type> v0;
                    blueprint_variable<base_field_type> v4;

                    element_fp3_mul(blueprint<base_field_type> &bp,
                                    const element_fp3<Fp3T> &A,
                                    const element_fp3<Fp3T> &B,
                                    const element_fp3<Fp3T> &result) :
                        component<base_field_type>(bp),
                        A(A), B(B), result(result) {
                        v0.allocate(bp);
                        v4.allocate(bp);
                    }

                    void generate_r1cs_constraints() {
                        /*
                            Tom-Cook-3x for Fp3:
                                v0 = A.data[0] * B.data[0]
                                v1 = (A.data[0] + A.data[1] + A.data[2]) * (B.data[0] + B.data[1] + B.data[2])
                                v2 = (A.data[0] - A.data[1] + A.data[2]) * (B.data[0] - B.data[1] + B.data[2])
                                v3 = (A.data[0] + 2*A.data[1] + 4*A.data[2]) * (B.data[0] + 2*B.data[1] +
                           4*B.data[2]) v4 = A.data[2] * B.data[2] result.data[0] = v0 + non_residue * (v0/2 - v1/2
                           - v2/6 + v3/6 - 2*v4) result.data[1] = -(1/2) v0 +  v1 - (1/3) v2 - (1/6) v3 + 2 v4 +
                           non_residue*v4 result.data[2] = -v0 + (1/2) v1 + (1/2) v2 - v4

                            Enforced with 5 constraints. Doing so requires some care, as we first
                            compute two of the v_i explicitly, and then "inline" result.data[1]/data[2]/c3
                            in computations of teh remaining three v_i.

                            Concretely, we first compute v0 and v4 explicitly, via 2 constraints:
                                A.data[0] * B.data[0] = v0
                                A.data[2] * B.data[2] = v4
                            Then we use the following 3 additional constraints:
                                v1 = result.data[1] + result.data[2] + (result.data[0] - v0)/non_residue + v0 + v4 -
                           non_residue v4 v2 = -result.data[1] + result.data[2] + v0 + (-result.data[0] +
                           v0)/non_residue + v4 + non_residue v4 v3 = 2 * result.data[1] + 4 result.data[2] +
                           (8*(result.data[0] - v0))/non_residue + v0 + 16 * v4 - 2 * non_residue * v4

                            Reference:
                                "Multiplication and Squaring on Pairing-Friendly Fields"
                                Devegili, OhEigeartaigh, Scott, Dahab

                            NOTE: the expressions above were cherry-picked from the Mathematica result
                            of the following command:

                            (# -> Solve[{data[0] == v0 + non_residue*(v0/2 - v1/2 - v2/6 + v3/6 - 2 v4),
                                        data[1] == -(1/2) v0 + v1 - (1/3) v2 - (1/6) v3 + 2 v4 + non_residue*v4,
                                        data[2] == -v0 + (1/2) v1 + (1/2) v2 - v4}, #] // FullSimplify) & /@
                            Subsets[{v0, v1, v2, v3, v4}, {3}]
                        */
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<base_field_type>(A.data[0], B.data[0], v0));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<base_field_type>(A.data[2], B.data[2], v4));

                        const typename base_field_type::value_type beta = Fp3T::value_type::non_residue;

                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<base_field_type>(
                            A.data[0] + A.data[1] + A.data[2],
                            B.data[0] + B.data[1] + B.data[2],
                            result.data[1] + result.data[2] + result.data[0] * beta.inversed() +
                                v0 * (typename base_field_type::value_type(1) - beta.inversed()) +
                                v4 * (typename base_field_type::value_type(1) - beta)));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<base_field_type>(
                            A.data[0] - A.data[1] + A.data[2],
                            B.data[0] - B.data[1] + B.data[2],
                            -result.data[1] + result.data[2] +
                                v0 * (typename base_field_type::value_type(1) + beta.inversed()) -
                                result.data[0] * beta.inversed() +
                                v4 * (typename base_field_type::value_type(1) + beta)));
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<base_field_type>(
                            A.data[0] + 2 * A.data[1] + 4 * A.data[2],
                            B.data[0] + 2 * B.data[1] + 4 * B.data[2],
                            2 * result.data[1] + 4 * result.data[2] +
                                result.data[0] * (typename base_field_type::value_type(8) * beta.inversed()) +
                                v0 * (typename base_field_type::value_type(1) -
                                      typename base_field_type::value_type(8) * beta.inversed()) +
                                v4 * (typename base_field_type::value_type(16) -
                                      typename base_field_type::value_type(2) * beta)));
                    }

                    void generate_r1cs_witness() {
                        this->bp.val(v0) = this->bp.lc_val(A.data[0]) * this->bp.lc_val(B.data[0]);
                        this->bp.val(v4) = this->bp.lc_val(A.data[2]) * this->bp.lc_val(B.data[2]);

                        const typename Fp3T::value_type Aval = A.get_element();
                        const typename Fp3T::value_type Bval = B.get_element();
                        const typename Fp3T::value_type Rval = Aval * Bval;
                        result.generate_r1cs_witness(Rval);
                    }
                };

                /******************************** element_fp3_mul_by_lc ************************************/

                /**
                 * Component that creates constraints for Fp3 multiplication by a linear combination.
                 */
                template<typename Fp3T>
                struct element_fp3_mul_by_lc : public component<typename Fp3T::underlying_field_type> {
                    using base_field_type = typename Fp3T::underlying_field_type;

                    element_fp3<Fp3T> A;
                    blueprint_linear_combination<base_field_type> lc;
                    element_fp3<Fp3T> result;

                    element_fp3_mul_by_lc(blueprint<base_field_type> &bp,
                                          const element_fp3<Fp3T> &A,
                                          const blueprint_linear_combination<base_field_type> &lc,
                                          const element_fp3<Fp3T> &result) :
                        component<base_field_type>(bp),
                        A(A), lc(lc), result(result) {
                    }

                    void generate_r1cs_constraints() {
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<base_field_type>(A.data[0], lc, result.data[0]));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<base_field_type>(A.data[1], lc, result.data[1]));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<base_field_type>(A.data[2], lc, result.data[2]));
                    }

                    void generate_r1cs_witness() {
                        this->bp.lc_val(result.data[0]) = this->bp.lc_val(A.data[0]) * this->bp.lc_val(lc);
                        this->bp.lc_val(result.data[1]) = this->bp.lc_val(A.data[1]) * this->bp.lc_val(lc);
                        this->bp.lc_val(result.data[2]) = this->bp.lc_val(A.data[2]) * this->bp.lc_val(lc);
                    }
                };

                /******************************** element_fp3_squared ************************************/

                /**
                 * Component that creates constraints for Fp3 squaring.
                 */
                template<typename Fp3T>
                struct element_fp3_squared : public component<typename Fp3T::underlying_field_type> {
                    using base_field_type = typename Fp3T::underlying_field_type;

                    element_fp3<Fp3T> A;
                    element_fp3<Fp3T> result;

                    std::shared_ptr<element_fp3_mul<Fp3T>> mul;

                    element_fp3_squared(blueprint<base_field_type> &bp,
                                        const element_fp3<Fp3T> &A,
                                        const element_fp3<Fp3T> &result) :
                        component<base_field_type>(bp),
                        A(A), result(result) {
                        mul.reset(new element_fp3_mul<Fp3T>(bp, A, A, result));
                    }

                    void generate_r1cs_constraints() {
                        mul->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        mul->generate_r1cs_witness();
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_FP3_COMPONENTS_HPP
