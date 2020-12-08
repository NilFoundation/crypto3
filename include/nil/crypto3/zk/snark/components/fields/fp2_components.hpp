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
// @file Declaration of interfaces for Fp2 components.
//
// The components verify field arithmetic in Fp2 = Fp[U]/(U^2-non_residue),
// where non_residue is in Fp.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_FP2_COMPONENTS_HPP
#define CRYPTO3_ZK_FP2_COMPONENTS_HPP

#include <memory>

#include <nil/crypto3/zk/snark/component.hpp>

#include <nil/crypto3/zk/snark/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace components {

                    /******************************** Fp2_variable ************************************/

                    /**
                     * Component that represents an Fp2 variable.
                     */
                    template<typename Fp2T>
                    struct Fp2_variable : public component<typename Fp2T::underlying_field_type> {
                        using base_field_type = typename Fp2T::base_field_type;
                        using base_field_value_type = typename base_field_type::value_type;

                        using underlying_type = blueprint_linear_combination<base_field_type>;

                        using data_type = std::array<underlying_type, Fp2T::arity/Fp2T::underlying_field_type::arity>;

                        data_type data;

                        blueprint_linear_combination_vector<base_field_type> all_vars;

                        Fp2_variable(blueprint<base_field_type> &bp) : component<base_field_type>(bp) {
                            blueprint_variable<base_field_type> c0_var, c1_var;

                            c0_var.allocate(bp);
                            c1_var.allocate(bp);

                            //c0 = blueprint_linear_combination<base_field_type>(c0_var);
                            //c1 = blueprint_linear_combination<base_field_type>(c1_var);

                            data = data_type({underlying_type(c0_var), underlying_type(c1_var)});

                            all_vars.emplace_back(data[0]);
                            all_vars.emplace_back(data[1]);
                        }

                        Fp2_variable(blueprint<base_field_type> &bp, const typename Fp2T::value_type &el) : 
                            component<base_field_type>(bp) {
                            blueprint_linear_combination<base_field_type> c0_lc;
                            blueprint_linear_combination<base_field_type> c1_lc;

                            c0_lc.assign(bp, el.data[0]);
                            c1_lc.assign(bp, el.data[1]);

                            c0_lc.evaluate(bp);
                            c1_lc.evaluate(bp);

                            data = data_type({underlying_type(c0_lc), underlying_type(c1_lc)});

                            all_vars.emplace_back(data[0]);
                            all_vars.emplace_back(data[1]);
                        }

                        Fp2_variable(blueprint<base_field_type> &bp,
                                     const typename Fp2T::value_type &el,
                                     const blueprint_linear_combination<base_field_type> &coeff) :
                            component<base_field_type>(bp) {

                            blueprint_linear_combination<base_field_type> c0_lc;
                            blueprint_linear_combination<base_field_type> c1_lc;

                            c0_lc.assign(bp, el.data[0] * coeff);
                            c1_lc.assign(bp, el.data[1] * coeff);

                            data = data_type({underlying_type(c0_lc), underlying_type(c1_lc)});

                            all_vars.emplace_back(data[0]);
                            all_vars.emplace_back(data[1]);
                        }

                        Fp2_variable(blueprint<base_field_type> &bp,
                                     const blueprint_linear_combination<base_field_type> &c0_lc,
                                     const blueprint_linear_combination<base_field_type> &c1_lc) :
                            component<base_field_type>(bp){

                            data = data_type({underlying_type(c0_lc), underlying_type(c1_lc)});

                            all_vars.emplace_back(data[0]);
                            all_vars.emplace_back(data[1]);
                        }

                        void generate_r1cs_equals_const_constraints(const typename Fp2T::value_type &el) {
                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(1, el.data[0], data[0]));
                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(1, el.data[1], data[1]));
                        }

                        void generate_r1cs_witness(const typename Fp2T::value_type &el) {
                            this->bp.lc_val(data[0]) = el.data[0];
                            this->bp.lc_val(data[1]) = el.data[1];
                        }

                        typename Fp2T::value_type get_element() {
                            typename Fp2T::value_type el;
                            el.data[0] = this->bp.lc_val(data[0]);
                            el.data[1] = this->bp.lc_val(data[1]);
                            return el;
                        }

                        Fp2_variable operator*(const base_field_value_type &coeff) const {
                            blueprint_linear_combination<base_field_type> new_c0, new_c1;
                            new_c0.assign(this->bp, this->data[0] * coeff);
                            new_c1.assign(this->bp, this->data[1] * coeff);
                            return Fp2_variable<Fp2T>(this->bp, new_c0, new_c1);
                        }

                        Fp2_variable operator+(const Fp2_variable &other) const {
                            blueprint_linear_combination<base_field_type> new_c0, new_c1;
                            new_c0.assign(this->bp, this->data[0] + other.data[0]);
                            new_c1.assign(this->bp, this->data[1] + other.data[1]);
                            return Fp2_variable<Fp2T>(this->bp, new_c0, new_c1);
                        }

                        Fp2_variable operator+(const typename Fp2T::value_type &other) const {
                            blueprint_linear_combination<base_field_type> new_c0, new_c1;
                            new_c0.assign(this->bp, this->data[0] + other.data[0]);
                            new_c1.assign(this->bp, this->data[1] + other.data[1]);
                            return Fp2_variable<Fp2T>(this->bp, new_c0, new_c1);
                        }

                        Fp2_variable mul_by_X() const {
                            blueprint_linear_combination<base_field_type> new_c0, new_c1;
                            new_c0.assign(this->bp, this->data[1] * Fp2T::value_type::one().non_residue);
                            // while constepr is not ready
                            // must be:
                            //new_c0.assign(this->bp, this->data[1] * Fp2T::value_type::non_residue);

                            new_c1.assign(this->bp, this->data[0]);
                            return Fp2_variable<Fp2T>(this->bp, new_c0, new_c1);
                        }

                        void evaluate() const {
                            (this->data[0]).evaluate(this->bp);
                            (this->data[1]).evaluate(this->bp);
                        }

                        bool is_constant() const {
                            return ((this->data[0]).is_constant() && (this->data[1]).is_constant());
                        }

                        static std::size_t size_in_bits() {
                            return 2 * base_field_type::value_bits;
                        }

                        static std::size_t num_variables() {
                            return 2;
                        }
                    };

                    /******************************** Fp2_mul_component ************************************/

                    /**
                     * Component that creates constraints for Fp2 by Fp2 multiplication.
                     */
                    template<typename Fp2T>
                    struct Fp2_mul_component : public component<typename Fp2T::underlying_field_type> {
                        using base_field_type = typename Fp2T::underlying_field_type;
                        using base_field_value_type = typename base_field_type::value_type;

                        Fp2_variable<Fp2T> A;
                        Fp2_variable<Fp2T> B;
                        Fp2_variable<Fp2T> result;

                        blueprint_variable<base_field_type> v1;

                        Fp2_mul_component(blueprint<base_field_type> &bp,
                                          const Fp2_variable<Fp2T> &A,
                                          const Fp2_variable<Fp2T> &B,
                                          const Fp2_variable<Fp2T> &result) :
                            component<base_field_type>(bp),
                            A(A), B(B), result(result) {
                            v1.allocate(bp);
                        }

                        void generate_r1cs_constraints() {
                            /*
                                Karatsuba multiplication for Fp2:
                                    v0 = A.data[0] * B.data[0]
                                    v1 = A.data[1] * B.data[1]
                                    result.data[0] = v0 + non_residue * v1
                                    result.data[1] = (A.data[0] + A.data[1]) * (B.data[0] + B.data[1]) - v0 - v1

                                Enforced with 3 constraints:
                                    A.data[1] * B.data[1] = v1
                                    A.data[0] * B.data[0] = result.data[0] - non_residue * v1
                                    (A.data[0]+A.data[1])*(B.data[0]+B.data[1]) = result.data[1] + result.data[0] + (1 - non_residue) * v1

                                Reference:
                                    "Multiplication and Squaring on Pairing-Friendly Fields"
                                    Devegili, OhEigeartaigh, Scott, Dahab
                            */
                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(A.data[1], B.data[1], v1));
                            this->bp.add_r1cs_constraint(
                                r1cs_constraint<base_field_type>(A.data[0], B.data[0], result.data[0] + v1 * (-Fp2T::value_type::one().non_residue)));
                            // while constepr is not ready
                            // must be:
                            //this->bp.add_r1cs_constraint(
                            //    r1cs_constraint<base_field_type>(A.data[0], B.data[0], result.data[0] + v1 * (-Fp2T::value_type::non_residue)));

                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(
                                A.data[0] + A.data[1],
                                B.data[0] + B.data[1],
                                result.data[1] + result.data[0] + v1 * (base_field_value_type::one() - Fp2T::value_type::one().non_residue)));
                            // while constepr is not ready
                            // must be:
                            //this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(
                            //    A.data[0] + A.data[1],
                            //    B.data[0] + B.data[1],
                            //    result.data[1] + result.data[0] + v1 * (base_field_value_type::one() - Fp2T::value_type::non_residue)));
                        }

                        void generate_r1cs_witness() {
                            const base_field_value_type aA = this->bp.lc_val(A.data[0]) * this->bp.lc_val(B.data[0]);
                            this->bp.val(v1) = this->bp.lc_val(A.data[1]) * this->bp.lc_val(B.data[1]);
                            this->bp.lc_val(result.data[0]) = aA + Fp2T::value_type::one().non_residue * this->bp.val(v1);
                            // while constepr is not ready
                            // must be:
                            //this->bp.lc_val(result.data[0]) = aA + Fp2T::value_type::non_residue * this->bp.val(v1);

                            this->bp.lc_val(result.data[1]) = (this->bp.lc_val(A.data[0]) + this->bp.lc_val(A.data[1])) *
                                                             (this->bp.lc_val(B.data[0]) + this->bp.lc_val(B.data[1])) -
                                                         aA - this->bp.lc_val(v1);
                        }
                    };

                    /******************************** Fp2_mul_by_lc_component ************************************/

                    /**
                     * Component that creates constraints for Fp2 multiplication by a linear combination.
                     */
                    template<typename Fp2T>
                    struct Fp2_mul_by_lc_component : public component<typename Fp2T::underlying_field_type> {
                        using base_field_type = typename Fp2T::underlying_field_type;

                        Fp2_variable<Fp2T> A;
                        blueprint_linear_combination<base_field_type> lc;
                        Fp2_variable<Fp2T> result;

                        Fp2_mul_by_lc_component(blueprint<base_field_type> &bp,
                                                const Fp2_variable<Fp2T> &A,
                                                const blueprint_linear_combination<base_field_type> &lc,
                                                const Fp2_variable<Fp2T> &result) :
                            component<base_field_type>(bp),
                            A(A), lc(lc), result(result) {
                        }

                        void generate_r1cs_constraints() {
                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(A.data[0], lc, result.data[0]));
                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(A.data[1], lc, result.data[1]));
                        }

                        void generate_r1cs_witness() {
                            this->bp.lc_val(result.data[0]) = this->bp.lc_val(A.data[0]) * this->bp.lc_val(lc);
                            this->bp.lc_val(result.data[1]) = this->bp.lc_val(A.data[1]) * this->bp.lc_val(lc);
                        }
                    };

                    /******************************** Fp2_sqr_component ************************************/

                    /**
                     * Component that creates constraints for Fp2 squaring.
                     */
                    template<typename Fp2T>
                    struct Fp2_sqr_component : public component<typename Fp2T::underlying_field_type> {
                        using base_field_type = typename Fp2T::base_field_type;

                        Fp2_variable<Fp2T> A;
                        Fp2_variable<Fp2T> result;

                        using base_field_value_type = typename base_field_type::value_type;

                        Fp2_sqr_component(blueprint<base_field_type> &bp,
                                          const Fp2_variable<Fp2T> &A,
                                          const Fp2_variable<Fp2T> &result) :
                            component<base_field_type>(bp),
                            A(A), result(result) {
                        }

                        void generate_r1cs_constraints() {
                            /*
                                Complex multiplication for Fp2:
                                    v0 = A.data[0] * A.data[1]
                                    result.data[0] = (A.data[0] + A.data[1]) * (A.data[0] + non_residue * A.data[1]) - (1 + non_residue) * v0
                                    result.data[1] = 2 * v0

                                Enforced with 2 constraints:
                                    (2*A.data[0]) * A.data[1] = result.data[1]
                                    (A.data[0] + A.data[1]) * (A.data[0] + non_residue * A.data[1]) = result.data[0] + result.data[1] * (1 +
                               non_residue)/2

                                Reference:
                                    "Multiplication and Squaring on Pairing-Friendly Fields"
                                    Devegili, OhEigeartaigh, Scott, Dahab
                            */
                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(2 * A.data[0], A.data[1], result.data[1]));
                            this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(
                                A.data[0] + A.data[1],
                                A.data[0] + Fp2T::value_type::one().non_residue * A.data[1],
                                result.data[0] + result.data[1] * (base_field_value_type::one() + Fp2T::value_type::one().non_residue) *
                                                base_field_value_type(0x02).inversed()));
                            // while constepr is not ready
                            // must be:
                            //this->bp.add_r1cs_constraint(r1cs_constraint<base_field_type>(
                            //    A.data[0] + A.data[1],
                            //    A.data[0] + Fp2T::value_type::non_residue * A.data[1],
                            //    result.data[0] + result.data[1] * (base_field_value_type::one() + Fp2T::value_type::non_residue) *
                            //                    base_field_value_type(0x02).inversed()));

                        }

                        void generate_r1cs_witness() {
                            const base_field_value_type a = this->bp.lc_val(A.data[0]);
                            const base_field_value_type b = this->bp.lc_val(A.data[1]);
                            this->bp.lc_val(result.data[1]) = base_field_value_type(0x02) * a * b;
                            this->bp.lc_val(result.data[0]) =
                                (a + b) * (a + Fp2T::value_type::one().non_residue * b) - a * b - Fp2T::value_type::one().non_residue * a * b;
                            // while constepr is not ready
                            // must be:
                            //this->bp.lc_val(result.data[0]) =
                            //    (a + b) * (a + Fp2T::value_type::non_residue * b) - a * b - Fp2T::value_type::non_residue * a * b;
                        }
                    };

                }    // namespace components
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_FP2_COMPONENTS_HPP
