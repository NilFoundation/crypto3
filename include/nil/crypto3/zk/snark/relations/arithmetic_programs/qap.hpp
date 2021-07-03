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
// @file Declaration of interfaces for a QAP ("Quadratic Arithmetic Program").
//
// QAPs are defined in \[GGPR13].
//
// References:
//
// \[GGPR13]:
// "Quadratic span programs and succinct NIZKs without PCPs",
// Rosario Gennaro, Craig Gentry, Bryan Parno, Mariana Raykova,
// EUROCRYPT 2013,
// <http://eprint.iacr.org/2012/215>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_QAP_HPP
#define CRYPTO3_ZK_QAP_HPP

#include <map>
#include <memory>
#include <vector>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/multiexp/inner_product.hpp>

#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
#include <nil/crypto3/fft/make_evaluation_domain.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using namespace nil::crypto3::fft;

                template<typename FieldType>
                struct qap_witness;

                template<typename FieldType>
                struct qap_instance_evaluation;

                /*************************  INSTATNCE  ***********************************/

                /**
                 * A QAP instance.
                 *
                 * Specifically, the datastructure stores:
                 * - a choice of domain (corresponding to a certain subset of the field);
                 * - the number of variables, the degree, and the number of inputs; and
                 * - coefficients of the A,B,C polynomials in the Lagrange basis.
                 *
                 * There is no need to store the Z polynomial because it is uniquely
                 * determined by the domain (as Z is its vanishing polynomial).
                 */
                template<typename FieldType>
                class qap_instance {
                    using field_type = FieldType;
                    using field_value_type = typename field_type::value_type;

                public:
                    std::size_t num_variables;
                    std::size_t degree;
                    std::size_t num_inputs;

                    std::shared_ptr<evaluation_domain<field_type>> domain;

                    std::vector<std::map<std::size_t, field_value_type>> A_in_Lagrange_basis;
                    std::vector<std::map<std::size_t, field_value_type>> B_in_Lagrange_basis;
                    std::vector<std::map<std::size_t, field_value_type>> C_in_Lagrange_basis;

                    qap_instance(const std::shared_ptr<evaluation_domain<field_type>> &domain,
                                 const std::size_t num_variables,
                                 const std::size_t degree,
                                 const std::size_t num_inputs,
                                 const std::vector<std::map<std::size_t, field_value_type>> &A_in_Lagrange_basis,
                                 const std::vector<std::map<std::size_t, field_value_type>> &B_in_Lagrange_basis,
                                 const std::vector<std::map<std::size_t, field_value_type>> &C_in_Lagrange_basis) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain),
                        A_in_Lagrange_basis(A_in_Lagrange_basis), B_in_Lagrange_basis(B_in_Lagrange_basis),
                        C_in_Lagrange_basis(C_in_Lagrange_basis) {
                    }

                    qap_instance(const std::shared_ptr<evaluation_domain<field_type>> &domain,
                                 const std::size_t num_variables,
                                 const std::size_t degree,
                                 const std::size_t num_inputs,
                                 std::vector<std::map<std::size_t, field_value_type>> &&A_in_Lagrange_basis,
                                 std::vector<std::map<std::size_t, field_value_type>> &&B_in_Lagrange_basis,
                                 std::vector<std::map<std::size_t, field_value_type>> &&C_in_Lagrange_basis) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain),
                        A_in_Lagrange_basis(std::move(A_in_Lagrange_basis)),
                        B_in_Lagrange_basis(std::move(B_in_Lagrange_basis)),
                        C_in_Lagrange_basis(std::move(C_in_Lagrange_basis)) {
                    }

                    qap_instance(const qap_instance<field_type> &other) = default;
                    qap_instance(qap_instance<field_type> &&other) = default;
                    qap_instance &operator=(const qap_instance<field_type> &other) = default;
                    qap_instance &operator=(qap_instance<field_type> &&other) = default;

                    bool is_satisfied(const qap_witness<field_type> &witness) const {
                        const field_value_type t = algebra::random_element<field_type>();

                        std::vector<field_value_type> At(this->num_variables + 1, field_value_type::zero());
                        std::vector<field_value_type> Bt(this->num_variables + 1, field_value_type::zero());
                        std::vector<field_value_type> Ct(this->num_variables + 1, field_value_type::zero());
                        std::vector<field_value_type> Ht(this->degree + 1);

                        const field_value_type Zt = this->domain->compute_vanishing_polynomial(t);

                        const std::vector<field_value_type> u = this->domain->evaluate_all_lagrange_polynomials(t);

                        for (size_t i = 0; i < this->num_variables + 1; ++i) {
                            for (auto &el : A_in_Lagrange_basis[i]) {
                                At[i] += u[el.first] * el.second;
                            }

                            for (auto &el : B_in_Lagrange_basis[i]) {
                                Bt[i] += u[el.first] * el.second;
                            }

                            for (auto &el : C_in_Lagrange_basis[i]) {
                                Ct[i] += u[el.first] * el.second;
                            }
                        }

                        field_value_type ti = field_value_type::one();
                        for (size_t i = 0; i < this->degree + 1; ++i) {
                            Ht[i] = ti;
                            ti *= t;
                        }

                        const qap_instance_evaluation<field_type> eval_qap_inst(this->domain,
                                                                                this->num_variables,
                                                                                this->degree,
                                                                                this->num_inputs,
                                                                                t,
                                                                                std::move(At),
                                                                                std::move(Bt),
                                                                                std::move(Ct),
                                                                                std::move(Ht),
                                                                                Zt);
                        return eval_qap_inst.is_satisfied(witness);
                    }
                };

                /*************************  INSTATNCE  EVALUATION ***********************************/

                /**
                 * A QAP instance evaluation is a QAP instance that is evaluated at a field element t.
                 *
                 * Specifically, the datastructure stores:
                 * - a choice of domain (corresponding to a certain subset of the field);
                 * - the number of variables, the degree, and the number of inputs;
                 * - a field element t;
                 * - evaluations of the A,B,C (and Z) polynomials at t;
                 * - evaluations of all monomials of t;
                 * - counts about how many of the above evaluations are in fact non-zero.
                 */
                template<typename FieldType>
                class qap_instance_evaluation {
                    using field_type = FieldType;
                    using field_value_type = typename field_type::value_type;

                public:
                    std::size_t num_variables;
                    std::size_t degree;
                    std::size_t num_inputs;

                    std::shared_ptr<evaluation_domain<field_type>> domain;

                    field_value_type t;

                    std::vector<field_value_type> At, Bt, Ct, Ht;

                    field_value_type Zt;

                    qap_instance_evaluation(const std::shared_ptr<evaluation_domain<field_type>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const field_value_type &t,
                                            const std::vector<field_value_type> &At,
                                            const std::vector<field_value_type> &Bt,
                                            const std::vector<field_value_type> &Ct,
                                            const std::vector<field_value_type> &Ht,
                                            const field_value_type &Zt) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain), t(t), At(At), Bt(Bt), Ct(Ct), Ht(Ht),
                        Zt(Zt) {
                    }

                    qap_instance_evaluation(const std::shared_ptr<evaluation_domain<field_type>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const field_value_type &t,
                                            std::vector<field_value_type> &&At,
                                            std::vector<field_value_type> &&Bt,
                                            std::vector<field_value_type> &&Ct,
                                            std::vector<field_value_type> &&Ht,
                                            const field_value_type &Zt) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain), t(t), At(std::move(At)),
                        Bt(std::move(Bt)), Ct(std::move(Ct)), Ht(std::move(Ht)), Zt(Zt) {
                    }

                    qap_instance_evaluation(const qap_instance_evaluation<field_type> &other) = default;
                    qap_instance_evaluation(qap_instance_evaluation<field_type> &&other) = default;
                    qap_instance_evaluation &operator=(const qap_instance_evaluation<field_type> &other) = default;
                    qap_instance_evaluation &operator=(qap_instance_evaluation<field_type> &&other) = default;

                    bool is_satisfied(const qap_witness<field_type> &witness) const {

                        if (this->num_variables != witness.num_variables) {
                            return false;
                        }

                        if (this->degree != witness.degree) {
                            return false;
                        }

                        if (this->num_inputs != witness.num_inputs) {
                            return false;
                        }

                        if (this->num_variables != witness.coefficients_for_ABCs.size()) {
                            return false;
                        }

                        if (this->degree + 1 != witness.coefficients_for_H.size()) {
                            return false;
                        }

                        if (this->At.size() != this->num_variables + 1 || this->Bt.size() != this->num_variables + 1 ||
                            this->Ct.size() != this->num_variables + 1) {
                            return false;
                        }

                        if (this->Ht.size() != this->degree + 1) {
                            return false;
                        }

                        if (this->Zt != this->domain->compute_vanishing_polynomial(this->t)) {
                            return false;
                        }

                        field_value_type ans_A = this->At[0] + witness.d1 * this->Zt;
                        field_value_type ans_B = this->Bt[0] + witness.d2 * this->Zt;
                        field_value_type ans_C = this->Ct[0] + witness.d3 * this->Zt;
                        field_value_type ans_H = field_value_type::zero();

                        ans_A = ans_A + algebra::inner_product(this->At.begin() + 1,
                                                                           this->At.begin() + 1 + this->num_variables,
                                                                           witness.coefficients_for_ABCs.begin(),
                                                                           witness.coefficients_for_ABCs.begin() +
                                                                               this->num_variables);
                        ans_B = ans_B + algebra::inner_product(this->Bt.begin() + 1,
                                                                           this->Bt.begin() + 1 + this->num_variables,
                                                                           witness.coefficients_for_ABCs.begin(),
                                                                           witness.coefficients_for_ABCs.begin() +
                                                                               this->num_variables);
                        ans_C = ans_C + algebra::inner_product(this->Ct.begin() + 1,
                                                                           this->Ct.begin() + 1 + this->num_variables,
                                                                           witness.coefficients_for_ABCs.begin(),
                                                                           witness.coefficients_for_ABCs.begin() +
                                                                               this->num_variables);
                        ans_H = ans_H + algebra::inner_product(this->Ht.begin(),
                                                                           this->Ht.begin() + this->degree + 1,
                                                                           witness.coefficients_for_H.begin(),
                                                                           witness.coefficients_for_H.begin() +
                                                                               this->degree + 1);

                        if (ans_A * ans_B - ans_C != ans_H * this->Zt) {
                            return false;
                        }

                        return true;
                    }
                };

                /*************************  WITNESS ***********************************/

                /**
                 * A QAP witness.
                 */
                template<typename FieldType>
                class qap_witness {
                    using field_type = FieldType;
                    using field_value_type = typename field_type::value_type;

                public:
                    std::size_t num_variables;
                    std::size_t degree;
                    std::size_t num_inputs;

                    field_value_type d1, d2, d3;

                    std::vector<field_value_type> coefficients_for_ABCs;
                    std::vector<field_value_type> coefficients_for_H;

                    qap_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const field_value_type &d1,
                                const field_value_type &d2,
                                const field_value_type &d3,
                                const std::vector<field_value_type> &coefficients_for_ABCs,
                                const std::vector<field_value_type> &coefficients_for_H) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), d1(d1), d2(d2), d3(d3),
                        coefficients_for_ABCs(coefficients_for_ABCs), coefficients_for_H(coefficients_for_H) {
                    }

                    qap_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const field_value_type &d1,
                                const field_value_type &d2,
                                const field_value_type &d3,
                                const std::vector<field_value_type> &coefficients_for_ABCs,
                                std::vector<field_value_type> &&coefficients_for_H) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), d1(d1), d2(d2), d3(d3),
                        coefficients_for_ABCs(coefficients_for_ABCs),
                        coefficients_for_H(std::move(coefficients_for_H)) {
                    }

                    qap_witness(const qap_witness<field_type> &other) = default;
                    qap_witness(qap_witness<field_type> &&other) = default;
                    qap_witness &operator=(const qap_witness<field_type> &other) = default;
                    qap_witness &operator=(qap_witness<field_type> &&other) = default;
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_QAP_HPP
