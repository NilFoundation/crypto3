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
// @file Declaration of interfaces for a SAP ("Square Arithmetic Program").
//
// SAPs are defined in \[GM17].
//
// References:
//
// \[GM17]:
// "Snarky Signatures: Minimal Signatures of Knowledge from
//  Simulation-Extractable SNARKs",
// Jens Groth and Mary Maller,
// IACR-CRYPTO-2017,
// <https://eprint.iacr.org/2017/540>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_SAP_HPP
#define CRYPTO3_ZK_SAP_HPP

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
                struct sap_witness;

                template<typename FieldType>
                struct sap_instance_evaluation;

                /*************************  INSTATNCE  ***********************************/

                /**
                 * A SAP instance.
                 *
                 * Specifically, the datastructure stores:
                 * - a choice of domain (corresponding to a certain subset of the field);
                 * - the number of variables, the degree, and the number of inputs; and
                 * - coefficients of the A,C polynomials in the Lagrange basis.
                 *
                 * There is no need to store the Z polynomial because it is uniquely
                 * determined by the domain (as Z is its vanishing polynomial).
                 */
                template<typename FieldType>
                struct sap_instance {
                    std::size_t num_variables;
                    std::size_t degree;
                    std::size_t num_inputs;

                    std::shared_ptr<evaluation_domain<FieldType>> domain;

                    std::vector<std::map<std::size_t, typename FieldType::value_type>> A_in_Lagrange_basis;
                    std::vector<std::map<std::size_t, typename FieldType::value_type>> C_in_Lagrange_basis;

                    sap_instance(
                        const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                        const std::size_t num_variables,
                        const std::size_t degree,
                        const std::size_t num_inputs,
                        const std::vector<std::map<std::size_t, typename FieldType::value_type>> &A_in_Lagrange_basis,
                        const std::vector<std::map<std::size_t, typename FieldType::value_type>> &C_in_Lagrange_basis) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain),
                        A_in_Lagrange_basis(A_in_Lagrange_basis), C_in_Lagrange_basis(C_in_Lagrange_basis) {
                    }

                    sap_instance(
                        const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                        const std::size_t num_variables,
                        const std::size_t degree,
                        const std::size_t num_inputs,
                        std::vector<std::map<std::size_t, typename FieldType::value_type>> &&A_in_Lagrange_basis,
                        std::vector<std::map<std::size_t, typename FieldType::value_type>> &&C_in_Lagrange_basis) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain),
                        A_in_Lagrange_basis(std::move(A_in_Lagrange_basis)),
                        C_in_Lagrange_basis(std::move(C_in_Lagrange_basis)) {
                    }

                    sap_instance(const sap_instance<FieldType> &other) = default;
                    sap_instance(sap_instance<FieldType> &&other) = default;
                    sap_instance &operator=(const sap_instance<FieldType> &other) = default;
                    sap_instance &operator=(sap_instance<FieldType> &&other) = default;

                    bool is_satisfied(const sap_witness<FieldType> &witness) const {
                        const typename FieldType::value_type t = algebra::random_element<FieldType>();

                        std::vector<typename FieldType::value_type> At(this->num_variables + 1,
                                                                       FieldType::value_type::zero());
                        std::vector<typename FieldType::value_type> Ct(this->num_variables + 1,
                                                                       FieldType::value_type::zero());
                        std::vector<typename FieldType::value_type> Ht(this->degree + 1);

                        const typename FieldType::value_type Zt = this->domain->compute_vanishing_polynomial(t);

                        const std::vector<typename FieldType::value_type> u =
                            this->domain->evaluate_all_lagrange_polynomials(t);

                        for (std::size_t i = 0; i < this->num_variables + 1; ++i) {
                            for (auto &el : A_in_Lagrange_basis[i]) {
                                At[i] += u[el.first] * el.second;
                            }

                            for (auto &el : C_in_Lagrange_basis[i]) {
                                Ct[i] += u[el.first] * el.second;
                            }
                        }

                        typename FieldType::value_type ti = FieldType::value_type::one();
                        for (std::size_t i = 0; i < this->degree + 1; ++i) {
                            Ht[i] = ti;
                            ti *= t;
                        }

                        const sap_instance_evaluation<FieldType> eval_sap_inst(this->domain,
                                                                               this->num_variables,
                                                                               this->degree,
                                                                               this->num_inputs,
                                                                               t,
                                                                               std::move(At),
                                                                               std::move(Ct),
                                                                               std::move(Ht),
                                                                               Zt);
                        return eval_sap_inst.is_satisfied(witness);
                    }
                };

                /*************************  INSTATNCE  EVALUATION ***********************************/

                /**
                 * A SAP instance evaluation is a SAP instance that is evaluated at a field element t.
                 *
                 * Specifically, the datastructure stores:
                 * - a choice of domain (corresponding to a certain subset of the field);
                 * - the number of variables, the degree, and the number of inputs;
                 * - a field element t;
                 * - evaluations of the A,C (and Z) polynomials at t;
                 * - evaluations of all monomials of t;
                 * - counts about how many of the above evaluations are in fact non-zero.
                 */
                template<typename FieldType>
                struct sap_instance_evaluation {
                    std::size_t num_variables;
                    std::size_t degree;
                    std::size_t num_inputs;

                    std::shared_ptr<evaluation_domain<FieldType>> domain;

                    typename FieldType::value_type t;

                    std::vector<typename FieldType::value_type> At, Ct, Ht;

                    typename FieldType::value_type Zt;

                    sap_instance_evaluation(const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const typename FieldType::value_type &t,
                                            const std::vector<typename FieldType::value_type> &At,
                                            const std::vector<typename FieldType::value_type> &Ct,
                                            const std::vector<typename FieldType::value_type> &Ht,
                                            const typename FieldType::value_type &Zt) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain), t(t), At(At), Ct(Ct), Ht(Ht), Zt(Zt) {
                    }

                    sap_instance_evaluation(const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const typename FieldType::value_type &t,
                                            std::vector<typename FieldType::value_type> &&At,
                                            std::vector<typename FieldType::value_type> &&Ct,
                                            std::vector<typename FieldType::value_type> &&Ht,
                                            const typename FieldType::value_type &Zt) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain), t(t), At(std::move(At)),
                        Ct(std::move(Ct)), Ht(std::move(Ht)), Zt(Zt) {
                    }

                    sap_instance_evaluation(const sap_instance_evaluation<FieldType> &other) = default;
                    sap_instance_evaluation(sap_instance_evaluation<FieldType> &&other) = default;
                    sap_instance_evaluation &operator=(const sap_instance_evaluation<FieldType> &other) = default;
                    sap_instance_evaluation &operator=(sap_instance_evaluation<FieldType> &&other) = default;

                    bool is_satisfied(const sap_witness<FieldType> &witness) const {
                        if (this->num_variables != witness.num_variables) {
                            return false;
                        }

                        if (this->degree != witness.degree) {
                            return false;
                        }

                        if (this->num_inputs != witness.num_inputs) {
                            return false;
                        }

                        if (this->num_variables != witness.coefficients_for_ACs.size()) {
                            return false;
                        }

                        if (this->degree + 1 != witness.coefficients_for_H.size()) {
                            return false;
                        }

                        if (this->At.size() != this->num_variables + 1 || this->Ct.size() != this->num_variables + 1) {
                            return false;
                        }

                        if (this->Ht.size() != this->degree + 1) {
                            return false;
                        }

                        if (this->Zt != this->domain->compute_vanishing_polynomial(this->t)) {
                            return false;
                        }

                        typename FieldType::value_type ans_A = this->At[0] + witness.d1 * this->Zt;
                        typename FieldType::value_type ans_C = this->Ct[0] + witness.d2 * this->Zt;
                        typename FieldType::value_type ans_H = FieldType::value_type::zero();

                        ans_A = ans_A + algebra::inner_product(this->At.begin() + 1,
                                                                          this->At.begin() + 1 + this->num_variables,
                                                                          witness.coefficients_for_ACs.begin(),
                                                                          witness.coefficients_for_ACs.begin() +
                                                                              this->num_variables);
                        ans_C = ans_C + algebra::inner_product(this->Ct.begin() + 1,
                                                                          this->Ct.begin() + 1 + this->num_variables,
                                                                          witness.coefficients_for_ACs.begin(),
                                                                          witness.coefficients_for_ACs.begin() +
                                                                              this->num_variables);
                        ans_H = ans_H + algebra::inner_product(this->Ht.begin(),
                                                                          this->Ht.begin() + this->degree + 1,
                                                                          witness.coefficients_for_H.begin(),
                                                                          witness.coefficients_for_H.begin() +
                                                                              this->degree + 1);

                        if (ans_A * ans_A - ans_C != ans_H * this->Zt) {
                            return false;
                        }

                        return true;
                    }
                };

                /*************************  WITNESS ***********************************/

                /**
                 * A SAP witness.
                 */
                template<typename FieldType>
                struct sap_witness {
                    std::size_t num_variables;
                    std::size_t degree;
                    std::size_t num_inputs;

                    typename FieldType::value_type d1, d2;

                    std::vector<typename FieldType::value_type> coefficients_for_ACs;
                    std::vector<typename FieldType::value_type> coefficients_for_H;

                    sap_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const typename FieldType::value_type &d1,
                                const typename FieldType::value_type &d2,
                                const std::vector<typename FieldType::value_type> &coefficients_for_ACs,
                                const std::vector<typename FieldType::value_type> &coefficients_for_H) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), d1(d1), d2(d2),
                        coefficients_for_ACs(coefficients_for_ACs), coefficients_for_H(coefficients_for_H) {
                    }

                    sap_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const typename FieldType::value_type &d1,
                                const typename FieldType::value_type &d2,
                                const std::vector<typename FieldType::value_type> &coefficients_for_ACs,
                                std::vector<typename FieldType::value_type> &&coefficients_for_H) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), d1(d1), d2(d2),
                        coefficients_for_ACs(coefficients_for_ACs), coefficients_for_H(std::move(coefficients_for_H)) {
                    }

                    sap_witness(const sap_witness<FieldType> &other) = default;
                    sap_witness(sap_witness<FieldType> &&other) = default;
                    sap_witness &operator=(const sap_witness<FieldType> &other) = default;
                    sap_witness &operator=(sap_witness<FieldType> &&other) = default;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SAP_HPP
