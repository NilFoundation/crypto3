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
// @file Declaration of interfaces for a SSP ("Square Span Program").
//
// SSPs are defined in \[DFGK14].
//
// References:
//
// \[DFGK14]:
// "Square Span Programs with Applications to Succinct NIZK Arguments"
// George Danezis, Cedric Fournet, Jens Groth, Markulf Kohlweiss,
// ASIACRYPT 2014,
// <http://eprint.iacr.org/2014/718>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_SSP_HPP
#define CRYPTO3_ZK_SSP_HPP

#include <map>
#include <memory>

#include <nil/crypto3/algebra/multiexp/inner_product.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
#include <nil/crypto3/fft/make_evaluation_domain.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using namespace nil::crypto3::fft;

                template<typename FieldType>
                struct ssp_witness;

                template<typename FieldType>
                struct ssp_instance_evaluation;

                /*************************  INSTATNCE  ***********************************/

                /**
                 * A SSP instance.
                 *
                 * Specifically, the datastructure stores:
                 * - a choice of domain (corresponding to a certain subset of the field);
                 * - the number of variables, the degree, and the number of inputs; and
                 * - coefficients of the V polynomials in the Lagrange basis.
                 *
                 * There is no need to store the Z polynomial because it is uniquely
                 * determined by the domain (as Z is its vanishing polynomial).
                 */
                template<typename FieldType>
                struct ssp_instance {
                    std::size_t num_variables;
                    std::size_t degree;
                    std::size_t num_inputs;

                    std::shared_ptr<evaluation_domain<FieldType>> domain;

                    std::vector<std::map<std::size_t, typename FieldType::value_type>> V_in_Lagrange_basis;

                    ssp_instance(
                        const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                        const std::size_t num_variables,
                        const std::size_t degree,
                        const std::size_t num_inputs,
                        const std::vector<std::map<std::size_t, typename FieldType::value_type>> &V_in_Lagrange_basis) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain),
                        V_in_Lagrange_basis(V_in_Lagrange_basis) {
                    }

                    ssp_instance(
                        const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                        const std::size_t num_variables,
                        const std::size_t degree,
                        const std::size_t num_inputs,
                        std::vector<std::map<std::size_t, typename FieldType::value_type>> &&V_in_Lagrange_basis) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain),
                        V_in_Lagrange_basis(std::move(V_in_Lagrange_basis)) {
                    }

                    ssp_instance(const ssp_instance<FieldType> &other) = default;
                    ssp_instance(ssp_instance<FieldType> &&other) = default;
                    ssp_instance &operator=(const ssp_instance<FieldType> &other) = default;
                    ssp_instance &operator=(ssp_instance<FieldType> &&other) = default;

                    bool is_satisfied(const ssp_witness<FieldType> &witness) const {
                        const typename FieldType::value_type t = algebra::random_element<FieldType>();
                        std::vector<typename FieldType::value_type> Vt(this->num_variables + 1,
                                                                       FieldType::value_type::zero());
                        std::vector<typename FieldType::value_type> Ht(this->degree + 1);

                        const typename FieldType::value_type Zt = this->domain->compute_vanishing_polynomial(t);

                        const std::vector<typename FieldType::value_type> u =
                            this->domain->evaluate_all_lagrange_polynomials(t);

                        for (std::size_t i = 0; i < this->num_variables + 1; ++i) {
                            for (auto &el : V_in_Lagrange_basis[i]) {
                                Vt[i] += u[el.first] * el.second;
                            }
                        }

                        typename FieldType::value_type ti = FieldType::value_type::one();
                        for (std::size_t i = 0; i < this->degree + 1; ++i) {
                            Ht[i] = ti;
                            ti *= t;
                        }

                        const ssp_instance_evaluation<FieldType> eval_ssp_inst(this->domain,
                                                                               this->num_variables,
                                                                               this->degree,
                                                                               this->num_inputs,
                                                                               t,
                                                                               std::move(Vt),
                                                                               std::move(Ht),
                                                                               Zt);
                        return eval_ssp_inst.is_satisfied(witness);
                    }
                };

                /*************************  INSTATNCE  EVALUATION ***********************************/

                /**
                 * A SSP instance evaluation is a SSP instance that is evaluated at a field element t.
                 *
                 * Specifically, the datastructure stores:
                 * - a choice of domain (corresponding to a certain subset of the field);
                 * - the number of variables, the degree, and the number of inputs;
                 * - a field element t;
                 * - evaluations of the V (and Z) polynomials at t;
                 * - evaluations of all monomials of t.
                 */
                template<typename FieldType>
                struct ssp_instance_evaluation {
                    std::size_t num_variables;
                    std::size_t degree;
                    std::size_t num_inputs;

                    std::shared_ptr<evaluation_domain<FieldType>> domain;

                    typename FieldType::value_type t;

                    std::vector<typename FieldType::value_type> Vt, Ht;

                    typename FieldType::value_type Zt;

                    ssp_instance_evaluation(const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const typename FieldType::value_type &t,
                                            const std::vector<typename FieldType::value_type> &Vt,
                                            const std::vector<typename FieldType::value_type> &Ht,
                                            const typename FieldType::value_type &Zt) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain), t(t), Vt(Vt), Ht(Ht), Zt(Zt) {
                    }

                    ssp_instance_evaluation(const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const typename FieldType::value_type &t,
                                            std::vector<typename FieldType::value_type> &&Vt,
                                            std::vector<typename FieldType::value_type> &&Ht,
                                            const typename FieldType::value_type &Zt) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain), t(t), Vt(std::move(Vt)),
                        Ht(std::move(Ht)), Zt(Zt) {
                    }

                    ssp_instance_evaluation(const ssp_instance_evaluation<FieldType> &other) = default;
                    ssp_instance_evaluation(ssp_instance_evaluation<FieldType> &&other) = default;
                    ssp_instance_evaluation &operator=(const ssp_instance_evaluation<FieldType> &other) = default;
                    ssp_instance_evaluation &operator=(ssp_instance_evaluation<FieldType> &&other) = default;

                    bool is_satisfied(const ssp_witness<FieldType> &witness) const {

                        if (this->num_variables != witness.num_variables) {
                            return false;
                        }

                        if (this->degree != witness.degree) {
                            return false;
                        }

                        if (this->num_inputs != witness.num_inputs) {
                            return false;
                        }

                        if (this->num_variables != witness.coefficients_for_Vs.size()) {
                            return false;
                        }

                        if (this->degree + 1 != witness.coefficients_for_H.size()) {
                            return false;
                        }

                        if (this->Vt.size() != this->num_variables + 1) {
                            return false;
                        }

                        if (this->Ht.size() != this->degree + 1) {
                            return false;
                        }

                        if (this->Zt != this->domain->compute_vanishing_polynomial(this->t)) {
                            return false;
                        }

                        typename FieldType::value_type ans_V = this->Vt[0] + witness.d * this->Zt;
                        typename FieldType::value_type ans_H = FieldType::value_type::zero();

                        ans_V = ans_V + algebra::inner_product(this->Vt.begin() + 1,
                                                                          this->Vt.begin() + 1 + this->num_variables,
                                                                          witness.coefficients_for_Vs.begin(),
                                                                          witness.coefficients_for_Vs.begin() +
                                                                              this->num_variables);
                        ans_H = ans_H + algebra::inner_product(this->Ht.begin(),
                                                                          this->Ht.begin() + this->degree + 1,
                                                                          witness.coefficients_for_H.begin(),
                                                                          witness.coefficients_for_H.begin() +
                                                                              this->degree + 1);

                        if (ans_V.squared() - FieldType::value_type::one() != ans_H * this->Zt) {
                            return false;
                        }

                        return true;
                    }
                };

                /*************************  WITNESS ***********************************/

                /**
                 * A SSP witness.
                 */
                template<typename FieldType>
                struct ssp_witness {
                    std::size_t num_variables;
                    std::size_t degree;
                    std::size_t num_inputs;

                    typename FieldType::value_type d;

                    std::vector<typename FieldType::value_type> coefficients_for_Vs;
                    std::vector<typename FieldType::value_type> coefficients_for_H;

                    ssp_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const typename FieldType::value_type &d,
                                const std::vector<typename FieldType::value_type> &coefficients_for_Vs,
                                const std::vector<typename FieldType::value_type> &coefficients_for_H) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), d(d), coefficients_for_Vs(coefficients_for_Vs),
                        coefficients_for_H(coefficients_for_H) {
                    }

                    ssp_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const typename FieldType::value_type &d,
                                const std::vector<typename FieldType::value_type> &coefficients_for_Vs,
                                std::vector<typename FieldType::value_type> &&coefficients_for_H) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), d(d), coefficients_for_Vs(coefficients_for_Vs),
                        coefficients_for_H(std::move(coefficients_for_H)) {
                    }

                    ssp_witness(const ssp_witness<FieldType> &other) = default;
                    ssp_witness(ssp_witness<FieldType> &&other) = default;
                    ssp_witness &operator=(const ssp_witness<FieldType> &other) = default;
                    ssp_witness &operator=(ssp_witness<FieldType> &&other) = default;
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SSP_HPP
