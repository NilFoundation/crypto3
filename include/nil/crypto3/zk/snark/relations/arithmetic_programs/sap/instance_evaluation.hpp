//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

#ifndef CRYPTO3_ZK_SAP_INSTANCE_EVALUATION_HPP
#define CRYPTO3_ZK_SAP_INSTANCE_EVALUATION_HPP

#include <map>
#include <memory>
#include <vector>

#include <nil/crypto3/zk/snark/relations/arithmetic_programs/sap/witness.hpp>

#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
#include <nil/crypto3/fft/make_evaluation_domain.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using namespace nil::crypto3::fft;

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
                        typename FieldType::value_type ans_H = typename FieldType::value_type::zero();

                        ans_A = ans_A + algebra::inner_product<FieldType>(this->At.begin() + 1,
                                                                          this->At.begin() + 1 + this->num_variables,
                                                                          witness.coefficients_for_ACs.begin(),
                                                                          witness.coefficients_for_ACs.begin() +
                                                                              this->num_variables);
                        ans_C = ans_C + algebra::inner_product<FieldType>(this->Ct.begin() + 1,
                                                                          this->Ct.begin() + 1 + this->num_variables,
                                                                          witness.coefficients_for_ACs.begin(),
                                                                          witness.coefficients_for_ACs.begin() +
                                                                              this->num_variables);
                        ans_H = ans_H +
                                algebra::inner_product<FieldType>(this->Ht.begin(),
                                                                  this->Ht.begin() + this->degree + 1,
                                                                  witness.coefficients_for_H.begin(),
                                                                  witness.coefficients_for_H.begin() + this->degree + 1);

                        if (ans_A * ans_A - ans_C != ans_H * this->Zt) {
                            return false;
                        }

                        return true;
                    }
                };
                
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SAP_INSTANCE_EVALUATION_HPP
