//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

#ifndef CRYPTO3_ZK_SSP_INSTANCE_EVALUATION_HPP
#define CRYPTO3_ZK_SSP_INSTANCE_EVALUATION_HPP

#include <map>
#include <memory>
#include <vector>

#include <nil/crypto3/zk/snark/relations/arithmetic_programs/ssp/witness.hpp>

#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
#include <nil/crypto3/fft/make_evaluation_domain.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using namespace nil::crypto3::fft;

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
                        typename FieldType::value_type ans_H = typename FieldType::value_type::zero();

                        ans_V = ans_V + algebra::inner_product<FieldType>(this->Vt.begin() + 1,
                                                                          this->Vt.begin() + 1 + this->num_variables,
                                                                          witness.coefficients_for_Vs.begin(),
                                                                          witness.coefficients_for_Vs.begin() +
                                                                              this->num_variables);
                        ans_H = ans_H +
                                algebra::inner_product<FieldType>(this->Ht.begin(),
                                                                  this->Ht.begin() + this->degree + 1,
                                                                  witness.coefficients_for_H.begin(),
                                                                  witness.coefficients_for_H.begin() + this->degree + 1);

                        if (ans_V.squared() - typename FieldType::value_type::one() != ans_H * this->Zt) {
                            return false;
                        }

                        return true;
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SSP_INSTANCE_EVALUATION_HPP
