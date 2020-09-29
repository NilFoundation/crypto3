//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

#ifndef CRYPTO3_ZK_QAP_INSTANCE_EVALUATION_HPP
#define CRYPTO3_ZK_QAP_INSTANCE_EVALUATION_HPP

#include <map>
#include <memory>
#include <vector>

#include <nil/crypto3/zk/snark/relations/arithmetic_programs/qap/witness.hpp>

#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
#include <nil/crypto3/fft/make_evaluation_domain.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using namespace nil::crypto3::fft;

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
                struct qap_instance_evaluation {
                    std::size_t num_variables;
                    std::size_t degree;
                    std::size_t num_inputs;

                    std::shared_ptr<evaluation_domain<FieldType>> domain;

                    typename FieldType::value_type t;

                    std::vector<typename FieldType::value_type> At, Bt, Ct, Ht;

                    typename FieldType::value_type Zt;

                    qap_instance_evaluation(const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const typename FieldType::value_type &t,
                                            const std::vector<typename FieldType::value_type> &At,
                                            const std::vector<typename FieldType::value_type> &Bt,
                                            const std::vector<typename FieldType::value_type> &Ct,
                                            const std::vector<typename FieldType::value_type> &Ht,
                                            const typename FieldType::value_type &Zt) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain), t(t), At(At), Bt(Bt), Ct(Ct), Ht(Ht),
                        Zt(Zt) {
                    }

                    qap_instance_evaluation(const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                                            const std::size_t num_variables,
                                            const std::size_t degree,
                                            const std::size_t num_inputs,
                                            const typename FieldType::value_type &t,
                                            std::vector<typename FieldType::value_type> &&At,
                                            std::vector<typename FieldType::value_type> &&Bt,
                                            std::vector<typename FieldType::value_type> &&Ct,
                                            std::vector<typename FieldType::value_type> &&Ht,
                                            const typename FieldType::value_type &Zt) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain), t(t), At(std::move(At)),
                        Bt(std::move(Bt)), Ct(std::move(Ct)), Ht(std::move(Ht)), Zt(Zt) {
                    }

                    qap_instance_evaluation(const qap_instance_evaluation<FieldType> &other) = default;
                    qap_instance_evaluation(qap_instance_evaluation<FieldType> &&other) = default;
                    qap_instance_evaluation &operator=(const qap_instance_evaluation<FieldType> &other) = default;
                    qap_instance_evaluation &operator=(qap_instance_evaluation<FieldType> &&other) = default;

                    bool is_satisfied(const qap_witness<FieldType> &witness) const {

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

                        FieldType ans_A = this->At[0] + witness.d1 * this->Zt;
                        FieldType ans_B = this->Bt[0] + witness.d2 * this->Zt;
                        FieldType ans_C = this->Ct[0] + witness.d3 * this->Zt;
                        FieldType ans_H = FieldType::value_type::zero();

                        /*ans_A = ans_A + algebra::inner_product<FieldType>(this->At.begin() + 1,
                                                                        this->At.begin() + 1 + this->num_variables,
                                                                        witness.coefficients_for_ABCs.begin(),
                                                                        witness.coefficients_for_ABCs.begin() +
                                                                            this->num_variables);
                        ans_B = ans_B + algebra::inner_product<FieldType>(this->Bt.begin() + 1,
                                                                        this->Bt.begin() + 1 + this->num_variables,
                                                                        witness.coefficients_for_ABCs.begin(),
                                                                        witness.coefficients_for_ABCs.begin() +
                                                                            this->num_variables);
                        ans_C = ans_C + algebra::inner_product<FieldType>(this->Ct.begin() + 1,
                                                                        this->Ct.begin() + 1 + this->num_variables,
                                                                        witness.coefficients_for_ABCs.begin(),
                                                                        witness.coefficients_for_ABCs.begin() +
                                                                            this->num_variables);
                        ans_H = ans_H +
                                algebra::inner_product<FieldType>(this->Ht.begin(),
                                                                this->Ht.begin() + this->degree + 1,
                                                                witness.coefficients_for_H.begin(),
                                                                witness.coefficients_for_H.begin() + this->degree + 1);*/

                        // uncomment
                        // when inner_product ready

                        if (ans_A * ans_B - ans_C != ans_H * this->Zt) {
                            return false;
                        }

                        return true;
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_QAP_INSTANCE_EVALUATION_HPP
