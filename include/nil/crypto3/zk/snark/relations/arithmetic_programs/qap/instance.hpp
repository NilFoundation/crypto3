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

#ifndef CRYPTO3_ZK_QAP_INSTANCE_HPP
#define CRYPTO3_ZK_QAP_INSTANCE_HPP

#include <map>
#include <memory>
#include <vector>

#include <nil/crypto3/zk/snark/relations/arithmetic_programs/qap/instance_evaluation.hpp>
#include <nil/crypto3/zk/snark/relations/arithmetic_programs/qap/witness.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
#include <nil/crypto3/fft/make_evaluation_domain.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using namespace nil::crypto3::fft;

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
                struct qap_instance {
                    std::size_t num_variables;
                    std::size_t degree;
                    std::size_t num_inputs;

                    std::shared_ptr<evaluation_domain<FieldType>> domain;

                    std::vector<std::map<std::size_t, typename FieldType::value_type>> A_in_Lagrange_basis;
                    std::vector<std::map<std::size_t, typename FieldType::value_type>> B_in_Lagrange_basis;
                    std::vector<std::map<std::size_t, typename FieldType::value_type>> C_in_Lagrange_basis;

                    qap_instance(
                        const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                        const std::size_t num_variables,
                        const std::size_t degree,
                        const std::size_t num_inputs,
                        const std::vector<std::map<std::size_t, typename FieldType::value_type>> &A_in_Lagrange_basis,
                        const std::vector<std::map<std::size_t, typename FieldType::value_type>> &B_in_Lagrange_basis,
                        const std::vector<std::map<std::size_t, typename FieldType::value_type>> &C_in_Lagrange_basis) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain),
                        A_in_Lagrange_basis(A_in_Lagrange_basis), B_in_Lagrange_basis(B_in_Lagrange_basis),
                        C_in_Lagrange_basis(C_in_Lagrange_basis) {
                    }

                    qap_instance(
                        const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                        const std::size_t num_variables,
                        const std::size_t degree,
                        const std::size_t num_inputs,
                        std::vector<std::map<std::size_t, typename FieldType::value_type>> &&A_in_Lagrange_basis,
                        std::vector<std::map<std::size_t, typename FieldType::value_type>> &&B_in_Lagrange_basis,
                        std::vector<std::map<std::size_t, typename FieldType::value_type>> &&C_in_Lagrange_basis) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain),
                        A_in_Lagrange_basis(std::move(A_in_Lagrange_basis)),
                        B_in_Lagrange_basis(std::move(B_in_Lagrange_basis)),
                        C_in_Lagrange_basis(std::move(C_in_Lagrange_basis)) {
                    }

                    qap_instance(const qap_instance<FieldType> &other) = default;
                    qap_instance(qap_instance<FieldType> &&other) = default;
                    qap_instance &operator=(const qap_instance<FieldType> &other) = default;
                    qap_instance &operator=(qap_instance<FieldType> &&other) = default;

                    bool is_satisfied(const qap_witness<FieldType> &witness) const {
                        const typename FieldType::value_type t = field_random_element<FieldType>();

                        std::vector<typename FieldType::value_type> At(this->num_variables + 1,
                                                                       FieldType::value_type::zero());
                        std::vector<typename FieldType::value_type> Bt(this->num_variables + 1,
                                                                       FieldType::value_type::zero());
                        std::vector<typename FieldType::value_type> Ct(this->num_variables + 1,
                                                                       FieldType::value_type::zero());
                        std::vector<typename FieldType::value_type> Ht(this->degree + 1);

                        const FieldType Zt = this->domain->compute_vanishing_polynomial(t);

                        const std::vector<FieldType> u = this->domain->evaluate_all_lagrange_polynomials(t);

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

                        typename FieldType::value_type ti = FieldType::value_type::one();
                        for (size_t i = 0; i < this->degree + 1; ++i) {
                            Ht[i] = ti;
                            ti *= t;
                        }

                        const qap_instance_evaluation<FieldType> eval_qap_inst(this->domain,
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

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_QAP_INSTANCE_HPP
