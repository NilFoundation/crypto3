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

#ifndef CRYPTO3_ZK_SSP_INSTANCE_HPP
#define CRYPTO3_ZK_SSP_INSTANCE_HPP

#include <map>
#include <memory>
#include <vector>

#include <nil/crypto3/zk/snark/relations/arithmetic_programs/ssp/instance_evaluation.hpp>
#include <nil/crypto3/zk/snark/relations/arithmetic_programs/ssp/witness.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
#include <nil/crypto3/fft/make_evaluation_domain.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using namespace nil::crypto3::fft;

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

                    ssp_instance(const std::shared_ptr<evaluation_domain<FieldType>> &domain,
                                 const std::size_t num_variables,
                                 const std::size_t degree,
                                 const std::size_t num_inputs,
                                 const std::vector<std::map<std::size_t, typename FieldType::value_type>> &V_in_Lagrange_basis) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), domain(domain), V_in_Lagrange_basis(V_in_Lagrange_basis) {
                    }

                    ssp_instance(const std::shared_ptr<evaluation_domain<FieldType>> &domain,
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
                        const typename FieldType::value_type t = field_random_element<FieldType>();
                        std::vector<typename FieldType::value_type> Vt(this->num_variables + 1, FieldType::value_type::zero());
                        std::vector<typename FieldType::value_type> Ht(this->degree + 1);

                        const typename FieldType::value_type Zt = this->domain->compute_vanishing_polynomial(t);

                        const std::vector<typename FieldType::value_type> u = this->domain->evaluate_all_lagrange_polynomials(t);

                        for (std::size_t i = 0; i < this->num_variables + 1; ++i) {
                            for (auto &el : V_in_Lagrange_basis[i]) {
                                Vt[i] += u[el.first] * el.second;
                            }
                        }

                        typename FieldType::value_type ti = typename FieldType::value_type::one();
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

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SSP_INSTANCE_HPP
