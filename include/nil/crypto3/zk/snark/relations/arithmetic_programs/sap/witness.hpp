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

#ifndef CRYPTO3_ZK_SAP_WITNESS_HPP
#define CRYPTO3_ZK_SAP_WITNESS_HPP

#include <map>
#include <memory>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

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

#endif    // CRYPTO3_ZK_SAP_WITNESS_HPP
