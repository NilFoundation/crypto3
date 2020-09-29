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

#ifndef CRYPTO3_ZK_QAP_WITNESS_HPP
#define CRYPTO3_ZK_QAP_WITNESS_HPP

#include <map>
#include <memory>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using namespace nil::crypto3::fft;

                /**
                 * A QAP witness.
                 */
                template<typename FieldType>
                struct qap_witness {
                    std::size_t num_variables;
                    std::size_t degree;
                    std::size_t num_inputs;

                    typename FieldType::value_type d1, d2, d3;

                    std::vector<typename FieldType::value_type> coefficients_for_ABCs;
                    std::vector<typename FieldType::value_type> coefficients_for_H;

                    qap_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const typename FieldType::value_type &d1,
                                const typename FieldType::value_type &d2,
                                const typename FieldType::value_type &d3,
                                const std::vector<typename FieldType::value_type> &coefficients_for_ABCs,
                                const std::vector<typename FieldType::value_type> &coefficients_for_H) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), d1(d1), d2(d2), d3(d3),
                        coefficients_for_ABCs(coefficients_for_ABCs), coefficients_for_H(coefficients_for_H) {
                    }

                    qap_witness(const std::size_t num_variables,
                                const std::size_t degree,
                                const std::size_t num_inputs,
                                const typename FieldType::value_type &d1,
                                const typename FieldType::value_type &d2,
                                const typename FieldType::value_type &d3,
                                const std::vector<typename FieldType::value_type> &coefficients_for_ABCs,
                                std::vector<typename FieldType::value_type> &&coefficients_for_H) :
                        num_variables(num_variables),
                        degree(degree), num_inputs(num_inputs), d1(d1), d2(d2), d3(d3),
                        coefficients_for_ABCs(coefficients_for_ABCs),
                        coefficients_for_H(std::move(coefficients_for_H)) {
                    }

                    qap_witness(const qap_witness<FieldType> &other) = default;
                    qap_witness(qap_witness<FieldType> &&other) = default;
                    qap_witness &operator=(const qap_witness<FieldType> &other) = default;
                    qap_witness &operator=(qap_witness<FieldType> &&other) = default;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_QAP_WITNESS_HPP
