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

#ifndef CRYPTO3_ZK_SSP_WITNESS_HPP
#define CRYPTO3_ZK_SSP_WITNESS_HPP

#include <map>
#include <memory>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

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

#endif    // CRYPTO3_ZK_SSP_WITNESS_HPP
