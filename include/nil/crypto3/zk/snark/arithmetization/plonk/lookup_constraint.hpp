//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_LOOKUP_CONSTRAINT_HPP
#define CRYPTO3_ZK_PLONK_LOOKUP_CONSTRAINT_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename VariableType = plonk_variable<FieldType>>
                class plonk_lookup_constraint {
                public:
                    std::vector<math::non_linear_term<VariableType>> lookup_input;
                    std::vector<VariableType> lookup_value;

                    /*template<std::size_t WitnessColumns, std::size_t SelectorColumns, 
                        std::size_t PublicInputColumns, std::size_t ConstantColumns>
                    std::array<math::polynomial<typename VariableType::assignment_type>, k>
                    evaluate_lookup_input(const plonk_polynomial_table<FieldType, WitnessColumns,
                                SelectorColumns, PublicInputColumns, ConstantColumns> &assignments) const {
                        std::array<math::polynomial<typename VariableType::assignment_type>, k> acc;
                        for (std::size_t i = 0; i < k, i++) {
                            typename VariableType::assignment_type assignment;
                                switch (lookup_input[i].type) {
                                    case VariableType::column_type::witness:
                                        assignment = math::polynomial_shift<FieldType>(assignments.witness(lookup_input[i].index), domain->get_domain_element(lookup_input[i].rotation));
                                        break;
                                    case VariableType::column_type::selector:
                                        assignment = math::polynomial_shift<FieldType>(assignments.witness(lookup_input[i].index), domain->get_domain_element(lookup_input[i].rotation));
                                        break;
                                    case VariableType::column_type::public_input:
                                        assignment = math::polynomial_shift<FieldType>(assignments.witness(lookup_input[i].index), domain->get_domain_element(lookup_input[i].rotation));
                                        break;
                                    case VariableType::column_type::constant:
                                        assignment = math::polynomial_shift<FieldType>(assignments.witness(lookup_input[i].index), domain->get_domain_element(lookup_input[i].rotation));
                                        break;
                                }
                            acc[i] = assignment;
                        }
                        return acc;
                    }

                    template<std::size_t WitnessColumns, std::size_t SelectorColumns, 
                        std::size_t PublicInputColumns, std::size_t ConstantColumns>
                    std::array<math::polynomial<typename VariableType::assignment_type>, k>
                    evaluate_lookup_value(const plonk_polynomial_table<FieldType, WitnessColumns,
                                SelectorColumns, PublicInputColumns, ConstantColumns> &assignments) const {
                        std::array<math::polynomial<typename VariableType::assignment_type>, k> acc;
                        for (std::size_t i = 0; i < k, i++) {
                            typename VariableType::assignment_type assignment;
                                switch (lookup_value[i].type) {
                                    case VariableType::column_type::witness:
                                        assignment = assignments.witness(lookup_input[i].index);
                                        break;
                                    case VariableType::column_type::selector:
                                        assignment = assignments.selector(lookup_input[i].index);
                                        break;
                                    case VariableType::column_type::public_input:
                                        assignment = assignments.public_input(lookup_input[i].index);
                                        break;
                                    case VariableType::column_type::constant:
                                        assignment = assignments.constant(lookup_input[i].index);
                                        break;
                                }
                            acc[i] = assignment;
                        }
                        return acc;
                    }*/

                   /*template<typename ArithmetizationParams>
                    std::pair<std::array<std::vector<typename VariableType::column_type>, k>, typename FieldType::value_type>
                    evaluate_lookup_input(const plonk_assignment_table<FieldType, ArithmetizationParams> &assignments, typename FieldType::value_type theta,
                    typename FieldType::value_type theta_acc) const {
                        std::array<std::vector<typename VariableType::column_type>, k> acc;
                        for (std::size_t i = 0; i < k; i++) {
                            typename VariableType::column_type assignment;
                                switch (lookup_input[i].type) {
                                    case VariableType::column_type::witness:
                                        assignment = assignments.witness(lookup_input[i].index);
                                        break;
                                    case VariableType::column_type::public_input:
                                        assignment = assignments.public_input(lookup_input[i].index);
                                        break;
                                    case VariableType::column_type::constant:
                                        assignment = assignments.constant(lookup_input[i].index);
                                        break;
                                }
                            for (std:: size_t j = 0; j < assignment.size(); j++) {  
                                acc[i].push_back(assignment[(j + lookup_input[i].rotation) % assignment.size()] * theta_acc);
                            }
                            theta_acc = theta * theta_acc;
                        }
                        return std::make_pair(acc, theta_acc);
                    }

                   template<typename ArithmetizationParams>
                    std::pair<std::array<std::vector<typename VariableType::column_type>, k>, typename FieldType::value_type>
                    evaluate_lookup_value(const plonk_assignment_table<FieldType, ArithmetizationParams> &assignments, typename FieldType::value_type theta, 
                    typename FieldType::value_type theta_acc) const {
                        std::array<std::vector<typename VariableType::column_type>, k> acc;
                        for (std::size_t i = 0; i < k; i++) {
                            typename VariableType::column_type assignment;
                                switch (lookup_value[i].type) {
                                    case VariableType::column_type::witness:
                                        assignment = assignments.witness(lookup_input[i].index);
                                        break;
                                    case VariableType::column_type::public_input:
                                        assignment = assignments.public_input(lookup_input[i].index);
                                        break;
                                    case VariableType::column_type::constant:
                                        assignment = assignments.constant(lookup_input[i].index);
                                        break;
                                }
                            for (std:: size_t j = 0; j < assignment.size(); j++) {  
                                acc[i].push_back(assignment[j] * theta_acc);
                            }
                            theta_acc = thets_acc * theta;
                        }
                        return std::make_pair(acc, theta_acc);
                    }*/
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_LOOKUP_CONSTRAINT_HPP
