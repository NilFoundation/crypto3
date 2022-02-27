//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_ASSIGNMENT_PLONK_HPP
#define CRYPTO3_ZK_BLUEPRINT_ASSIGNMENT_PLONK_HPP

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>

#include <nil/crypto3/zk/blueprint_variable.hpp>
#include <nil/crypto3/zk/blueprint_linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType>
                class blueprint_assignment_table;

                template<typename BlueprintFieldType, std::size_t WitnessColumns>
                class blueprint_public_assignment_table<snark::plonk_constraint_system<BlueprintFieldType, WitnessColumns>> :
                    public snark::plonk_public_assignment_table<BlueprintFieldType, WitnessColumns>> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, WitnessColumns> ArithmetizationType;
                public:
                    
                    blueprint_assignment_table() : snark::plonk_public_assignment_table<BlueprintFieldType, WitnessColumns>>(){
                    }
                    
                    snark::plonk_column& selector(std::size_t selector_index){
                        if (selector_index >= selector_columns.size()) {
                            selector_columns.resize(selector_index + 1);
                        }
                        return selector_columns[selector_index];
                    }

                    std::size_t add_selector(std::size_t row_index){
                        snark::plonk_column selector_column(row_index + 1, FieldType::value_type::zero());
                        selector_column[row_index] = FieldType::value_type::one();
                        selector_columns.push_back(selector_column);
                        return selector_columns.size() - 1;
                    }

                    std::size_t add_selector(const std::initializer_list<std::size_t> &&row_indices){
                        std::size_t max_row_index = std::max(row_indices);
                        snark::plonk_column selector_column(max_row_index + 1, FieldType::value_type::zero());
                        for (std::size_t row_index : row_indices){
                            selector_column[row_index] = FieldType::value_type::one();
                        }
                        selector_columns.push_back(selector_column);
                        return selector_columns.size() - 1;
                    }

                    snark::plonk_column& public_input(std::size_t public_input_index){
                        assert(public_input_index < public_input_columns.size());
                        return public_input_columns[public_input_index];
                    }

                    snark::plonk_column& operator[](std::size_t index){
                        if (index < selector_columns.size())
                            return selector_columns[index];
                        index -= selector_columns.size();
                        // if (index < public_input_columns.size())
                        //     return public_input_columns[index];
                        // index -= public_input_columns.size();
                    }
                };

                template<typename BlueprintFieldType, std::size_t WitnessColumns>
                class blueprint_private_assignment_table<snark::plonk_constraint_system<BlueprintFieldType, WitnessColumns>> :
                    public snark::plonk_private_assignment_table<BlueprintFieldType, WitnessColumns>> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, WitnessColumns> ArithmetizationType;
                public:
                    
                    blueprint_assignment_table() : snark::plonk_private_assignment_table<BlueprintFieldType, WitnessColumns>>(){
                    }

                    snark::plonk_column witness(std::size_t witness_index) {
                        assert(witness_index < RedshiftParams::witness_columns);
                        return witness_columns[witness_index];
                    }

                    snark::plonk_column operator[](std::size_t index) {
                        if (index < RedshiftParams::witness_columns)
                            return witness_columns[index];
                        index -= RedshiftParams::witness_columns;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_ASSIGNMENT_PLONK_HPP
