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

#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/blueprint_linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType>
                class blueprint_assignment_table;

                template<typename BlueprintFieldType, std::size_t WitnessColumns>
                class blueprint_assignment_table<snark::plonk_constraint_system<BlueprintFieldType, WitnessColumns>> :
                    public snark::plonk_table<BlueprintFieldType, WitnessColumns>> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, WitnessColumns> ArithmetizationType;
                public:
                    
                    blueprint_assignment_table() : snark::plonk_table<BlueprintFieldType, WitnessColumns>>(){
                    }

                    snark::plonk_column& witness(std::size_t index){
                        if (index >= witness_variables.size()) {
                            witness_variables.resize(index + 1);
                        }
                        return witness_variables[index];
                    }

                    snark::plonk_column& selector(std::size_t index){
                        if (index >= selector_variables.size()) {
                            selector_variables.resize(index + 1);
                        }
                        return selector_variables[index];
                    }

                    snark::plonk_column& public_input(std::size_t index){
                        assert(index < public_input_variables.size());
                        return public_input_variables[index];
                    }

                    snark::plonk_column& operator[](std::size_t index){
                        if (index < RedshiftParams::witness_columns)
                            return witness_variables[index];
                        index -= RedshiftParams::witness_columns;
                        if (index < selector_variables.size())
                            return selector_variables[index];
                        index -= selector_variables.size();
                        // if (index < public_input_variables.size())
                        //     return public_input_variables[index];
                        // index -= public_input_variables.size();
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_ASSIGNMENT_PLONK_HPP
