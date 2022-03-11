//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PROFILING_HPP
#define CRYPTO3_PROFILING_HPP

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

namespace nil {
    namespace crypto3 {
        
        template <typename ValueType>
        void profiling(std::vector<ValueType> column){
            for (std::size_t index = 0; index < column.size(); index++){
                std::cout << "\t" << column[index].data;
            }
        }
        
        template <typename FieldType, std::size_t WitnessColumns, std::size_t SelectorColumns,
                        std::size_t PublicInputColumns, std::size_t ConstantColumns>
        void profiling(zk::snark::plonk_assignment_table<FieldType, WitnessColumns, SelectorColumns,
        PublicInputColumns, ConstantColumns> assignments){

            zk::snark::plonk_table_description<FieldType> description = assignments.table_description();

            for (std::size_t w_index = 0; w_index < description.witness_columns; w_index++){
                std::cout << "W" << w_index << ":";
                profiling(assignments.witness(w_index));
                std::cout << std::endl;
            }

            for (std::size_t pi_index = 0; pi_index < description.public_input_columns; pi_index++){
                std::cout << "PI" << pi_index << ":";
                profiling(assignments.public_input(pi_index));
                std::cout << std::endl;
            }

            for (std::size_t c_index = 0; c_index < description.constant_columns; c_index++){
                std::cout << "C" << c_index << ":";
                profiling(assignments.constant(c_index));
                std::cout << std::endl;
            }

            for (std::size_t s_index = 0; s_index < description.selector_columns; s_index++){
                std::cout << "S" << s_index << ":";
                profiling(assignments.selector(s_index));
                std::cout << std::endl;
            }
        }


    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PROFILING_HPP
