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
// @file Declaration of PLONK table profiling util.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_TABLE_PROFILING_HPP
#define CRYPTO3_BLUEPRINT_TABLE_PROFILING_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/blueprint/plonk/assignment.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            template<typename ValueType>
            void profiling(std::vector<ValueType> column) {
                for (std::size_t index = 0; index < column.size(); index++) {
                    std::cout << "\t" << column[index].data;
                }
            }

            template<typename FieldType, typename ArithmetizationParams>
            void profiling(zk::snark::plonk_assignment_table<FieldType, ArithmetizationParams> assignments) {

                for (std::size_t row_index = 0; row_index < assignments.rows_amount(); row_index++) {
                    std::cout << "\t" << row_index;
                }
                std::cout << std::endl;

                for (std::size_t w_index = 0; w_index < ArithmetizationParams::WitnessColumns; w_index++) {
                    std::cout << "W" << w_index << ":";
                    profiling(assignments.witness(w_index));
                    std::cout << std::endl;
                }

                for (std::size_t pi_index = 0; pi_index < ArithmetizationParams::PublicInputColumns; pi_index++) {
                    std::cout << "PI" << pi_index << ":";
                    profiling(assignments.public_input(pi_index));
                    std::cout << std::endl;
                }

                for (std::size_t c_index = 0; c_index < ArithmetizationParams::ConstantColumns; c_index++) {
                    std::cout << "C" << c_index << ":";
                    profiling(assignments.constant(c_index));
                    std::cout << std::endl;
                }

                for (std::size_t s_index = 0; s_index < ArithmetizationParams::SelectorColumns; s_index++) {
                    std::cout << "S" << s_index << ":";
                    profiling(assignments.selector(s_index));
                    std::cout << std::endl;
                }
            }
        }    // namespace blueprint
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_TABLE_PROFILING_HPP
