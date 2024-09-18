//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#pragma once

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <ostream>

namespace nil {
    namespace blueprint {
        // It is really simplified state variable. We assume that each state position uses the whole column.
        // In this case variable is defined only by witness column id.
        // It's useful to have some convenient functions for rotations for circuit construction and absolute variables for assignment.
        template<typename BlueprintFieldType>
        struct state_var:public crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>{
            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            state_var(std::uint32_t witness_id = 0, typename var::column_type t = var::column_type::witness): var(witness_id, 0, true, t){}
            var operator() () const {
                return var(this->index, 0, true, this->type);
            }
            var next() const {
                return var(this->index, 1, true, this->type);
            }
            var prev() const {
                return var(this->index, -1, true, this->type);
            }
            var abs(std::size_t row) const {
                return var(this->index, row, false, this->type);
            }
        };
        // This class just contains state variables zkEVM state and next state
        // We'll write all state transition constraints directly in zkevm circuit.
        // All variables are named.
        // This data structure is filled only once by
        //     zkevm_circuit
        //     zkevm_table has it as a constant input.
        template<typename BlueprintFieldType>
        struct zkevm_vars {
            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            using state_var = state_var<BlueprintFieldType>;
        public:
            state_var pc;
            state_var stack_size;
            state_var memory_size;
            state_var gas;
            state_var opcode;

            state_var row_counter;           // Decreasing row counter
            state_var step_start;             // 1 in first line of new opcode, 0 otherwise
            state_var row_counter_inv;
            state_var last_row_indicator;   // Do we really need it? I don't think so. Last opcode should be RETURN, err or padding.
            state_var opcode_parity;        // opcode%2
            state_var is_even;              // TODO: Do it constant column
        };
    }    // namespace blueprint
}    // namespace nil
