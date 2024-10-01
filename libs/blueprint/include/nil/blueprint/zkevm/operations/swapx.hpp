//---------------------------------------------------------------------------//
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

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm/zkevm_operation.hpp>

namespace nil {
    namespace blueprint {
        template<typename BlueprintFieldType>
        class zkevm_operation;

        template<typename BlueprintFieldType>
        class zkevm_swapx_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using zkevm_table_type = typename op_type::zkevm_table_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

            zkevm_swapx_operation(std::size_t _x) : byte_count(_x) {
                BOOST_ASSERT(_x <= 16); // the maximum possible swap
                this->stack_input = _x+1;
                this->stack_output = _x+1;
            }

            std::size_t byte_count;

            std::map<gate_class, std::pair<
                std::vector<std::pair<std::size_t, constraint_type>>,
                std::vector<std::pair<std::size_t, lookup_constraint_type>>
                >>
                generate_gates(zkevm_circuit_type &zkevm_circuit) override {

                return {{gate_class::MIDDLE_OP, {{}, {}}}};
            }

            void generate_assignments(zkevm_table_type &zkevm_table, const zkevm_machine_interface &machine) override{
                std::cout << "Generate assignments for SWAPx opcodes" << std::endl;
            }

            std::size_t rows_amount() override {
                return 1;
            }
        };
    }   // namespace blueprint
}   // namespace nil
