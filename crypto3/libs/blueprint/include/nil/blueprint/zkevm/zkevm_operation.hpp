//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <map>
#include <vector>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/zkevm/zkevm_circuit.hpp>
#include <nil/blueprint/zkevm/zkevm_machine_interface.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType>
        class zkevm_circuit;

        // interface class for generic zkevm operation
        template<typename BlueprintFieldType>
        class zkevm_operation {
        public:
            enum class gate_class {
                // gate on if the operation is first in the circuit
                FIRST_OP,
                // gate always on if the operation is executed
                MIDDLE_OP,
                // gate on if the operation is last in the circuit
                LAST_OP,
                // gate on if the operation is not last in the circuit
                NOT_LAST_OP
            };

            using zkevm_circuit_type = zkevm_circuit<BlueprintFieldType>;
            using constraint_type = nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using assignment_type = assignment<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;
            using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            zkevm_operation() {}

            virtual ~zkevm_operation() = default;
            // note that some parts of the map may be empty
            // we expect that most of the operations would only use MIDDLE_OP
            virtual std::map<gate_class, std::vector<constraint_type>> generate_gates(zkevm_circuit_type &zkevm_circuit) = 0;

            virtual void generate_assignments(zkevm_circuit_type &zkevm_circuit, zkevm_machine_interface &machine);
            // should return the same rows amount for everyс operation right now
            // here in case we would make it dynamic in the future
            virtual std::size_t rows_amount() = 0;
            // utility funciton
            static var var_gen(const std::vector<std::size_t> &witness_cols, std::size_t i, int32_t offset = 0) {
                return var(witness_cols[i], offset, true, var::column_type::witness);
            };
        };
    }   // namespace blueprint
}   // namespace nil
