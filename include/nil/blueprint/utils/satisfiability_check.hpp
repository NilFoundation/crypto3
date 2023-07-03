//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_UTILS_PLONK_SATISFIABILITY_CHECK_HPP
#define CRYPTO3_BLUEPRINT_UTILS_PLONK_SATISFIABILITY_CHECK_HPP

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType,
                 typename ArithmetizationParams>
        bool is_satisfied(circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                       ArithmetizationParams>> bp,
                          crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType,
                                                    ArithmetizationParams> assignments){

            const std::vector<crypto3::zk::snark::plonk_gate<BlueprintFieldType, crypto3::zk::snark::plonk_constraint<BlueprintFieldType>>> gates =
                        bp.gates();

            const std::vector<crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>> copy_constraints =
                        bp.copy_constraints();

            const std::vector<crypto3::zk::snark::plonk_gate<BlueprintFieldType, crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>>> lookup_gates =
                        bp.lookup_gates();

            for (std::size_t i = 0; i < gates.size(); i++) {
                crypto3::zk::snark::plonk_column<BlueprintFieldType> selector =
                    assignments.selector(gates[i].selector_index);

                for (std::size_t selector_row = 0; selector_row < selector.size(); selector_row++) {
                    if (!selector[selector_row].is_zero()) {
                        for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {

                            typename BlueprintFieldType::value_type constraint_result =
                                gates[i].constraints[j].evaluate(selector_row, assignments);

                            if (!constraint_result.is_zero()) {
                                std::cout << "Constraint " << j << " from gate " << i << "on row " << selector_row
                                          << " is not satisfied." << std::endl;
                                return false;
                            }
                        }
                    }
                }
            }

            for (std::size_t i = 0; i < copy_constraints.size(); i++) {
                if (var_value(assignments, copy_constraints[i].first) !=
                    var_value(assignments, copy_constraints[i].second)){
                    std::cout << "Copy constraint number " << i << " is not satisfied." << std::endl;
                    return false;
                }
            }

            return true;
        }

    }    // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_UTILS_PLONK_SATISFIABILITY_CHECK_HPP
