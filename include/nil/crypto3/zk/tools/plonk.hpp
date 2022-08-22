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

#ifndef CRYPTO3_ZK_BLUEPRINT_TOOLS_PLONK_HPP
#define CRYPTO3_ZK_BLUEPRINT_TOOLS_PLONK_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            bool is_satisfied(blueprint<snark::plonk_constraint_system<BlueprintFieldType,
                                                           ArithmetizationParams>> bp,
                              snark::plonk_assignment_table<BlueprintFieldType,
                                                        ArithmetizationParams> assignments){

                const std::vector<snark::plonk_gate<BlueprintFieldType, snark::plonk_constraint<BlueprintFieldType>>> gates =
                            bp.gates();

                for (std::size_t i = 0; i < gates.size(); i++) {
                    snark::plonk_column<BlueprintFieldType> selector = assignments.selector(gates[i].selector_index);

                    for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {

                        for (std::size_t selector_row = 0; selector_row < selector.size(); selector_row++){
                            if (!selector[selector_row].is_zero()){

                                typename BlueprintFieldType::value_type constraint_result =
                                    gates[i].constraints[j].evaluate(selector_row, assignments);
                                    
                                if (!constraint_result.is_zero()) {
                                    // std::cout << "constraint " << j << " from gate " << i << "on row " << std::endl;
                                    return false;
                                }
                            }
                        }
                    }
                }

                return true;
            }

        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_TOOLS_PLONK_HPP
