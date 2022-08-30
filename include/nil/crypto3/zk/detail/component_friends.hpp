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

#ifndef CRYPTO3_ZK_BLUEPRINT_DETAIL_COMPONENT_FRIENDS_HPP
#define CRYPTO3_ZK_BLUEPRINT_DETAIL_COMPONENT_FRIENDS_HPP

#include <typeinfo>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

#define DECLARE_BLUEPRINT_COMPONENT_FRIENDS( ComponentType , WitnessAmount) \
    template<typename BlueprintFieldType,\
         typename ArithmetizationParams>\
    typename ComponentType<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount>::result_type\
    generate_assignments(\
        const ComponentType<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount> &state,\
        blueprint_assignment_table<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,\
        const std::uint32_t start_row_index);\
    template<typename BlueprintFieldType,\
         typename ArithmetizationParams>\
    void generate_gates(\
        const ComponentType<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount> &state,\
        blueprint<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,\
        blueprint_public_assignment_table<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,\
        const std::uint32_t first_selector_index);\
    template<typename BlueprintFieldType,\
         typename ArithmetizationParams>\
    void generate_copy_constraints(\
        const ComponentType<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount> &state,\
        blueprint<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,\
        blueprint_public_assignment_table<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,\
        const std::uint32_t start_row_index);\
    template<typename BlueprintFieldType,\
         typename ArithmetizationParams>\
    typename ComponentType<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount>::result_type\
        generate_circuit1(\
        const ComponentType<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount> &state,\
        blueprint<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,\
        blueprint_public_assignment_table<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,\
        const std::uint32_t start_row_index);

#define INCLASS_BLUEPRINT_COMPONENT_GENERATE_ASSIGNMENTS_FRIEND(ComponentType, BlueprintFieldType, ArithmetizationParams, WitnessAmount) \
    typename ComponentType<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount>::result_type\
        generate_assignments<BlueprintFieldType, ArithmetizationParams>(\
        const ComponentType<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount> &state,\
        blueprint_assignment_table<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,\
        const std::uint32_t start_row_index);

#define INCLASS_BLUEPRINT_COMPONENT_GENERATE_GATES_FRIEND(ComponentType, BlueprintFieldType, ArithmetizationParams, WitnessAmount) \
    void generate_gates<BlueprintFieldType, ArithmetizationParams>(\
        const ComponentType<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount> &state,\
        blueprint<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,\
        blueprint_public_assignment_table<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,\
        const std::uint32_t first_selector_index);

#define INCLASS_BLUEPRINT_COMPONENT_GENERATE_COPY_CONSTRAINTS_FRIEND(ComponentType, BlueprintFieldType, ArithmetizationParams, WitnessAmount) \
    void generate_copy_constraints<BlueprintFieldType, ArithmetizationParams>(\
        const ComponentType<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount> &state,\
        blueprint<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,\
        blueprint_public_assignment_table<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,\
        const std::uint32_t start_row_index);

#define INCLASS_BLUEPRINT_COMPONENT_GENERATE_CIRCUIT_FRIEND(ComponentType, BlueprintFieldType, ArithmetizationParams, WitnessAmount) \
    typename ComponentType<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount>::result_type\
        generate_circuit1<BlueprintFieldType, ArithmetizationParams>(\
        const ComponentType<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessAmount> &state,\
        blueprint<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,\
        blueprint_public_assignment_table<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,\
        const std::uint32_t start_row_index);

            }    // namespace components
        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_DETAIL_COMPONENT_FRIENDS_HPP
