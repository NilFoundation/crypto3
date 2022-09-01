//---------------------------------------------------------------------------//
// Copyright (c) 2020-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_CIRCUIT_PLONK_HPP
#define CRYPTO3_ZK_BLUEPRINT_CIRCUIT_PLONK_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {

            template<typename ArithmetizationType, std::size_t... BlueprintParams>
            class circuit;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            class circuit<zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public zk::snark::plonk_constraint_system<BlueprintFieldType> {

                typedef zk::snark::plonk_constraint_system<BlueprintFieldType> ArithmetizationType;

                struct component_selectors_info{
                    std::uint32_t first_selector_index;
                    std::uint32_t selectors_amount;
                }            

                using selector_map_type = std::map<
                    detail::blueprint_component_id_type, component_selectors_info>;
                selector_map_type selector_map;

                std::size_t next_selector_index = 0;

            public:
                typedef BlueprintFieldType blueprint_field_type;

                circuit(zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> &table_description) :
                    ArithmetizationType() {
                }

                // TODO: should put constraint in some storage and return its index
                zk::snark::plonk_constraint<BlueprintFieldType>
                    add_constraint(const zk::snark::plonk_constraint<BlueprintFieldType> &constraint) {
                    return constraint;
                }

                template <typename ComponentType>
                void add_gate(ComponentType &state,
                              std::size_t selector_index,
                              const zk::snark::plonk_constraint<BlueprintFieldType> &constraint) {
                    state.increase_gates_amount(1);
                    this->_gates.emplace_back(selector_index, constraint);
                }

                template <typename ComponentType>
                void add_gate(ComponentType &state,
                              std::size_t selector_index,
                              const std::initializer_list<zk::snark::plonk_constraint<BlueprintFieldType>> &constraints) {
                    state.increase_gates_amount(1);
                    this->_gates.emplace_back(selector_index, constraints);
                }

                template <typename ComponentType>
                void add_gate(ComponentType &state,
                              zk::snark::plonk_gate<BlueprintFieldType, zk::snark::plonk_constraint<BlueprintFieldType>> &gate) {
                    state.increase_gates_amount(1);
                    this->_gates.emplace_back(gate);
                }

                bool selector_is_allocated(const typename selector_map_type::iterator &selector_iterator) const{
                    return selector_iterator != selector_map.end();
                }

                template <typename ComponentType>
                selector_map_type::iterator find_selector(const ComponentType &state){

                    std::string component_id = get_component_id(state);
                    return selector_map.find(component_id);
                }

                template <typename ComponentType>
                std::size_t allocate_selector(const ComponentType &state,
                    std::size_t selectors_amount){

                    std::string component_id = get_component_id(state);

                    std::size_t selector_index = next_selector_index;
                    selector_map[component_id] = {selector_index, selectors_amount};
                    next_selector_index += selectors_amount;
                    return selector_index;
                }

                zk::snark::plonk_constraint<BlueprintFieldType>
                    add_bit_check(const zk::snark::plonk_variable<BlueprintFieldType> &bit_variable) {
                    return add_constraint(bit_variable * (bit_variable - 1));
                }

                void add_copy_constraint(const zk::snark::plonk_copy_constraint<BlueprintFieldType> &copy_constraint) {
                    if (copy_constraint.first == copy_constraint.second) {
                        return;
                    }
                    this->_copy_constraints.emplace_back(copy_constraint);
                }

                zk::snark::plonk_lookup_constraint<BlueprintFieldType>
                    add_lookup_constraint(std::vector<math::non_linear_term<zk::snark::plonk_variable<BlueprintFieldType>>> lookup_input, 
                    std::vector<zk::snark::plonk_variable<BlueprintFieldType>> lookup_value) {
                    zk::snark::plonk_lookup_constraint<BlueprintFieldType> lookup_constraint;
                    lookup_constraint.lookup_input = lookup_input;
                    lookup_constraint.lookup_value = lookup_value;
                    return lookup_constraint;
                }


                void add_lookup_gate(std::size_t selector_index,
                              const std::initializer_list<zk::snark::plonk_lookup_constraint<BlueprintFieldType>> &constraints) {
                    this->_lookup_gates.emplace_back(selector_index, constraints);
                }
            };
        }    // namespace blueprint
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_CIRCUIT_PLONK_HPP
