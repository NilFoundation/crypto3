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

                using component_selector_map_type = std::unordered_map<
                    detail::blueprint_component_id_type, std::vector<std::int32_t>>;

                component_selector_map_type component_selector_map;

                std::int32_t _next_selector_global_index = 0;

                std::int32_t next_selector_global_index(){
                    return _next_selector_global_index++;
                }

            public:
                typedef BlueprintFieldType blueprint_field_type;

                circuit(zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> &table_description) :
                    ArithmetizationType() {
                }

                template <typename ComponentType>
                void add_gate(ComponentType &component_instance,
                              std::size_t selector_serial_number,
                              const std::initializer_list<zk::snark::plonk_constraint<BlueprintFieldType>> constraints) {

                    detail::blueprint_component_id_type component_instance_id =
                        detail::get_component_id(component_instance);

                    typename component_selector_map_type::const_iterator found = component_selector_map.find(
                        component_instance_id);

                    // Component add_gate is being called for the first time
                    if (found == component_selector_map.end()){
                        component_selector_map[component_instance_id] = component_selector_map_type::value_type(
                            selector_serial_number + 1, -1);
                    }

                    // Selector index container resize with default values
                    if (find->second[selector_serial_number].size < selector_serial_number + 1){
                        find->second[selector_serial_number].resize(selector_serial_number + 1, -1);
                    }

                    // Selector with such serial number hasn't been added yet
                    if (find->second[selector_serial_number] == -1){
                        find->second[selector_serial_number] = next_selector_global_index();

                        this->_gates.emplace_back(find->second[selector_serial_number], constraints);
                    }
                }

                template <typename ComponentType>
                void add_gate(ComponentType &component_instance,
                              std::size_t selector_serial_number,
                              const zk::snark::plonk_constraint<BlueprintFieldType> constraint) {

                    add_gate(component_instance, selector_serial_number, {constraint});
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
