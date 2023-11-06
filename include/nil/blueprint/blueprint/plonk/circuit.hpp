//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_CIRCUIT_PLONK_HPP
#define CRYPTO3_BLUEPRINT_CIRCUIT_PLONK_HPP

#include <map>

#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/lookup_library.hpp>

namespace nil {
    namespace blueprint {

        template<typename ArithmetizationType, std::size_t... BlueprintParams>
        class circuit;

        template<typename ArithmetizationType, std::size_t... BlueprintParams>
        class assignment;

        template<typename BlueprintFieldType,
                 typename ArithmetizationParams>
        class circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                       ArithmetizationParams>>
            : public crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                    ArithmetizationParams> {

            typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                   ArithmetizationParams> ArithmetizationType;

        private:
            using gate_id_type = gate_id<BlueprintFieldType, ArithmetizationParams>;
            using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using gate_selector_map = std::map<gate_id_type, std::size_t>;
            using gate_type = crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;

            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using lookup_gate_type = crypto3::zk::snark::plonk_lookup_gate<BlueprintFieldType, lookup_constraint_type>;
            using lookup_gate_id_type = lookup_gate_id<BlueprintFieldType, ArithmetizationParams>;
            using lookup_gate_selector_map = std::map<lookup_gate_id_type, std::size_t>;

            using lookup_table_definition = typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;

            gate_selector_map selector_map = {};
            lookup_gate_selector_map lookup_selector_map = {};
            std::size_t next_selector_index = 0;
        protected:
            lookup_library<BlueprintFieldType> _lookup_library;
        public:
            typedef BlueprintFieldType blueprint_field_type;

            circuit(crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams> constraint_system) :
                    ArithmetizationType(constraint_system) { }

            circuit() : ArithmetizationType() {}

            virtual const typename ArithmetizationType::gates_container_type& gates() const {
                return ArithmetizationType::gates();
            }

            virtual const typename ArithmetizationType::copy_constraints_container_type& copy_constraints() const {
                return ArithmetizationType::copy_constraints();
            }

            virtual const typename ArithmetizationType::lookup_gates_container_type& lookup_gates() const {
                return ArithmetizationType::lookup_gates();
            }

            virtual const typename ArithmetizationType::lookup_tables_type& lookup_tables() const {
                return ArithmetizationType::lookup_tables();
            }

            virtual std::size_t num_gates() const {
                return ArithmetizationType::num_gates();
            }

            virtual std::size_t num_lookup_gates() const {
                return ArithmetizationType::num_lookup_gates();
            }

            #define GENERIC_GATE_ADDER_MACRO(mapping, gate_container) \
                auto it = mapping.find(gate_id); \
                if (it != mapping.end()) { \
                    return it->second; \
                } else { \
                    std::size_t selector_index = next_selector_index; \
                    mapping[gate_id] = selector_index; \
                    this->gate_container.emplace_back(selector_index, args); \
                    next_selector_index++; \
                    return selector_index; \
                }

            #define GATE_ADDER_MACRO(mapping, gate_container) \
                auto gate_id = gate_id_type(args); \
                GENERIC_GATE_ADDER_MACRO(mapping, gate_container)

            #define LOOKUP_GATE_ADDER_MACRO(mapping, gate_container) \
                auto gate_id = lookup_gate_id_type(args); \
                GENERIC_GATE_ADDER_MACRO(mapping, gate_container)

            virtual std::size_t add_gate(const std::vector<constraint_type> &args) {
                GATE_ADDER_MACRO(selector_map, _gates);
            }

            virtual std::size_t add_gate(const constraint_type &args) {
                GATE_ADDER_MACRO(selector_map, _gates);
            }

            virtual std::size_t add_gate(const std::initializer_list<constraint_type> &&args) {
                GATE_ADDER_MACRO(selector_map, _gates);
            }

            virtual std::size_t add_lookup_gate(const std::vector<lookup_constraint_type> &args) {
                LOOKUP_GATE_ADDER_MACRO(lookup_selector_map, _lookup_gates);
            }

            virtual std::size_t add_lookup_gate(const lookup_constraint_type &args) {
                LOOKUP_GATE_ADDER_MACRO(lookup_selector_map, _lookup_gates);
            }

            virtual std::size_t add_lookup_gate(const std::initializer_list<lookup_constraint_type> &&args) {
                LOOKUP_GATE_ADDER_MACRO(lookup_selector_map, _lookup_gates);
            }

            virtual const typename ArithmetizationType::lookup_table_type &lookup_table(std::size_t table_id) const {
                return ArithmetizationType::lookup_table(table_id);
            }

            virtual void add_lookup_table(const typename ArithmetizationType::lookup_table_type &table) {
                ArithmetizationType::add_lookup_table(table);
            }

            virtual void register_lookup_table(std::shared_ptr<lookup_table_definition> table) {
                _lookup_library.register_lookup_table(table);
            }

            virtual void reserve_table(std::string name){
                _lookup_library.reserve_table(name);
            }

            virtual const typename lookup_library<BlueprintFieldType>::left_reserved_type
                    &get_reserved_indices() const {
                return _lookup_library.get_reserved_indices().left;
            }

            // used in satisfiability check
            virtual const typename lookup_library<BlueprintFieldType>::right_reserved_type
                    &get_reserved_indices_right() const {
                return _lookup_library.get_reserved_indices().right;
            }

            virtual const std::map<std::string, std::shared_ptr<lookup_table_definition>> &get_reserved_tables() {
                return _lookup_library.get_reserved_tables();
            }

            #undef GATE_ADDER_MACRO
            #undef LOOKUP_GATE_ADDER_MACRO
            #undef GENERIC_GATE_ADDER_MACRO

            virtual void add_copy_constraint(const crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType> &copy_constraint) {
                static const std::size_t private_storage_index =
                    assignment<crypto3::zk::snark::plonk_constraint_system<
                        BlueprintFieldType, ArithmetizationParams>>::private_storage_index;
                if (copy_constraint.first == copy_constraint.second) {
                    return;
                }
                if (copy_constraint.first.index == private_storage_index ||
                    copy_constraint.second.index == private_storage_index) {
                    return;
                }
                this->_copy_constraints.emplace_back(copy_constraint);
            }

            virtual std::size_t get_next_selector_index() const {
                return next_selector_index;
            }

            virtual void export_circuit(std::ostream& os) const {
                std::ios_base::fmtflags os_flags(os.flags());
                std::size_t gates_size = this->_gates.size(),
                            copy_constraints_size = this->_copy_constraints.size(),
                            lookup_gates_size = this->_lookup_gates.size();
                os << "gates_size: " << gates_size << " "
                   << "copy_constraints_size: " << copy_constraints_size << " "
                   << "lookup_gates_size: " << lookup_gates_size << "\n";
                for (std::size_t i = 0; i < gates_size; i++) {
                    os << "selector: " << this->_gates[i].selector_index
                       << " constraints_size: " << this->_gates[i].constraints.size() << "\n";
                    for (std::size_t j = 0; j < this->_gates[i].constraints.size(); j++) {
                        os << this->_gates[i].constraints[j] << "\n";
                    }
                }
                for (std::size_t i = 0; i < copy_constraints_size; i++) {
                    os << this->_copy_constraints[i].first << " "
                       << this->_copy_constraints[i].second << "\n";
                }
                os.flush();
                os.flags(os_flags);
            }
        };
    }    // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_CIRCUIT_PLONK_HPP
