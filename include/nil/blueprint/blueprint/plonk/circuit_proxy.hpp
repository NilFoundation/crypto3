//---------------------------------------------------------------------------//
// Copyright (c) 2023 Kokoshnikov Aleksei <alexeikokoshnikov@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_CIRCUIT_PROXY_PLONK_HPP
#define CRYPTO3_BLUEPRINT_CIRCUIT_PROXY_PLONK_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>

namespace nil {
    namespace blueprint {

        template<typename ArithmetizationType, std::size_t... BlueprintParams>
        class circuit_proxy;

        template<typename ArithmetizationType, std::size_t... BlueprintParams>
        class assignment;

        template<typename BlueprintFieldType,
                 typename ArithmetizationParams>
        class circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                       ArithmetizationParams>>
            : public circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                       ArithmetizationParams>> {

            typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                   ArithmetizationParams> ArithmetizationType;

        private:
            using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using lookup_table_definition = typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;

            std::uint32_t id;
            std::shared_ptr<circuit<ArithmetizationType>> circuit_ptr;
            std::set<std::uint32_t> used_gates;
            std::set<std::uint32_t> used_copy_constraints;
            std::set<std::uint32_t> used_lookup_gates;
            std::set<std::uint32_t> used_lookup_tables;

            std::uint32_t get_gate_index(std::size_t selector_index) const {
                const auto& gates = circuit_ptr->gates();
                auto it = std::find_if(gates.begin(), gates.end(), [selector_index](const typename ArithmetizationType::gates_container_type::value_type& gate) -> bool
                    { return selector_index == gate.selector_index; });
                return it - gates.begin();
            }

            std::uint32_t get_lookup_gate_index(std::size_t selector_index) const {
                const auto& lookup_gates = circuit_ptr->lookup_gates();
                auto it = std::find_if(lookup_gates.begin(), lookup_gates.end(),
                                       [selector_index](const typename ArithmetizationType::lookup_gates_container_type::value_type& lookup_gate) -> bool
                { return selector_index == lookup_gate.tag_index; });
                return it - lookup_gates.begin();
            }

        public:

            circuit_proxy(std::shared_ptr<circuit<ArithmetizationType>> circuit, std::uint32_t _id) :
                    circuit_ptr(circuit),
                    id(_id) {}

            circuit_proxy() = delete;

            const circuit<ArithmetizationType>& get() const {
                return *circuit_ptr;
            }

            circuit<ArithmetizationType>& get() {
                return *circuit_ptr;
            }

            std::uint32_t get_id() const {
                return id;
            }

            const std::set<std::uint32_t>& get_used_gates() const {
                return used_gates;
            }

            const typename ArithmetizationType::gates_container_type& gates() const override {
                return circuit_ptr->gates();
            }

            const std::set<std::uint32_t>& get_used_copy_constraints() const {
                return used_copy_constraints;
            }

            const typename ArithmetizationType::copy_constraints_container_type& copy_constraints() const override {
                return circuit_ptr->copy_constraints();
            }

            const std::set<std::uint32_t>& get_used_lookup_gates() const {
                return used_lookup_gates;
            }

            const typename ArithmetizationType::lookup_gates_container_type& lookup_gates() const override {
                return circuit_ptr->lookup_gates();
            }

            const std::set<std::uint32_t>& get_used_lookup_tables() const {
                return used_lookup_tables;
            }

            const typename ArithmetizationType::lookup_tables_type& lookup_tables() const override {
                return circuit_ptr->lookup_tables();
            }

            std::size_t num_gates() const override {
                return circuit_ptr->num_gates();
            }

            std::size_t num_lookup_gates() const override {
                return circuit_ptr->num_lookup_gates();
            }

            std::size_t add_gate(const std::vector<constraint_type> &args) override {
                const auto selector_index = circuit_ptr->add_gate(args);
                used_gates.insert(get_gate_index(selector_index));
                return selector_index;
            }

            std::size_t add_gate(const constraint_type &args) override {
                const auto selector_index = circuit_ptr->add_gate(args);
                used_gates.insert(get_gate_index(selector_index));
                return selector_index;
            }

            std::size_t add_gate(const std::initializer_list<constraint_type> &&args) override {
                const auto selector_index = circuit_ptr->add_gate(args);
                used_gates.insert(get_gate_index(selector_index));
                return selector_index;
            }

            std::size_t add_lookup_gate(const std::vector<lookup_constraint_type> &args) override {
                const auto selector_index = circuit_ptr->add_lookup_gate(args);
                used_lookup_gates.insert(get_lookup_gate_index(selector_index));
                return selector_index;
            }

            std::size_t add_lookup_gate(const lookup_constraint_type &args) override {
                const auto selector_index = circuit_ptr->add_lookup_gate(args);
                used_lookup_gates.insert(get_lookup_gate_index(selector_index));
                return selector_index;
            }

            std::size_t add_lookup_gate(const std::initializer_list<lookup_constraint_type> &&args) override {
                const auto selector_index = circuit_ptr->add_lookup_gate(args);
                used_lookup_gates.insert(get_lookup_gate_index(selector_index));
                return selector_index;
            }

            const typename ArithmetizationType::lookup_table_type &lookup_table(std::size_t table_id) const override {
                return circuit_ptr->lookup_table(table_id);
            }

            void add_lookup_table(const typename ArithmetizationType::lookup_table_type &table) override {
                circuit_ptr->add_lookup_table(table);
            }

            void register_lookup_table(std::shared_ptr<lookup_table_definition> table) override {
                circuit_ptr->register_lookup_table(table);
            }

            void reserve_table(std::string name) override {
                circuit_ptr->reserve_table(name);
                const auto idx = circuit_ptr->get_reserved_indices().at(name) - 1;
                used_lookup_tables.insert(idx);
            }

            const typename lookup_library<BlueprintFieldType>::left_reserved_type
                    &get_reserved_indices() const override {
                return circuit_ptr->get_reserved_indices();
            }

            const typename lookup_library<BlueprintFieldType>::right_reserved_type &
                    get_reserved_indices_right() const override {
                return circuit_ptr->get_reserved_indices_right();
            }

            const std::map<std::string, std::shared_ptr<lookup_table_definition>> &get_reserved_tables() const override {
                return circuit_ptr->get_reserved_tables();
            }

            void add_copy_constraint(const crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType> &copy_constraint) override {
                circuit_ptr->add_copy_constraint(copy_constraint);
                if (circuit_ptr->copy_constraints().size() > 0) {
                    used_copy_constraints.insert(circuit_ptr->copy_constraints().size() - 1);
                }
            }

            std::size_t get_next_selector_index() const override {
                return circuit_ptr->get_next_selector_index();
            }

            void export_circuit(std::ostream& os) const override {
                std::ios_base::fmtflags os_flags(os.flags());

                const auto gates = circuit_ptr->gates();
                const auto copy_constraints = circuit_ptr->copy_constraints();
                const auto lookup_gates = circuit_ptr->lookup_gates();
                const auto lookup_tables = circuit_ptr->lookup_tables();
                const auto lookup_table_indexes = circuit_ptr->get_reserved_indices();

                os << "used_gates_size: " << used_gates.size() << " "
                   << "gates_size: " << gates.size() << " "
                   << "used_copy_constraints_size: " << used_copy_constraints.size() << " "
                   << "copy_constraints_size: " << copy_constraints.size() << " "
                   << "lookup_gates_size: " << used_lookup_gates.size() << "\n";

                for (const auto& i : used_gates) {
                    os << i << ": selector: " << gates[i].selector_index
                       << " constraints_size: " << gates[i].constraints.size() << "\n";
                    for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                        os << gates[i].constraints[j] << "\n";
                    }
                }

                for (const auto& i : used_copy_constraints) {
                    os << i << ": " << copy_constraints[i].first << " "
                       << copy_constraints[i].second << "\n";
                }

                std::cout << "\nlookup gates:\n";
                for (const auto& i : used_lookup_gates) {
                    os << i << ": selector: " << lookup_gates[i].tag_index
                       << " lookup constraints size: " << lookup_gates[i].constraints.size() << "\n";
                    for (std::size_t j = 0; j < lookup_gates[i].constraints.size(); j++) {
                        os << "constraints size: " << lookup_gates[i].constraints[j].lookup_input.size() << "\n";
                        os << "table index: " << lookup_gates[i].constraints[j].table_id << "\n";
                        for (std::size_t k = 0; k < lookup_gates[i].constraints[j].lookup_input.size(); k++) {
                            os << lookup_gates[i].constraints[j].lookup_input[k] << "\n";
                        }
                        std::cout << "\n";
                    }
                    std::cout << "\n";
                }

                std::cout << "\nlookup tables:\n";
                for (const auto& i : used_lookup_tables) {
                    bool found = false;
                    for (const auto it : lookup_table_indexes) {
                        if (it.second == (i + 1)) {
                            os << i << ": " << it.first << "\n";
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        os << i << ": not found\n";
                    }
                }

                os.flush();
                os.flags(os_flags);
            }
        };
    }    // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_CIRCUIT_PROXY_PLONK_HPP
