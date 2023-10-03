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
            using gate_selector_map = std::map<
                gate_id_type,
                std::size_t>;
            using gate_type =
                crypto3::zk::snark::plonk_gate<
                    BlueprintFieldType,
                    crypto3::zk::snark::plonk_constraint<BlueprintFieldType>>;
            using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

            gate_selector_map selector_map = {};
            std::size_t next_selector_index = 0;

        public:
            typedef BlueprintFieldType blueprint_field_type;

            circuit(crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams> constraint_system) :
                    ArithmetizationType(constraint_system) { }

            circuit() : ArithmetizationType() {}

            #define gate_adder_macro \
                gate_id_type gate_id = gate_id_type(args); \
                auto it = selector_map.find(gate_id); \
                if (it != selector_map.end()) { \
                    return it->second; \
                } else { \
                    std::size_t selector_index = next_selector_index; \
                    selector_map[gate_id] = selector_index; \
                    this->_gates.emplace_back(selector_index, args); \
                    next_selector_index++; \
                    return selector_index; \
                }

            template <typename GateArguments>
            std::size_t add_gate(const GateArguments &args) {
                gate_adder_macro;
            }

            std::size_t add_gate(const std::initializer_list<constraint_type> &&args) {
                gate_adder_macro;
            }

            #undef gate_adder_macro

            void add_copy_constraint(const crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType> &copy_constraint) {
                static std::size_t private_storage_index =
                    assignment<crypto3::zk::snark::plonk_constraint_system<
                        BlueprintFieldType, ArithmetizationParams>>::PRIVATE_STORAGE_INDEX;
                if (copy_constraint.first == copy_constraint.second) {
                    return;
                }
                if (copy_constraint.first.index == private_storage_index ||
                    copy_constraint.second.index == private_storage_index) {
                    return;
                }
                this->_copy_constraints.emplace_back(copy_constraint);
            }

            void export_circuit(std::ostream& os) const {
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
