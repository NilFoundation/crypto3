//---------------------------------------------------------------------------//
// Copyright (c) 2023 Aleksei Kokoshnikov <alexeikokoshnikov@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_ASSIGNMENT_PROXY_PLONK_HPP
#define CRYPTO3_BLUEPRINT_ASSIGNMENT_PROXY_PLONK_HPP

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit_proxy.hpp>

namespace nil {
    namespace blueprint {
        template<typename ArithmetizationType, std::size_t... BlueprintParams>
        class assignment_proxy;

        template<typename BlueprintFieldType,
                typename ArithmetizationParams>
        class assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>>
        : public assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>> {

            typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams> ArithmetizationType;

            using value_type = typename BlueprintFieldType::value_type;
            using column_type = typename crypto3::zk::snark::plonk_column<BlueprintFieldType>;

            std::shared_ptr<assignment<ArithmetizationType>> assignment_ptr;
            std::shared_ptr<std::set<std::uint32_t>> shared_input_rows_ptr;
            std::uint32_t id;
            bool check;
            std::set<std::uint32_t> used_rows;
        public:

            assignment_proxy(std::shared_ptr<assignment<ArithmetizationType>> assignment,
                             std::shared_ptr<std::set<std::uint32_t>> shared_input,
                             std::uint32_t _id) :
                assignment_ptr(assignment),
                shared_input_rows_ptr(shared_input),
                id(_id),
                check(false) {
                assert(assignment_ptr);
                assert(shared_input_rows_ptr);
            }

            assignment_proxy() = delete;

            const assignment<ArithmetizationType>& get() const {
                return *assignment_ptr;
            }

            std::uint32_t get_id() const {
                return id;
            }

            void set_check(bool flag) {
                check = flag;
            }

            const std::set<std::uint32_t>& get_used_rows() const {
                return used_rows;
            }

            std::set<std::uint32_t>& get_shared_used_rows() {
                return *shared_input_rows_ptr;
            }

            const std::set<std::uint32_t>& get_shared_used_rows() const {
                return *shared_input_rows_ptr;
            }

            std::uint32_t rows_amount() const override {
                return assignment_ptr->rows_amount();
            }

            std::uint32_t allocated_rows() const override {
                return assignment_ptr->allocated_rows();
            }

            value_type &selector(std::size_t selector_index, std::uint32_t row_index) override {
                used_rows.insert(row_index);
                return assignment_ptr->selector(selector_index, row_index);
            }

            value_type selector(std::size_t selector_index, std::uint32_t row_index) const override {
                if (check && used_rows.find(row_index) == used_rows.end() && shared_input_rows_ptr->find(row_index) == shared_input_rows_ptr->end()) {
                    std::cout << id << ": Not found selector " << selector_index << " on row " << row_index << std::endl;
                    BLUEPRINT_ASSERT(false);
                }
                return std::const_pointer_cast<const assignment<ArithmetizationType>>(assignment_ptr)->selector(selector_index, row_index);
            }

            const column_type& selector(std::uint32_t index) const override {
                return assignment_ptr->selector(index);
            }

            std::uint32_t selector_column_size(std::uint32_t col_idx) const override {
                return assignment_ptr->selector_column_size(col_idx);
            }

            std::uint32_t selectors_amount() const override {
                return assignment_ptr->selectors_amount();
            }

            void enable_selector(const std::size_t selector_index, const std::size_t row_index) override {
                used_rows.insert(row_index);
                assignment_ptr->enable_selector(selector_index, row_index);
            }

            void enable_selector(const std::size_t selector_index,
                                 const std::size_t begin_row_index,
                                 const std::size_t end_row_index,
                                 const std::size_t index_step = 1) override {
                for (auto i = begin_row_index; i <= end_row_index; i = i + index_step) {
                    enable_selector(selector_index, i);
                }
            }

            value_type &witness(std::uint32_t witness_index, std::uint32_t row_index) override {
                used_rows.insert(row_index);
                return assignment_ptr->witness(witness_index, row_index);
            }

            value_type witness(std::uint32_t witness_index, std::uint32_t row_index) const override {
                if (check && used_rows.find(row_index) == used_rows.end() && shared_input_rows_ptr->find(row_index) == shared_input_rows_ptr->end()) {
                    std::cout << id << ": Not found witness " << witness_index << " on row " << row_index << std::endl;
                    BLUEPRINT_ASSERT(false);
                }
                return std::const_pointer_cast<const assignment<ArithmetizationType>>(assignment_ptr)->witness(witness_index, row_index);
            }

            std::uint32_t witnesses_amount() const override {
                return assignment_ptr->witnesses_amount();
            }

            std::uint32_t witness_column_size(std::uint32_t index) const override {
                return assignment_ptr->witness_column_size(index);
            }

            value_type &public_input(
                std::uint32_t public_input_index, std::uint32_t row_index) override {
                shared_input_rows_ptr->insert(row_index);
                return assignment_ptr->public_input(public_input_index, row_index);
            }

            value_type public_input(
                std::uint32_t public_input_index, std::uint32_t row_index) const override {
                if (check && used_rows.find(row_index) == used_rows.end() && shared_input_rows_ptr->find(row_index) == shared_input_rows_ptr->end()) {
                    std::cout << id << ": Not found public_input " << public_input_index << " on row " << row_index << std::endl;
                    BLUEPRINT_ASSERT(false);
                }
                return std::const_pointer_cast<const assignment<ArithmetizationType>>(assignment_ptr)->public_input(public_input_index, row_index);
            }

            std::uint32_t public_inputs_amount() const override {
                return assignment_ptr->public_inputs_amount();
            }

            std::uint32_t public_input_column_size(std::uint32_t index) const override {
                return assignment_ptr->public_input_column_size(index);
            }

            value_type &constant(
                std::uint32_t constant_index, std::uint32_t row_index) override {
                used_rows.insert(row_index);
                return assignment_ptr->constant(constant_index, row_index);
            }

            value_type constant(std::uint32_t constant_index, std::uint32_t row_index) const override {
                if (check && used_rows.find(row_index) == used_rows.end() && shared_input_rows_ptr->find(row_index) == shared_input_rows_ptr->end()) {
                    std::cout << id << ": Not found constant " << constant_index << " on row " << row_index << std::endl;
                    BLUEPRINT_ASSERT(false);
                }
                return std::const_pointer_cast<const assignment<ArithmetizationType>>(assignment_ptr)->constant(constant_index, row_index);
            }

            std::uint32_t constants_amount() const override {
                return assignment_ptr->constants_amount();
            }

            std::uint32_t constant_column_size(std::uint32_t index) const override {
                return assignment_ptr->constant_column_size(index);
            }

            value_type private_storage(std::uint32_t storage_index) const override {
                return assignment_ptr->private_storage(storage_index);
            }

            value_type &private_storage(std::uint32_t storage_index) override {
                return assignment_ptr->private_storage(storage_index);
            }

            // Not required to be called; get_private_storage will automatically resize
            // But you might want to use this to clear
            void resize_private_storage(std::uint32_t new_size) override {
                assignment_ptr->resize_private_storage(new_size);
            }

            void clear_private_storage() override {
                assignment_ptr->clear_private_storage();
            }

            std::size_t private_storage_size() const override {
                return assignment_ptr->private_storage_size();
            }

            void export_table(std::ostream& os, bool wide_export = false) const override {
                std::ios_base::fmtflags os_flags(os.flags());

                std::uint32_t witnesses_size = ArithmetizationParams::witness_columns;
                std::uint32_t public_size = ArithmetizationParams::public_input_columns;
                std::uint32_t constants_size = ArithmetizationParams::constant_columns;
                std::uint32_t selectors_size = ArithmetizationParams::selector_columns;

                os << "witnesses_size: " << witnesses_size << " "
                   << "public_inputs_size: " << public_size << " "
                   << "constants_size: " << constants_size << " "
                   << "selectors_size: " << selectors_size << " "
                   << "used rows: " << used_rows.size() << " "
                   << "used shared rows: " << shared_input_rows_ptr->size() << "\n";

                std::cout << "shared rows: ";
                for (const auto& it : *shared_input_rows_ptr) {
                    std::cout << it << " ";
                }
                std::cout << "\n";
                std::cout << "internal used rows: ";
                for (const auto& it : used_rows) {
                    std::cout << it << " ";
                }
                std::cout << "\n";

                os << std::dec;
                os << std::hex << std::setfill('0');
                std::uint32_t width = wide_export ? (BlueprintFieldType::modulus_bits + 4 - 1) / 4 : 0;

                std::set<std::uint32_t> all_rows;
                std::set_union(used_rows.begin(), used_rows.end(),
                               shared_input_rows_ptr->begin(), shared_input_rows_ptr->end(),
                               std::inserter(all_rows, all_rows.begin()));
                for (const auto& it : all_rows) {
                    std::cout << it << ": ";
                    for (std::uint32_t j = 0; j < witnesses_size; j++) {
                        os << std::setw(width)
                           << (it < assignment_ptr->witness_column_size(j) ?
                                    assignment_ptr->witness(j, it) : 0).data << " ";
                    }
                    os << "| ";
                    for (std::uint32_t j = 0; j < public_size; j++) {
                        os << std::setw(width)
                           << (it < assignment_ptr->public_input_column_size(j) ?
                           assignment_ptr->public_input(j, it) : 0).data << " ";
                    }
                    os << "| ";
                    for (std::uint32_t j = 0; j < constants_size; j++) {
                        os << std::setw(width)
                           << (it < assignment_ptr->constant_column_size(j) ?
                           assignment_ptr->constant(j, it) : 0).data << " ";
                    }
                    os << "| ";
                    // Selectors only need a single bit, so we do not renew the size here
                    for (std::uint32_t j = 0; j < selectors_size - 1; j++) {
                        os << (it < assignment_ptr->selector_column_size(j) ?
                               assignment_ptr->selector(j, it) : 0).data << " ";
                    }
                    os << "\n";
                }
                os.flush();
                os.flags(os_flags);
            }
        };

        template<typename BlueprintFieldType,
                typename ArithmetizationParams>
        typename BlueprintFieldType::value_type var_value(
                const assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>> &input_assignment,
                const crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &input_var) {
            using var_column_type =
                    typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>::column_type;
            using assignment_type =
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;
            // This SHOULD be handled by a separate variable type
            // But adding a new variable type breaks assigner
            // So we add a type without actually adding a type
            if (input_var.index == assignment_type::private_storage_index) {
                return input_assignment.private_storage(input_var.rotation);
            }
            switch(input_var.type){
                case var_column_type::witness:
                    return input_assignment.witness(input_var.index, input_var.rotation);
                case var_column_type::public_input:
                    return input_assignment.public_input(input_var.index, input_var.rotation);
                default:
                    return input_assignment.constant(input_var.index, input_var.rotation);
            }
        }

        template<typename BlueprintFieldType,
                typename ArithmetizationParams>
        void save_shared_var(
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>> &input_assignment,
                const crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &input_var) {
            input_assignment.get_shared_used_rows().insert(input_var.rotation);
        }

        template<typename BlueprintFieldType,
                typename ArithmetizationParams>
        bool is_accessible(const circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>> &bp,
                          const assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                  ArithmetizationParams>> &assignments){

            using variable_type = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            std::set<std::uint32_t> rows;
            const auto shared_rows = assignments.get_shared_used_rows();
            const auto private_rows = assignments.get_used_rows();
            rows.insert(shared_rows.begin(), shared_rows.end());
            rows.insert(private_rows.begin(), private_rows.end());

            const std::vector<crypto3::zk::snark::plonk_gate<BlueprintFieldType,
                              crypto3::zk::snark::plonk_constraint<BlueprintFieldType>>> &gates = bp.gates();
            const std::set<std::uint32_t>& used_gates = bp.get_used_gates();

            const std::vector<crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>> &copy_constraints =
                    bp.copy_constraints();
            const std::set<std::uint32_t>& used_copy_constraints = bp.get_used_copy_constraints();

            for (const auto& i : used_gates) {
                if (i >= gates.size()) {
                    std::cout << "No gate " << i << "\n";
                    return false;
                }

                std::uint32_t row_index = 0;
                crypto3::math::expression_for_each_variable_visitor<variable_type> visitor(
                        [&assignments, &row_index](const variable_type& var) {
                            BLUEPRINT_ASSERT((row_index + var.rotation) >= 0);
                            switch (var.type) {
                                case variable_type::column_type::witness:
                                    assignments.witness(var.index, row_index + var.rotation);
                                    return;
                                case variable_type::column_type::public_input:
                                    assignments.public_input(var.index, row_index + var.rotation);
                                    return;
                                case variable_type::column_type::constant:
                                    assignments.constant(var.index, row_index + var.rotation);
                                    return;
                                default:
                                    BLUEPRINT_ASSERT(false);
                                    return;
                            }
                        }
                );

                crypto3::zk::snark::plonk_column<BlueprintFieldType> selector =
                        assignments.selector(gates[i].selector_index);

                for (std::size_t selector_row = 0; selector_row < selector.size(); selector_row++) {
                    if (!selector[selector_row].is_zero() && rows.find(selector_row) != rows.end()) {
                        row_index = selector_row;
                        for (const auto& constraint : gates[i].constraints) {
                            visitor.visit(constraint);
                        }
                    }
                }
            }

            for (const auto& i : used_copy_constraints) {
                if (i >= copy_constraints.size()) {
                    std::cout << "No copy constraint " << i << "\n";
                    return false;
                }
                var_value(assignments, copy_constraints[i].first);
                var_value(assignments, copy_constraints[i].second);
            }

            return true;
        }

    }    // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_ASSIGNMENT_PROXY_PLONK_HPP
