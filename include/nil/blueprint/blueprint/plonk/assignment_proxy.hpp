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

        private:
            std::shared_ptr<assignment<ArithmetizationType>> assignment_ptr;
            std::uint32_t id;
            bool check;
            std::set<std::uint32_t> used_rows;
            std::set<std::uint32_t> used_selector_rows;
        public:
            assignment_proxy(std::shared_ptr<assignment<ArithmetizationType>> assignment,
                             std::uint32_t _id) :
                assignment_ptr(assignment),
                id(_id),
                check(false) {
                assert(assignment_ptr);
            }

            assignment_proxy() = delete;

            const assignment<ArithmetizationType>& get() const {
                return *assignment_ptr;
            }

            assignment<ArithmetizationType>& get() {
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

            const std::set<std::uint32_t>& get_used_selector_rows() const {
                return used_selector_rows;
            }

            std::uint32_t rows_amount() const override {
                return assignment_ptr->rows_amount();
            }

            std::uint32_t allocated_rows() const override {
                return assignment_ptr->allocated_rows();
            }

            value_type &selector(std::size_t selector_index, std::uint32_t row_index) override {
                used_rows.insert(row_index);
                used_selector_rows.insert(row_index);
                return assignment_ptr->selector(selector_index, row_index);
            }

            value_type selector(std::size_t selector_index, std::uint32_t row_index) const override {
                if (check) {
                    const auto lookup_selector_cols = assignment_ptr->get_lookup_selector_cols();
                    if (lookup_selector_cols.find(selector_index) == lookup_selector_cols.end() &&
                        used_selector_rows.find(row_index) == used_selector_rows.end()) {
                        std::cout << id << ": Not found selector " << selector_index << " on row " << row_index << std::endl;
                        BLUEPRINT_ASSERT(false);
                    }
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
                used_selector_rows.insert(row_index);
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

            void fill_selector(std::uint32_t index, const column_type& column) override {
                assignment_ptr->fill_selector(index, column);
            }

            const std::set<std::uint32_t>& get_lookup_selector_cols() const override {
                return assignment_ptr->get_lookup_selector_cols();
            }

            std::uint32_t get_lookup_selector_amount() const override {
                return assignment_ptr->get_lookup_selector_amount();
            }

            value_type &shared(std::uint32_t shared_index, std::uint32_t row_index) override {
                return assignment_ptr->shared(shared_index, row_index);
            }

            value_type shared(std::uint32_t shared_index, std::uint32_t row_index) const override{
                if (check && row_index >= assignment_ptr->shared_column_size(shared_index)) {
                    std::cout << id << ": Not found shared " << shared_index << " on row " << row_index << std::endl;
                    BLUEPRINT_ASSERT(false);
                }
                return std::const_pointer_cast<const assignment<ArithmetizationType>>(assignment_ptr)->shared(shared_index, row_index);
            }

            std::uint32_t shared_column_size(std::uint32_t index) const override {
                return assignment_ptr->shared_column_size(index);
            }

            const column_type& shared(std::uint32_t index) const override {
                return assignment_ptr->shared(index);
            }

            std::uint32_t shareds_amount() const override {
                return assignment_ptr->shareds_amount();
            }

            value_type &witness(std::uint32_t witness_index, std::uint32_t row_index) override {
                used_rows.insert(row_index);
                return assignment_ptr->witness(witness_index, row_index);
            }

            value_type witness(std::uint32_t witness_index, std::uint32_t row_index) const override {
                if (check && used_rows.find(row_index) == used_rows.end()) {
                    std::cout << id << ": Not found witness " << witness_index << " on row " << row_index << std::endl;
                    BLUEPRINT_ASSERT(false);
                }
                return std::const_pointer_cast<const assignment<ArithmetizationType>>(assignment_ptr)->witness(witness_index, row_index);
            }

            const column_type& witness(std::uint32_t index) const override {
                return assignment_ptr->witness(index);
            }

            std::uint32_t witnesses_amount() const override {
                return assignment_ptr->witnesses_amount();
            }

            std::uint32_t witness_column_size(std::uint32_t index) const override {
                return assignment_ptr->witness_column_size(index);
            }

            value_type &public_input(
                std::uint32_t public_input_index, std::uint32_t row_index) override {
                return assignment_ptr->public_input(public_input_index, row_index);
            }

            value_type public_input(
                std::uint32_t public_input_index, std::uint32_t row_index) const override {
                return std::const_pointer_cast<const assignment<ArithmetizationType>>(assignment_ptr)->public_input(public_input_index, row_index);
            }

            const column_type& public_input(std::uint32_t index) const override {
                return assignment_ptr->public_input(index);
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
                if (check) {
                    const auto lookup_constant_cols = assignment_ptr->get_lookup_constant_cols();
                    if (lookup_constant_cols.find(constant_index) == lookup_constant_cols.end() &&
                        used_rows.find(row_index) == used_rows.end()) {
                        std::cout << id << ": Not found constant " << constant_index << " on row " << row_index << std::endl;
                        BLUEPRINT_ASSERT(false);
                    }
                }
                return std::const_pointer_cast<const assignment<ArithmetizationType>>(assignment_ptr)->constant(constant_index, row_index);
            }

            std::uint32_t constants_amount() const override {
                return assignment_ptr->constants_amount();
            }

            std::uint32_t constant_column_size(std::uint32_t index) const override {
                return assignment_ptr->constant_column_size(index);
            }

            void fill_constant(std::uint32_t index, const column_type& column) override {
                assignment_ptr->fill_constant(index, column);
            }

            const column_type& constant(std::uint32_t index) const override {
                return assignment_ptr->constant(index);
            }

            const std::set<std::uint32_t>& get_lookup_constant_cols() const override {
                return assignment_ptr->get_lookup_constant_cols();
            }

            std::uint32_t get_lookup_constant_amount() const override {
                return assignment_ptr->get_lookup_constant_amount();
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

                std::uint32_t witnesses_size = witnesses_amount();
                std::uint32_t shared_size = shareds_amount();
                std::uint32_t public_size = public_inputs_amount();
                std::uint32_t constants_size = constants_amount();
                std::uint32_t selectors_size = selectors_amount();

                std::uint32_t max_size = 0,
                        max_witnesses_size = 0,
                        max_shared_size = 0,
                        max_public_inputs_size = 0,
                        max_constants_size = 0,
                        max_selectors_size = 0;
                for (std::uint32_t i = 0; i < witnesses_size; i++) {
                    max_witnesses_size = std::max(max_witnesses_size, witness_column_size(i));
                }
                for (std::uint32_t i = 0; i < shared_size; i++) {
                    max_shared_size = std::max(max_shared_size, shared_column_size(i));
                }
                for (std::uint32_t i = 0; i < public_size; i++) {
                    max_public_inputs_size = std::max(max_public_inputs_size, public_input_column_size(i));
                }
                for (std::uint32_t i = 0; i < constants_size; i++) {
                    max_constants_size = std::max(max_constants_size, constant_column_size(i));
                }
                for (std::uint32_t i = 0; i < selectors_size; i++) {
                    max_selectors_size = std::max(max_selectors_size, selector_column_size(i));
                }

                max_size = std::max({max_witnesses_size,
                                     max_public_inputs_size,
                                     max_constants_size,
                                     max_selectors_size});

                os << "witnesses_size: " << witnesses_size << " "
                   << "shared_size: " << shared_size << " "
                   << "public_inputs_size: " << public_size << " "
                   << "constants_size: " << constants_size << " "
                   << "selectors_size: " << selectors_size << " "
                   << "max_size: " << max_size << " "
                   << "internal used rows size: " << used_rows.size() << "\n";

                os << "internal used rows: ";
                for (const auto& it : used_rows) {
                    os << it << " ";
                }
                os << "\n";

                os << "internal used selector rows: ";
                for (const auto& it : used_selector_rows) {
                    os << it << " ";
                }
                os << "\n";

                os << "lookup constants: ";
                for (const auto &it : assignment_ptr->get_lookup_constant_cols()) {
                    os << it << " ";
                }
                os << "\n";

                os << "lookup selectors: ";
                for (const auto &it : assignment_ptr->get_lookup_selector_cols()) {
                    os << it << " ";
                }
                os << "\n";

                os << std::dec;
                os << std::hex << std::setfill('0');
                std::uint32_t width = wide_export ? (BlueprintFieldType::modulus_bits + 4 - 1) / 4 : 0;

                for (std::uint32_t i = 0; i < max_size; i++) {
                    os << i << ": ";
                    const auto is_used_row = used_rows.find(i) != used_rows.end();
                    for (std::uint32_t j = 0; j < witnesses_size; j++) {
                        os << std::setw(width)
                           << (i < assignment_ptr->witness_column_size(j) && is_used_row ?
                                    assignment_ptr->witness(j, i) : 0).data << " ";
                    }
                    os << "| ";
                    for (std::uint32_t j = 0; j < shared_size; j++) {
                        os << std::setw(width)
                        << (i < shared_column_size(j) ?
                        shared(j, i) : 0).data << " ";
                    }
                    os << "| ";
                    for (std::uint32_t j = 0; j < public_size; j++) {
                        os << std::setw(width)
                           << (i < assignment_ptr->public_input_column_size(j) ?
                           assignment_ptr->public_input(j, i) : 0).data << " ";
                    }
                    os << "| ";
                    for (std::uint32_t j = 0; j < constants_size; j++) {
                        os << std::setw(width)
                           << (i < assignment_ptr->constant_column_size(j) ?
                           assignment_ptr->constant(j, i) : 0).data << " ";
                    }
                    os << "| ";
                    // Selectors only need a single bit, so we do not renew the size here
                    for (std::uint32_t j = 0; j < selectors_size - 1; j++) {
                        os << (i < assignment_ptr->selector_column_size(j) ?
                               assignment_ptr->selector(j, i) : 0).data << " ";
                    }
                    os << "\n";
                }
                os.flush();
                os.flags(os_flags);
            }
        };

        template<typename BlueprintFieldType,
                typename ArithmetizationParams>
        crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> save_shared_var(
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>> &input_assignment,
                const crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &input_var) {
            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            std::uint32_t row_index = input_assignment.shared_column_size(0);
            auto res = var(1, row_index, false, var::column_type::public_input);
            input_assignment.shared(0, row_index) = var_value(input_assignment, input_var);
            return res;
        }

        template<typename BlueprintFieldType,
                typename ArithmetizationParams>
        std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> save_shared_var(
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>> &input_assignment,
                const std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &input_vars) {
            std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> res;
            for (const auto &it : input_vars) {
                res.push_back(save_shared_var(input_assignment, it));
            }
            return res;
        }

        template<typename BlueprintFieldType,
                 typename ArithmetizationParams>
        bool is_satisfied(const circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                          ArithmetizationParams>> &bp,
                          const assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                             ArithmetizationParams>> &assignments){
            const auto& used_gates = bp.get_used_gates();

            const auto& used_lookup_gates = bp.get_used_lookup_gates();

            const auto& used_copy_constraints = bp.get_used_copy_constraints();

            const auto& private_rows = assignments.get_used_selector_rows();

            return is_satisfied(bp, assignments, used_gates, used_lookup_gates, used_copy_constraints, private_rows);
        }
    }    // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_ASSIGNMENT_PROXY_PLONK_HPP
