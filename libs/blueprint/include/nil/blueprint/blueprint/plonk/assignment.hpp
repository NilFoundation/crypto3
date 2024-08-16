//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_ASSIGNMENT_PLONK_HPP
#define CRYPTO3_BLUEPRINT_ASSIGNMENT_PLONK_HPP

#include <algorithm>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <limits>
#include <optional>
#include <ostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <boost/type_erasure/any.hpp>
#include <boost/type_erasure/same_type.hpp>
#include <boost/type_erasure/operators.hpp>
#include <boost/type_erasure/any_cast.hpp>
#include <boost/container/stable_vector.hpp>

#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

#include <nil/blueprint/component.hpp>
#include <nil/blueprint/assert.hpp>
#include <nil/blueprint/gate_id.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component_batch.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {
            template<typename BlueprintFieldType>
            struct constant_batch_ref_compare {
                using value_type = typename BlueprintFieldType::value_type;
                using ref_type = std::reference_wrapper<const value_type>;
                using pair_type = std::pair<ref_type, std::size_t>;

                bool operator()(const pair_type &p1, const pair_type &p2) const {
                    return p1.first.get() < p2.first.get();
                }
            };
        }   // namespace detail

        template<typename ArithmetizationType>
        class assignment;

        template<typename ArithmetizationType>
        class circuit;

        template<typename ArithmetizationType, typename BlueprintFieldType, typename ComponentType,
                 typename... ComponentParams>
        class component_batch;

        template<typename BatchType, typename InputType, typename ResultType>
        struct has_add_input;

        template<typename BatchType, typename ArithmetizationType, typename VariableType>
        struct has_finalize_batch;

        template<typename BatchType>
        struct has_name;

        template<typename ComponentType>
        struct input_type_v;

        template<typename ComponentType>
        struct result_type_v;

        template<typename ComponentType>
        struct component_params_type_v;;

        struct _batch : boost::type_erasure::placeholder {};
        struct _component : boost::type_erasure::placeholder {};
        struct _input_type : boost::type_erasure::placeholder {};
        struct _result_type : boost::type_erasure::placeholder {};
        struct _variadics : boost::type_erasure::placeholder {};

        template<typename BlueprintFieldType>
        class assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType> {

            using zk_type = crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>;

            typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType> ArithmetizationType;

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            using value_type = typename BlueprintFieldType::value_type;
            using column_type = typename crypto3::zk::snark::plonk_column<BlueprintFieldType>;
            using shared_container_type = typename std::array<column_type, 1>;
            using constant_set_compare_type = detail::constant_batch_ref_compare<BlueprintFieldType>;

            std::uint32_t assignment_allocated_rows = 0;
            std::vector<value_type> assignment_private_storage;
            // for variables used in component batching
            std::vector<value_type> assignment_batch_private_storage;
            using batcher_type = boost::type_erasure::any<
                boost::mpl::vector<
                    has_add_input<_batch, _input_type, _result_type>,
                    has_finalize_batch<_batch, ArithmetizationType, var>,
                    has_name<_batch>,
                    boost::type_erasure::same_type<boost::type_erasure::deduced<input_type_v<_batch>>, _input_type>,
                    boost::type_erasure::same_type<boost::type_erasure::deduced<result_type_v<_batch>>, _result_type>,
                    boost::type_erasure::same_type<boost::type_erasure::deduced<component_params_type_v<_batch>>, _variadics>,
                    boost::type_erasure::less_than_comparable<_batch>,
                    boost::type_erasure::copy_constructible<_batch>,
                    boost::type_erasure::constructible<_batch(assignment<ArithmetizationType>&, _variadics)>,
                    boost::type_erasure::destructible<_batch>,
                    boost::type_erasure::typeid_<_batch>,
                    boost::type_erasure::relaxed>,
                _batch>;
            std::set<batcher_type> component_batches;
            // technically we can delete this one after finalization
            // but tests require it to replace the outputs
            std::unordered_map<var, var> batch_variable_map;
            // for constants which we are going to try to put into aribtrary places
            boost::container::stable_vector<value_type> assignment_batch_constant_storage;
            std::set<std::pair<std::reference_wrapper<const value_type>, std::size_t>, constant_set_compare_type>
                assignment_batch_constant_storage_set;
            shared_container_type shared_storage; // results of the previously prover
            std::set<std::uint32_t> lookup_constant_cols;
            std::set<std::uint32_t> lookup_selector_cols;

            /// Used to specify ranges of indexes for columns or rows
            using ranges = std::vector<std::pair<std::size_t, std::size_t>>;

        public:
            static constexpr const std::size_t private_storage_index = std::numeric_limits<std::size_t>::max();
            static constexpr const std::size_t batch_private_storage_index = std::numeric_limits<std::size_t>::max() - 1;
            static constexpr const std::size_t batch_constant_storage_index = std::numeric_limits<std::size_t>::max() - 2;

            assignment(std::size_t witness_amount, std::size_t public_input_amount,
                       std::size_t constant_amount, std::size_t selector_amount)
                : zk_type(witness_amount, public_input_amount, constant_amount, selector_amount) {
            }

            assignment(const crypto3::zk::snark::plonk_table_description<BlueprintFieldType> &desc)
                : zk_type(desc.witness_columns, desc.public_input_columns,
                          desc.constant_columns, desc.selector_columns) {
            }

            template<typename ComponentType, typename... ComponentParams>
            typename ComponentType::result_type add_input_to_batch_assignment(
                    const typename ComponentType::input_type &input,
                    ComponentParams... params) {

                return add_input_to_batch<ComponentType>(input, false, params...);
            }

            template<typename ComponentType, typename... ComponentParams>
            typename ComponentType::result_type add_input_to_batch_circuit(
                    const typename ComponentType::input_type &input,
                    ComponentParams... params) {

                return add_input_to_batch<ComponentType>(input, true, params...);
            }

            template<typename ComponentType, typename... ComponentParams>
            typename ComponentType::result_type add_input_to_batch(
                    const typename ComponentType::input_type &input,
                    bool called_from_generate_circuit,
                    ComponentParams... params) {
                using batching_type = component_batch<ArithmetizationType, BlueprintFieldType, ComponentType,
                                                      ComponentParams...>;
                batching_type batch(*this, std::tuple<ComponentParams...>(params...));
                auto it = component_batches.find(batch);
                if (it == component_batches.end()) {
                    auto result = batch.add_input(input, called_from_generate_circuit);
                    component_batches.insert(batch);
                    return result;
                } else {
                    // safe because the ordering doesn't depend on the batch inputs
                    return boost::type_erasure::any_cast<batching_type&>(const_cast<batcher_type&>(*it))
                            .add_input(input, called_from_generate_circuit);
                }
            }

            std::size_t finalize_component_batches(nil::blueprint::circuit<ArithmetizationType> &bp,
                                                   std::size_t start_row_index) {
                std::size_t next_row_index = start_row_index;
                for (auto& batch : component_batches) {
                    // safe because the ordering doesn't depend on the batch inputs
                    next_row_index = const_cast<batcher_type&>(batch).finalize_batch(
                            bp, batch_variable_map, next_row_index);
                }
                auto &copy_constraints = bp.mutable_copy_constraints();
                for (auto &constraint : copy_constraints) {
                    for (auto variable : {&(constraint.first), &(constraint.second)}) {
                        if (batch_variable_map.find(*variable) != batch_variable_map.end()) {
                            *variable = batch_variable_map[*variable];
                        }
                    }
                }
                return next_row_index;
            }

            const std::unordered_map<var, var>& get_batch_variable_map() const {
                return batch_variable_map;
            }

            // currently only supports a single constant column to batch things into
            // ideally we should not require more than one
            std::size_t finalize_constant_batches(
                    nil::blueprint::circuit<ArithmetizationType> &bp,
                    std::size_t const_column,
                    std::size_t start_row_index = 1) {
                if (assignment_batch_constant_storage.size() == 0) {
                    return start_row_index;
                }
                BOOST_ASSERT(start_row_index >= 1);
                std::vector<bool> used_constants;
                if (this->constant_column_size(const_column) > start_row_index) {
                    used_constants.resize(this->constant_column_size(const_column) - start_row_index, false);
                    const auto &immutable_copy_constraints = bp.copy_constraints();
                    auto var_check = [const_column, start_row_index](const var &variable) -> bool {
                        return variable.type == var::column_type::constant &&
                                variable.index == const_column &&
                                variable.rotation >= start_row_index;
                    };
                    for (const auto &constraint : immutable_copy_constraints) {
                        for (const auto variable : {&(constraint.first), &(constraint.second)}) {
                            if (var_check(*variable)) {
                                used_constants[variable->rotation - start_row_index] = true;
                            }
                        }
                    }
                    const auto &gates = bp.gates();
                    for (const auto &gate : gates) {
                        std::unordered_set<var> variable_set;
                        std::function<void(var)> variable_extractor =
                            [&variable_set, &var_check](const var &variable) {
                                if (var_check(variable)) {
                                    variable_set.insert(variable);
                                }
                            };
                        nil::crypto3::math::expression_for_each_variable_visitor<var> visitor(variable_extractor);
                        for (const auto &constraint : gate.constraints) {
                            visitor.visit(constraint);
                        }
                        for (const auto &variable : variable_set) {
                            for (std::size_t row = start_row_index - 1;
                                 row < this->selector_column_size(gate.selector_index); row++) {
                                if (this->selector(gate.selector_index, row) == value_type::one()) {
                                    used_constants[row + variable.rotation - start_row_index] = true;
                                }
                            }
                        }
                    }
                    const auto &lookup_gates = bp.lookup_gates();
                    for (const auto &gate : lookup_gates) {
                        std::unordered_set<var> variable_set;
                        std::function<void(var)> variable_extractor =
                            [&variable_set, &var_check](const var &variable) {
                                if (var_check(variable)) {
                                    variable_set.insert(variable);
                                }
                            };
                        nil::crypto3::math::expression_for_each_variable_visitor<var> visitor(variable_extractor);
                        for (const auto &lookup_constraint : gate.constraints) {
                            for (const auto &constraint : lookup_constraint.lookup_input) {
                                visitor.visit(constraint);
                            }
                        }
                        for (const auto &variable : variable_set) {
                            for (std::size_t row = start_row_index - 1;
                                 row < this->selector_column_size(gate.tag_index); row++) {
                                if (this->selector(gate.tag_index, row) == BlueprintFieldType::value_type::one()) {
                                    used_constants[row + variable.rotation - start_row_index] = true;
                                }
                            }
                        }
                    }
                }
                std::size_t row = start_row_index;
                std::unordered_map<var, var> batch_variable_map;
                for (std::size_t constant_index = 0; constant_index < assignment_batch_constant_storage.size();
                     constant_index++) {
                    while (row < (used_constants.size() + start_row_index) && used_constants[row - start_row_index]) {
                        row++;
                    }
                    const var curr_batch_var =
                        var(batch_constant_storage_index, constant_index, false, var::column_type::constant);
                    const var curr_bp_var = var(const_column, row, false, var::column_type::constant);
                    this->constant(const_column, row) = assignment_batch_constant_storage[constant_index];
                    batch_variable_map[curr_batch_var] = curr_bp_var;
                    row++;
                }
                auto &copy_constraints = bp.mutable_copy_constraints();
                for (auto &constraint : copy_constraints) {
                    for (auto variable : {&(constraint.first), &(constraint.second)}) {
                        if (batch_variable_map.find(*variable) != batch_variable_map.end()) {
                            *variable = batch_variable_map[*variable];
                        }
                    }
                }
                return row;
            }

            virtual value_type &selector(std::size_t selector_index, std::uint32_t row_index) {

                assert(selector_index < this->_public_table._selectors.size());

                if (this->_public_table._selectors[selector_index].size() <= row_index)
                    this->_public_table._selectors[selector_index].resize(row_index + 1);

                return this->_public_table._selectors[selector_index][row_index];
            }

            virtual value_type selector(std::size_t selector_index, std::uint32_t row_index) const {

                assert(selector_index < this->_public_table._selectors.size());
                assert(row_index < this->_public_table._selectors[selector_index].size());

                return this->_public_table._selectors[selector_index][row_index];
            }

            virtual const column_type& selector(std::uint32_t index) const {
                return zk_type::selector(index);
            }

            virtual std::uint32_t selector_column_size(std::uint32_t col_idx) const {
                return zk_type::selector_column_size(col_idx);
            }

            virtual std::uint32_t selectors_amount() const {
                return zk_type::selectors_amount();
            }

            virtual std::uint32_t allocated_rows() const {
                return assignment_allocated_rows;
            }

            virtual std::uint32_t rows_amount() const {
                return zk_type::rows_amount();
            }

            virtual void enable_selector(const std::size_t selector_index, const std::size_t row_index) {

                selector(selector_index, row_index) = BlueprintFieldType::value_type::one();
                assignment_allocated_rows = std::uint32_t(std::max(std::size_t(assignment_allocated_rows), row_index + 1));
            }

            virtual void enable_selector(const std::size_t selector_index,
                                 const std::size_t begin_row_index,
                                 const std::size_t end_row_index,
                                 const std::size_t index_step = 1) {

                for (std::size_t row_index = begin_row_index; row_index <= end_row_index; row_index += index_step) {
                    enable_selector(selector_index, row_index);
                }
                assignment_allocated_rows = std::uint32_t(std::max(std::size_t(assignment_allocated_rows), end_row_index));
            }

            void fill_selector(std::uint32_t index, const column_type& column) override {
                lookup_selector_cols.insert(index);
                zk_type::fill_selector(index, column);
            }

            virtual const std::set<std::uint32_t>& get_lookup_selector_cols() const {
                return lookup_selector_cols;
            }

            virtual std::uint32_t get_lookup_selector_amount() const {
                return lookup_selector_cols.size();
            }

            virtual value_type &shared(std::uint32_t shared_index, std::uint32_t row_index) {
                if (shared_storage[shared_index].size() <= row_index) {
                    shared_storage[shared_index].resize(row_index + 1);
                }
                return shared_storage[shared_index][row_index];
            }

            virtual value_type shared(std::uint32_t shared_index, std::uint32_t row_index) const {
                BLUEPRINT_ASSERT(row_index < shared_storage[shared_index].size());
                return shared_storage[shared_index][row_index];
            }

            virtual std::uint32_t shared_column_size(std::uint32_t index) const {
                return shared_storage[index].size();
            }

            virtual std::uint32_t shareds_amount() const {
                return shared_storage.size();
            }

            virtual const column_type& shared(std::uint32_t index) const {
                return shared_storage[index];
            }

            virtual value_type &witness(std::uint32_t witness_index, std::uint32_t row_index) {
                BLUEPRINT_ASSERT(witness_index < this->_private_table._witnesses.size());

                if (this->_private_table._witnesses[witness_index].size() <= row_index)
                    this->_private_table._witnesses[witness_index].resize(row_index + 1);

                assignment_allocated_rows = std::max(assignment_allocated_rows, row_index + 1);
                return this->_private_table._witnesses[witness_index][row_index];
            }

            virtual value_type witness(std::uint32_t witness_index, std::uint32_t row_index) const {
                BLUEPRINT_RELEASE_ASSERT(witness_index < this->_private_table._witnesses.size());
                BLUEPRINT_RELEASE_ASSERT(row_index < this->_private_table._witnesses[witness_index].size());

                return this->_private_table._witnesses[witness_index][row_index];
            }

            virtual std::uint32_t witness_column_size(std::uint32_t col_idx) const {
                return this->_private_table.witness_column_size(col_idx);
            }

            virtual std::uint32_t witnesses_amount() const {
                return zk_type::witnesses_amount();
            }

            virtual const column_type& witness(std::uint32_t index) const {
                return zk_type::witness(index);
            }

            virtual value_type &public_input(
                std::uint32_t public_input_index, std::uint32_t row_index) {

                BLUEPRINT_ASSERT(public_input_index < zk_type::public_inputs_amount());

                if (zk_type::public_input_column_size(public_input_index) <= row_index)
                    this->_public_table._public_inputs[public_input_index].resize(row_index + 1);

                return this->_public_table._public_inputs[public_input_index][row_index];
            }

            virtual value_type public_input(
                std::uint32_t public_input_index, std::uint32_t row_index) const {

                BLUEPRINT_ASSERT(public_input_index < zk_type::public_inputs_amount());
                BLUEPRINT_ASSERT(row_index < zk_type::public_input_column_size(public_input_index));

                return zk_type::public_input(public_input_index)[row_index];
            }

            virtual std::uint32_t public_input_column_size(std::uint32_t col_idx) const {
                return this->_public_table.public_input_column_size(col_idx);
            }

            virtual std::uint32_t public_inputs_amount() const {
                return zk_type::public_inputs_amount();
            }

            virtual const column_type& public_input(std::uint32_t index) const {
                return zk_type::public_input(index);
            }

            virtual value_type &constant(
                std::uint32_t constant_index, std::uint32_t row_index) {

                BLUEPRINT_ASSERT(constant_index < zk_type::constants_amount());

                if (zk_type::constant_column_size(constant_index) <= row_index)
                    this->_public_table._constants[constant_index].resize(row_index + 1);

                assignment_allocated_rows = std::max(assignment_allocated_rows, row_index + 1);
                return this->_public_table._constants[constant_index][row_index];
            }

            virtual value_type constant(
                std::uint32_t constant_index, std::uint32_t row_index) const {

                BLUEPRINT_ASSERT(constant_index < zk_type::constants_amount());
                BLUEPRINT_ASSERT(row_index < zk_type::constant_column_size(constant_index));

                return zk_type::constant(constant_index)[row_index];
            }

            virtual const column_type& constant(std::uint32_t index) const {
                return zk_type::constant(index);
            }

            void fill_constant(std::uint32_t index, const column_type& column) override {
                lookup_constant_cols.insert(index);
                zk_type::fill_constant(index, column);
            }

            virtual const std::set<std::uint32_t>& get_lookup_constant_cols() const {
                return lookup_constant_cols;
            }

            virtual std::uint32_t get_lookup_constant_amount() const {
                return lookup_constant_cols.size();
            }

            virtual std::uint32_t constant_column_size(std::uint32_t col_idx) const {
                return this->_public_table.constant_column_size(col_idx);
            }

            virtual std::uint32_t constants_amount() const {
                return zk_type::constants_amount();
            }

            virtual value_type private_storage(std::uint32_t storage_index) const {
                BLUEPRINT_ASSERT(storage_index < assignment_private_storage.size());
                return assignment_private_storage[storage_index];
            }

            virtual value_type &private_storage(std::uint32_t storage_index) {
                if (assignment_private_storage.size() <= storage_index) {
                    assignment_private_storage.resize(storage_index + 1);
                }
                return assignment_private_storage[storage_index];
            }

            // Not required to be called; private_storage calls will automatically resize
            virtual void resize_private_storage(std::uint32_t new_size) {
                assignment_private_storage.resize(new_size);
            }

            virtual void clear_private_storage() {
                assignment_private_storage.clear();
            }

            virtual std::size_t private_storage_size() const {
                return assignment_private_storage.size();
            }

            virtual std::size_t batch_private_storage_size() const {
                return assignment_batch_private_storage.size();
            }

            virtual value_type batch_private_storage(std::uint32_t storage_index) const {
                BLUEPRINT_ASSERT(storage_index < assignment_batch_private_storage.size());
                return assignment_batch_private_storage[storage_index];
            }

            virtual value_type &batch_private_storage(std::uint32_t storage_index) {
                if (assignment_batch_private_storage.size() <= storage_index) {
                    assignment_batch_private_storage.resize(storage_index + 1);
                }
                return assignment_batch_private_storage[storage_index];
            }

            virtual var add_batch_variable(const value_type &value) {
                assignment_batch_private_storage.push_back(value);
                return var(batch_private_storage_index, assignment_batch_private_storage.size() - 1, false,
                           var::column_type::public_input);
            }

            virtual value_type batch_constant_storage(std::uint32_t storage_index) const {
                BLUEPRINT_ASSERT(storage_index < assignment_batch_constant_storage.size());
                return assignment_batch_constant_storage[storage_index];
            }

            virtual var add_batch_constant_variable(const value_type &value) {
                auto existing_const = assignment_batch_constant_storage_set.find(
                    std::make_pair<std::reference_wrapper<const value_type>, std::size_t>(std::cref(value), 0));
                if (existing_const == assignment_batch_constant_storage_set.end()) {
                    assignment_batch_constant_storage.push_back(value);
                    assignment_batch_constant_storage_set.insert(std::make_pair(std::cref(assignment_batch_constant_storage.back()),
                                                                                assignment_batch_constant_storage.size() - 1));
                    return var(batch_constant_storage_index, assignment_batch_constant_storage.size() - 1, false,
                               var::column_type::constant);
                } else {
                    return var(batch_constant_storage_index, existing_const->second, false,
                               var::column_type::constant);
                }
            }

            /// @brief Max size of witness columns.
            std::uint32_t max_witnesses_size() const {
                std::uint32_t size = 0;
                std::size_t ammount = this->_private_table.witnesses_amount();
                for (std::uint32_t i = 0; i < ammount; i++) {
                    size = std::max(size, this->_private_table.witness_column_size(i));
                }
                return size;
            }

            /// @brief Max size of public input columns.
            std::uint32_t max_public_inputs_size() const {
                std::uint32_t size = 0;
                std::size_t ammount = this->_public_table.public_inputs_amount();
                for (std::uint32_t i = 0; i < ammount; i++) {
                    size = std::max(size, this->_public_table.public_input_column_size(i));
                }
                return size;
            }

            /// @brief Max size of constant columns.
            std::uint32_t max_constants_size() const {
                std::uint32_t size = 0;
                std::size_t ammount = this->_public_table.constants_amount();
                for (std::uint32_t i = 0; i < ammount; i++) {
                    size = std::max(size, this->_public_table.constant_column_size(i));
                }
                return size;
            }

            /// @brief Max size of selector columns.
            std::uint32_t max_selectors_size() const {
                std::uint32_t size = 0;
                std::size_t ammount = this->_public_table.selectors_amount();
                for (std::uint32_t i = 0; i < ammount; i++) {
                    size = std::max(size, this->_public_table.selector_column_size(i));
                }
                return size;
            }

            /// @brief Max size of all columns.
            std::uint32_t max_size() const {
                return std::max(
                    {max_witnesses_size(), max_public_inputs_size(), max_constants_size(), max_selectors_size()});
            }

            virtual void export_table(std::ostream &os, bool wide_export = false) const {
                std::size_t witnesses_size = this->_private_table.witnesses_amount(),
                            public_size = this->_public_table.public_inputs_amount(),
                            constants_size = this->_public_table.constants_amount(),
                            selectors_size = this->_public_table.selectors_amount();
                std::uint32_t size = this->max_size();

                ranges rows;
                if (size) {
                    rows.push_back({0, size - 1});
                }
                ranges witnesses;
                if (witnesses_size) {
                    witnesses.push_back({0, witnesses_size - 1});
                }
                ranges public_inputs;
                if (public_size) {
                    public_inputs.push_back({0, public_size - 1});
                }
                ranges constants;
                if (constants_size) {
                    constants.push_back({0, constants_size - 1});
                }
                ranges selectors;
                if (selectors_size) {
                    selectors.push_back({0, selectors_size - 1});
                }
                return export_table(os, witnesses, public_inputs, constants, selectors, rows, wide_export);
            }

            /**
             * @brief Partial export of the table with specifies columns and rows.
             * Headers are still will describe the whole table.
             */
            virtual void export_table(std::ostream &os, ranges witnesses, ranges public_inputs, ranges constants,
                                      ranges selectors, ranges rows, bool wide_export = false) const {
                // wide_export is for e.g. potentiall fuzzer: does fixed width elements
                std::ios_base::fmtflags os_flags(os.flags());
                std::size_t total_witnesses_size = this->_private_table.witnesses_amount(),
                            total_public_size = this->_public_table.public_inputs_amount(),
                            total_constants_size = this->_public_table.constants_amount(),
                            total_selectors_size = this->_public_table.selectors_amount();
                std::uint32_t total_size = this->max_size();

                os << std::dec;

                os << "witnesses_size: " << total_witnesses_size << " "
                   << "public_inputs_size: " << total_public_size << " "
                   << "constants_size: " << total_constants_size << " "
                   << "selectors_size: " << total_selectors_size << " "
                   << "max_size: " << total_size << "\n";

                os << std::hex << std::setfill('0');
                std::uint32_t width = wide_export ? (BlueprintFieldType::modulus_bits + 4 - 1) / 4 : 0;

                for (auto [lower_row, upper_row] : rows) {
                    for (std::uint32_t i = lower_row; i <= upper_row; i++) {
                        for (auto [lower_witness, upper_witness] : witnesses) {
                            for (std::uint32_t j = lower_witness; j <= upper_witness; j++) {
                                os << std::setw(width)
                                   << (i < this->_private_table.witness_column_size(j) ?
                                           this->_private_table.witness(j)[i] :
                                           0)
                                          .data
                                   << " ";
                            }
                        }
                        os << "| ";
                        for (auto [lower_public_input, upper_public_input] : public_inputs) {
                            for (std::uint32_t j = lower_public_input; j <= upper_public_input; j++) {
                                os << std::setw(width)
                                   << (i < this->_public_table.public_input_column_size(j) ?
                                           this->_public_table.public_input(j)[i] :
                                           0)
                                          .data
                                   << " ";
                            }
                        }
                        os << "| ";
                        for (auto [lower_constant, upper_constant] : constants) {
                            for (std::uint32_t j = lower_constant; j <= upper_constant; j++) {
                                os << std::setw(width)
                                   << (i < this->_public_table.constant_column_size(j) ?
                                           this->_public_table.constant(j)[i] :
                                           0)
                                          .data
                                   << " ";
                            }
                        }
                        os << "| ";
                        for (auto [lower_selector, upper_selector] : selectors) {
                            // Selectors only need a single bit, so we do not renew the size here
                            for (std::uint32_t j = lower_selector; j <= upper_selector; j++) {
                                os << (i < this->_public_table.selector_column_size(j) ?
                                           this->_public_table.selector(j)[i] :
                                           0)
                                          .data
                                   << " ";
                            }
                        }
                        os << "\n";
                    }
                }

                os.flush();
                os.flags(os_flags);
            }
        };

        template<typename BlueprintFieldType>
        typename BlueprintFieldType::value_type var_value(
                const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &input_assignment,
                const crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &input_var) {
            using var_column_type =
                typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>::column_type;
            using assignment_type = assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;
            // This SHOULD be handled by a separate variable type
            // (Or even better: properly extracted from the component)
            // But adding a new variable type breaks assigner
            // So we add a type without actually adding a type
            if (input_var.index == assignment_type::private_storage_index) {
                return input_assignment.private_storage(input_var.rotation);
            }
            if (input_var.index == assignment_type::batch_private_storage_index) {
                return input_assignment.batch_private_storage(input_var.rotation);
            }
            if (input_var.index == assignment_type::batch_constant_storage_index) {
                return input_assignment.batch_constant_storage(input_var.rotation);
            }
            if (input_var.type == var_column_type::public_input && input_var.index > 0) {
                return input_assignment.shared(input_var.index - 1, input_var.rotation);
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

    }    // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_ASSIGNMENT_PLONK_HPP
