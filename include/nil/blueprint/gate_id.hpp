//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_GATE_ID_HPP
#define CRYPTO3_BLUEPRINT_GATE_ID_HPP

#include <vector>
#include <functional>
#include <string>
#include <sstream>

#include <boost/random/random_device.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_gate.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>

namespace nil {
    namespace blueprint {
        // Helper class for gate_id
        // Encapsulates storing values at random points for gate comparison
        template<typename BlueprintFieldType>
        class value_set {
        private:
            using value_type = typename BlueprintFieldType::value_type;
            using var = nil::crypto3::zk::snark::plonk_variable<value_type>;

            static constexpr std::size_t starting_constraint_mults_size = 20;

            boost::random::random_device dev;
            nil::crypto3::random::algebraic_engine<BlueprintFieldType> random_engine =
                nil::crypto3::random::algebraic_engine<BlueprintFieldType>(dev);

            std::array<std::array<std::vector<value_type>, 3>, 2> witnesses;
            std::array<std::array<std::vector<value_type>, 3>, 2> constants;
            // Used to separate constraints from each other in ids.
            std::vector<value_type> constraint_mults;
            // Used to separate lookup variables from each other in ids.
            std::vector<value_type> lookup_constraint_mults;
            // Used to separate lookup constraints by table id.
            std::vector<value_type> lookup_table_mults;

            value_type generate_constraint_mult() {
                value_type val = random_engine();
                // Here it's critical that the values are non-zero
                // Otherwise some of the constraints would never actually matter
                // The probability for that is extremely low, but checking for this
                // might still be worthwhile
                while (val == value_type::zero()) {
                    val = random_engine();
                }
                return val;
            }

            value_set() {

                constraint_mults.reserve(starting_constraint_mults_size);
                for (std::size_t i = 0; i < starting_constraint_mults_size; i++) {
                    constraint_mults.emplace_back(generate_constraint_mult());
                }
                lookup_constraint_mults.reserve(starting_constraint_mults_size);
                for (std::size_t i = 0; i < starting_constraint_mults_size; i++) {
                    lookup_constraint_mults.emplace_back(generate_constraint_mult());
                }
                lookup_table_mults.reserve(starting_constraint_mults_size);
                for (std::size_t i = 0; i < starting_constraint_mults_size; i++) {
                    lookup_table_mults.emplace_back(generate_constraint_mult());
                }
            }

            inline value_type get_power_helper(std::vector<value_type> &container, std::size_t index) {
                while (index >= container.size()) {
                    container.push_back(generate_constraint_mult());
                }
                return container[index];
            }

            inline value_type get_value_helper(
                    std::array<std::array<std::vector<value_type>, 3>, 2> &container,
                    std::size_t point, std::size_t index, std::size_t rotation) {
                BOOST_ASSERT_MSG(point == 0 || point == 1, "Point must be either 0 or 1.");
                return get_power_helper(container[point][rotation + 1], index);
            }

        public:
            // Singleton
            static value_set& get_value_set() {
                static value_set instance;
                return instance;
            }

            value_type get_witness(std::size_t point, std::size_t index, std::size_t rotation) {
                return get_value_helper(witnesses, point, index, rotation);
            }

            value_type get_constant(std::size_t point, std::size_t index, std::size_t rotation) {
                return get_value_helper(constants, point, index, rotation);
            }

            value_type get_power(std::size_t index) {
                return get_power_helper(constraint_mults, index);
            }

            value_type get_lookup_power(std::size_t index) {
                return get_power_helper(lookup_constraint_mults, index);
            }

            value_type get_table_power(std::size_t index) {
                return get_power_helper(lookup_table_mults, index);
            }

            value_type get_var_value(std::size_t point, const var &var) {
                BOOST_ASSERT_MSG(point == 0 || point == 1, "Index must be either 0 or 1.");
                BOOST_ASSERT_MSG(var.relative == true, "Absolute variables should not belong to a gate.");
                switch (var.type) {
                    case var::column_type::witness:
                        return this->get_witness(point, var.index, var.rotation);
                    case var::column_type::constant:
                        return this->get_constant(point, var.index, var.rotation);
                    case var::column_type::public_input:
                    case var::column_type::selector:
                        BOOST_ASSERT_MSG(false, "Public input/selectors should not be in a gate.");
                    case var::column_type::uninitialized:
                        BOOST_ASSERT_MSG(false, "Uninitialized variable should not be inside a gate.");
                }
                __builtin_unreachable();
            };

            value_type get_first_value(const var &var) {
                return get_var_value(0, var);
            };

            value_type get_second_value(const var &var) {
                return get_var_value(1, var);
            };
        };

        // Implements a comparison between gates
        // First, calculates a value of product of all constraints at a random
        // This uses [Schwartz–Zippel lemma](https://en.wikipedia.org/wiki/Schwartz%E2%80%93Zippel_lemma)
        // to guarantee a really small probability of collision : degree/field_size
        // We do that at two random points, because I am paranoid.
        template<typename BlueprintFieldType>
        class gate_id {
        private:
            using value_type = typename BlueprintFieldType::value_type;
            using var = nil::crypto3::zk::snark::plonk_variable<value_type>;
            using expression_type = nil::crypto3::math::expression<var>;
            using value_set_type = value_set<BlueprintFieldType>;
            using constraint_type = nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using gate_type = crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;

            value_set_type &values = value_set_type::get_value_set();

            value_type value_1, value_2;
            // We preserve this in order to be able to easily access the original gate.
            std::size_t selector_index;
        public:
            std::pair<value_type, value_type> eval_constraint(const constraint_type& constraint) const {
                nil::crypto3::math::expression_evaluator<var> evaluator_1(
                    constraint,
                    [this](const var &var) { return this->values.get_first_value(var); });
                nil::crypto3::math::expression_evaluator<var> evaluator_2(
                    constraint,
                    [this](const var &var) { return this->values.get_second_value(var); });
                return {evaluator_1.evaluate(), evaluator_2.evaluate()};
            }

            // Note that constraits have to be sorted in order to enforce equality between differently ordered gates.
            #define GATE_ID_INIT_MACRO(constraints_container) \
                value_1 = value_2 = 0; \
                if (constraints_container.empty()) { \
                    return; \
                } \
                std::vector<std::pair<value_type, value_type>> constraint_values; \
                constraint_values.reserve(constraints_container.size()); \
                for (std::size_t i = 0; i < constraints_container.size(); i++) { \
                    constraint_values.emplace_back(eval_constraint(constraints_container[i])); \
                } \
                std::stable_sort(constraint_values.begin(), constraint_values.end(), \
                    [](const std::pair<value_type, value_type> &a, const std::pair<value_type, value_type> &b) { \
                        return a.first < b.first || (a.first == b.first && a.second < b.second); \
                    }); \
                for (std::size_t i = 0; i < constraint_values.size(); i++) { \
                    value_1 += values.get_power(i) * constraint_values[i].first; \
                    value_2 += values.get_power(i) * constraint_values[i].second; \
                }

            gate_id(const gate_type &gate) : selector_index(gate.selector_index) {
                GATE_ID_INIT_MACRO(gate.constraints);
            }

            gate_id(const std::vector<constraint_type> &constraints) : selector_index(0) {
                GATE_ID_INIT_MACRO(constraints);
            }

            gate_id(const constraint_type constraint) : selector_index(0) {
                auto value_pair = eval_constraint(constraint);
                value_1 = value_pair.first;
                value_2 = value_pair.second;
            }

            gate_id(const std::initializer_list<constraint_type> &&constraints) : selector_index(0) {
                GATE_ID_INIT_MACRO(constraints);
            }

            #undef GATE_ID_INIT_MACRO

            bool operator==(const gate_id &other) const {
                return (value_1 == other.value_1) && (value_2 == other.value_2);
            }

            bool operator!=(const gate_id &other) const {
                return !(*this == other);
            }

            bool operator<(const gate_id &other) const {
                return (value_1 < other.value_1) || ((value_1 == other.value_1) && (value_2 < other.value_2));
            }

            const std::size_t get_selector() {
                return selector_index;
            }

            gate_id& operator=(const gate_id& other) {
                value_1 = other.value_1;
                value_2 = other.value_2;
                selector_index = other.selector_index;
                return *this;
            }

            std::string to_string() const {
                std::stringstream ss;
                ss << "Gate ID: " << value_1.data << " " << value_2.data;
                return ss.str();
            }
        };

        // Similar idea to gate_id, but implemented for lookup gates
        template<typename BlueprintFieldType>
        class lookup_gate_id {
        private:
            using value_type = typename BlueprintFieldType::value_type;
            using var = nil::crypto3::zk::snark::plonk_variable<value_type>;
            using expression_type = nil::crypto3::math::expression<var>;
            using value_set_type = value_set<BlueprintFieldType>;
            using constraint_type = nil::crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using gate_type = crypto3::zk::snark::plonk_lookup_gate<BlueprintFieldType, constraint_type>;

            value_set_type &values = value_set_type::get_value_set();

            value_type value_1, value_2;
            // We preserve this in order to be able to easily access the original gate.
            std::size_t tag_index;
        public:
            std::pair<value_type, value_type> eval_constraint(const constraint_type& constraint) const {
                value_type value_1 = 0, value_2 = 0;
                for (std::size_t i = 0; i < constraint.lookup_input.size(); i++) {
                    nil::crypto3::math::expression_evaluator<var> evaluator_1(
                        constraint.lookup_input[i],
                        [this](const var &var) { return this->values.get_first_value(var); });
                    nil::crypto3::math::expression_evaluator<var> evaluator_2(
                        constraint.lookup_input[i],
                        [this](const var &var) { return this->values.get_second_value(var); });
                    value_1 += values.get_lookup_power(i) * evaluator_1.evaluate();
                    value_2 += values.get_lookup_power(i) * evaluator_2.evaluate();
                }
                auto table_power = values.get_table_power(constraint.table_id);
                return {table_power * value_1, table_power * value_2};
            }

            // Note that constraits have to be sorted in order to enforce equality between differently ordered gates.
            #define LOOKUP_GATE_ID_INIT_MACRO(constraints_container) \
                value_1 = value_2 = 0; \
                if (constraints_container.empty()) { \
                    return; \
                } \
                std::vector<std::pair<value_type, value_type>> constraint_values; \
                constraint_values.reserve(constraints_container.size()); \
                for (std::size_t i = 0; i < constraints_container.size(); i++) { \
                    constraint_values.emplace_back(eval_constraint(constraints_container[i])); \
                } \
                std::stable_sort(constraint_values.begin(), constraint_values.end(), \
                    [](const std::pair<value_type, value_type> &a, const std::pair<value_type, value_type> &b) { \
                        return a.first < b.first || (a.first == b.first && a.second < b.second); \
                    }); \
                for (std::size_t i = 0; i < constraint_values.size(); i++) { \
                    value_1 += values.get_power(i) * constraint_values[i].first; \
                    value_2 += values.get_power(i) * constraint_values[i].second; \
                }

            lookup_gate_id(const gate_type &gate) : tag_index(gate.tag_index) {
                LOOKUP_GATE_ID_INIT_MACRO(gate.constraints);
            }

            lookup_gate_id(const std::vector<constraint_type> &constraints) : tag_index(0) {
                LOOKUP_GATE_ID_INIT_MACRO(constraints);
            }

            lookup_gate_id(const constraint_type &constraint) : tag_index(0) {
                auto value_pair = eval_constraint(constraint);
                value_1 = value_pair.first;
                value_2 = value_pair.second;
            }

            lookup_gate_id(const std::initializer_list<constraint_type> &&constraints) : tag_index(0) {
                LOOKUP_GATE_ID_INIT_MACRO(constraints);
            }

            #undef LOOKUP_GATE_ID_INIT_MACRO

            bool operator==(const lookup_gate_id &other) const {
                return (value_1 == other.value_1) && (value_2 == other.value_2);
            }

            bool operator!=(const lookup_gate_id &other) const {
                return !(*this == other);
            }

            bool operator<(const lookup_gate_id &other) const {
                return (value_1 < other.value_1) || ((value_1 == other.value_1) && (value_2 < other.value_2));
            }

            const std::size_t get_selector() {
                return tag_index;
            }

            lookup_gate_id& operator=(const lookup_gate_id& other) {
                value_1 = other.value_1;
                value_2 = other.value_2;
                tag_index = other.tag_index;
                return *this;
            }

            std::string to_string() const {
                std::stringstream ss;
                ss << "Lookup Gate ID: " << value_1.data << " " << value_2.data;
                return ss.str();
            }
        };
    }     // namespace blueprint
}   // namespace nil

#endif   // CRYPTO3_BLUEPRINT_GATE_ID_HPP