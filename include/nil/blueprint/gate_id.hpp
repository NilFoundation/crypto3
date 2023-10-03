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
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>

namespace nil {
    namespace blueprint {
        // Helper class for gate_id
        // Encapsulates storing values at random points for gate comparison
        template<typename BlueprintFieldType, typename ArithmetizationParams>
        class value_set {
        private:
            using value_type = typename BlueprintFieldType::value_type;

            static constexpr std::size_t starting_constraint_mults_size = 20;

            std::array<std::array<std::vector<value_type>, 3>, 2> witnesses;
            std::array<std::array<std::vector<value_type>, 3>, 2> constants;
            // Used to separate constraints from each other in ids.
            std::vector<value_type> constraint_mults;

            value_type generate_constraint_mult(
                    nil::crypto3::random::algebraic_engine<BlueprintFieldType> &engine) const {
                value_type val = engine();
                // Here it's critical that the values are non-zero
                // Otherwise some of the constraints would never actually matter
                // The probability for that is extremely low, but checking for this
                // might still be worthwhile
                while (val == value_type::zero()) {
                    val = engine();
                }
                return val;
            }

            value_set() {
                boost::random::random_device dev;
                nil::crypto3::random::algebraic_engine<BlueprintFieldType> random_engine(dev);

                for (std::size_t p = 0; p < 2; p++) {
                    for (std::size_t i = 0; i < 3; i++) {
                        witnesses[p][i].reserve(ArithmetizationParams::witness_columns);
                    }
                }

                for (std::size_t p = 0; p < 2; p++) {
                    for (std::size_t i = 0; i < 3; i++) {
                        constants[p][i].reserve(ArithmetizationParams::witness_columns);
                    }
                }

                for (std::size_t p = 0; p < 2; p++) {
                    for (std::size_t i = 0; i < 3; i++) {
                        for (std::size_t j = 0; j < ArithmetizationParams::witness_columns; j++) {
                            witnesses[p][i].emplace_back(random_engine());
                        }
                    }
                }

                for (std::size_t p = 0; p < 2; p++) {
                    for (std::size_t i = 0; i < 3; i++) {
                        for (std::size_t j = 0; j < ArithmetizationParams::constant_columns; j++) {
                            constants[p][i].emplace_back(random_engine());
                        }
                    }
                }
                constraint_mults.reserve(starting_constraint_mults_size);
                for (std::size_t i = 0; i < starting_constraint_mults_size; i++) {
                    constraint_mults.emplace_back(generate_constraint_mult(random_engine));
                }
            }
        public:
            static constexpr std::size_t witness_columns = ArithmetizationParams::witness_columns;
            static constexpr std::size_t constant_columns = ArithmetizationParams::constant_columns;

            // Singleton
            static value_set& get_value_set() {
                static value_set instance;
                return instance;
            }

            value_type get_witness(std::size_t point, std::size_t index, std::size_t rotation) const {
                BOOST_ASSERT_MSG(point == 0 || point == 1, "Point must be either 0 or 1.");
                BOOST_ASSERT_MSG(index < witness_columns, "Index must be less than witness_columns.");
                return witnesses[point][rotation + 1][index];
            }

            value_type get_constant(std::size_t point, std::size_t index, std::size_t rotation) const {
                BOOST_ASSERT_MSG(point == 0 || point == 1, "Point must be either 0 or 1.");
                BOOST_ASSERT_MSG(index < constant_columns, "Index must be less than constant_columns.");
                return constants[point][rotation + 1][index];
            }

            value_type get_power(std::size_t index) {
                if (index >= constraint_mults.size()) {
                    static boost::random::random_device dev;
                    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> random_engine(dev);
                    while (index >= constraint_mults.size()) {
                        constraint_mults.push_back(generate_constraint_mult(random_engine));
                    }
                }
                return constraint_mults[index];
            }
        };

        // Implements a comparison between gates
        // First, calculates a value of product of all constraints at a random
        // This uses [Schwartz–Zippel lemma](https://en.wikipedia.org/wiki/Schwartz%E2%80%93Zippel_lemma)
        // to guarantee a really small probability of collision : degree/field_size
        // We do that at two random points, because I am paranoid.
        template<typename BlueprintFieldType, typename ArithmetizationParams>
        class gate_id {
        private:
            using value_type = typename BlueprintFieldType::value_type;
            using var = nil::crypto3::zk::snark::plonk_variable<value_type>;
            using expression_type = nil::crypto3::math::expression<var>;
            using value_set_type = value_set<BlueprintFieldType, ArithmetizationParams>;
            using constraint_type = nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using gate_type = crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;

            value_set_type &values = value_set_type::get_value_set();
            value_type get_var_value(std::size_t point, const var &var) {
                BOOST_ASSERT_MSG(point == 0 || point == 1, "Index must be either 0 or 1.");
                BOOST_ASSERT_MSG(var.relative == true, "Absolute variables should not belong to a gate.");
                switch (var.type) {
                case var::column_type::witness:
                    return values.get_witness(point, var.index, var.rotation);
                case var::column_type::constant:
                    return values.get_constant(point, var.index, var.rotation);
                case var::column_type::public_input:
                case var::column_type::selector:
                    BOOST_ASSERT_MSG(false, "Public input/selectors should not be in a gate.");
                }
            };

            value_type get_first_value(const var &var) {
                return get_var_value(0, var);
            };

            value_type get_second_value(const var &var) {
                return get_var_value(1, var);
            };

            value_type value_1, value_2;
            // We preserve this in order to be able to easily access the original gate.
            std::size_t selector_index;

        public:
            // Note that constraits have to be sorted in order to enforce equality between differently ordered gates.
            #define gate_id_init_macro(constraints_container) \
                value_1 = value_2 = 0; \
                if (constraints_container.empty()) { \
                    return; \
                } \
                std::vector<std::pair<value_type, value_type>> constraint_values; \
                constraint_values.reserve(constraints_container.size()); \
                for (std::size_t i = 0; i < constraints_container.size(); i++) { \
                    nil::crypto3::math::expression_evaluator<var> evaluator_1( \
                        constraints_container[i], \
                        [this](const var &var) { return this->get_first_value(var); }); \
                    nil::crypto3::math::expression_evaluator<var> evaluator_2( \
                        constraints_container[i], \
                        [this](const var &var) { return this->get_second_value(var); }); \
                    constraint_values.emplace_back(evaluator_1.evaluate(), evaluator_2.evaluate()); \
                } \
                std::stable_sort(constraint_values.begin(), constraint_values.end(), \
                    [](const std::pair<value_type, value_type> &a, const std::pair<value_type, value_type> &b) { \
                        return a.first < b.first || (a.first == b.first && a.second < b.second); \
                    }); \
                for (std::size_t i = 0; i < constraint_values.size(); i++) { \
                    value_1 += values.get_power(i) * constraint_values[i].first; \
                    value_2 += values.get_power(i) * constraint_values[i].second; \
                } \

            gate_id(const gate_type &gate) : selector_index(gate.selector_index) {
                gate_id_init_macro(gate.constraints);
            }

            gate_id(const std::vector<constraint_type> &constraints) : selector_index(0) {
                gate_id_init_macro(constraints);
            }

            gate_id(const constraint_type constraint) : selector_index(0) {
                nil::crypto3::math::expression_evaluator<var> evaluator_1(
                    constraint,
                    [this](const var &var) { return this->get_first_value(var); });
                nil::crypto3::math::expression_evaluator<var> evaluator_2(
                    constraint,
                    [this](const var &var) { return this->get_second_value(var); });
                value_1 = evaluator_1.evaluate();
                value_2 = evaluator_2.evaluate();
            }

            gate_id(const std::initializer_list<constraint_type> &&constraints) : selector_index(0) {
                gate_id_init_macro(constraints);
            }

            #undef gate_id_init_macro

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
    }     // namespace blueprint
}   // namespace nil

#endif   // CRYPTO3_BLUEPRINT_GATE_ID_HPP