//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>=
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

#pragma once

#include <functional>

#include <boost/random.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType>
        crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> generate_random_global_var(
                const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignments,
                boost::random::mt19937 &random_engine) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            const std::size_t witness_amount = assignments.witnesses_amount();
            const std::size_t public_input_amount = assignments.public_inputs_amount();
            const std::size_t constant_amount = assignments.constants_amount();
            const std::size_t total_col_amount = witness_amount + public_input_amount + constant_amount;
            const std::size_t rows_amount = assignments.rows_amount();
            const std::size_t random_row =
                boost::random::uniform_int_distribution<std::size_t>(0, rows_amount - 1)(random_engine);
            std::size_t random_col =
                boost::random::uniform_int_distribution<std::size_t>(0, total_col_amount - 1)(random_engine);
            typename var::column_type column_type;
            if (random_col < witness_amount) {
                column_type = var::column_type::witness;
            } else if (random_col < witness_amount + public_input_amount) {
                column_type = var::column_type::public_input;
                random_col -= witness_amount;
            } else {
                column_type = var::column_type::constant;
                random_col -= witness_amount + public_input_amount;
            }
            return var(random_col, random_row, true, column_type);
        }

        template<typename BlueprintFieldType>
        crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> generate_random_local_var(
                const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignments,
                boost::random::mt19937 &random_engine) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            const std::size_t witness_amount = assignments.witnesses_amount();
            const std::size_t constant_amount = assignments.constants_amount();
            const std::size_t total_col_amount = witness_amount + constant_amount;
            const std::int32_t random_offset =
                boost::random::uniform_int_distribution<std::int32_t>(-1, 1)(random_engine);
            std::size_t random_col =
                boost::random::uniform_int_distribution<std::size_t>(0, total_col_amount - 1)(random_engine);
            typename var::column_type column_type;
            if (random_col < witness_amount) {
                column_type = var::column_type::witness;
            } else {
                column_type = var::column_type::constant;
                random_col -= witness_amount;
            }
            return var(random_col, random_offset, true, column_type);
        }

        template<typename BlueprintFieldType>
        void generate_random_copy_constraints(
                const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignments,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                const std::size_t num_constraints,
                boost::random::mt19937 &random_engine) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            for (std::size_t i = 0; i < num_constraints; ++i) {
                const var a = generate_random_global_var(assignments, random_engine);
                var b = generate_random_global_var(assignments, random_engine);
                // note that we technically might not generate a unique copy constraint here and it
                // might be already present
                // for the sake of simplicity we don't check for that, as the probability of that is really small
                // for the assignment tables of a reasonable size compared to the number of constraints
                while (a == b) { [[unlikely]]
                    b = generate_random_global_var(assignments, random_engine);
                }
                bp.add_copy_constraint({a, b});
            }
            // Sanity check
            BOOST_ASSERT(bp.copy_constraints().size() == num_constraints);
        }

        template<typename BlueprintFieldType>
        void fill_assignment_table(
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignments,
                const std::size_t rows_amount,
                boost::random::mt19937 &random_engine) {

            using value_type = typename BlueprintFieldType::value_type;
            crypto3::random::algebraic_engine<BlueprintFieldType> engine(random_engine);
            std::array<std::function<value_type&(std::size_t, std::size_t)>, 3> access_functions = {
                [&assignments](std::size_t col, std::size_t row) -> value_type& {
                    return assignments.witness(col, row);
                },
                [&assignments](std::size_t col, std::size_t row) -> value_type& {
                    return assignments.public_input(col, row);
                },
                [&assignments](std::size_t col, std::size_t row) -> value_type& {
                    return assignments.constant(col, row);
                }
            };
            std::array<std::size_t, 3> sizes = {
                assignments.witnesses_amount(), assignments.public_inputs_amount(),  assignments.constants_amount()};
            for (const auto &column_access_pair :
                    {std::pair(sizes[0], access_functions[0]),
                     std::pair(sizes[1], access_functions[1]),
                     std::pair(sizes[2], access_functions[2])}) {
                const std::size_t column_amount = column_access_pair.first;
                const auto &column_access_function = column_access_pair.second;
                for (std::size_t col = 0; col < column_amount; ++col) {
                    for (std::size_t row = 0; row < rows_amount; ++row) {
                        column_access_function(col, row) = engine();
                    }
                }
            }
        }

        template<typename BlueprintFieldType>
        void fill_selectors(
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignments,
                const circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                boost::random::mt19937 &random_engine) {

            // We use a separate algorithm for filling selectors, as they are 0/1
            // In practicde the distribution is not uniform, but we ignore that for the purposes of this benchmark
            // TODO: do something more clever
            for (std::size_t i = 0; i < assignments.selectors_amount(); ++i) {
                for (std::size_t row = 0; row < assignments.rows_amount(); ++row) {
                    assignments.selector(i, row) = random_engine() % 2;
                }
            }
        }

        template<typename BlueprintFieldType>
        nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType> generate_random_constraint(
                const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignments,
                const std::size_t max_degree,
                const std::size_t max_linear_comb_size,
                boost::random::mt19937 &random_engine) {
            // Strategy: generate two random polynomials of max_degree / 2, and then multiply them
            // If max_degree % 2 != 0, we multiply the result by a random linear combination
            // Which is incidentally the ouput of this function with max_degree = 1
            // This generates very "wide" gates on average.
            // I need a different algorithm probably? Unsure.
            if (max_degree > 1) {
                auto a = generate_random_constraint<BlueprintFieldType>(
                    assignments, max_degree / 2, max_linear_comb_size, random_engine);
                auto b = generate_random_constraint<BlueprintFieldType>(
                    assignments, max_degree / 2, max_linear_comb_size, random_engine);
                if (max_degree % 2 != 0) {
                    auto c = generate_random_constraint<BlueprintFieldType>(
                        assignments, 1, max_linear_comb_size, random_engine);
                    return a * b * c;
                } else {
                    return a * b;
                }
            } else if (max_degree == 1) {
                crypto3::random::algebraic_engine<BlueprintFieldType> engine(random_engine);
                nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType> linear_comb;
                const std::size_t linear_comb_size =
                    boost::random::uniform_int_distribution<std::size_t>(1, max_linear_comb_size)(random_engine);
                for (std::size_t i = 0; i < linear_comb_size; i++) {
                    linear_comb += engine() * generate_random_local_var(assignments, random_engine);
                }
                linear_comb += engine();
                return linear_comb;
            } else {
                BOOST_ASSERT_MSG(false, "max_degree must be > 0");
            }
            __builtin_unreachable();
        }

        template<typename BlueprintFieldType>
        void generate_random_gate(
                const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignments,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                const std::size_t max_degree,
                const std::size_t max_linear_comb_size,
                const std::size_t constraints_amount,
                boost::random::mt19937 &random_engine) {

            std::vector<typename nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> constraints;
            constraints.reserve(constraints_amount);
            // first, ensure that we have at least one of the constraints with the given max_degree
            constraints.emplace_back(generate_random_constraint<BlueprintFieldType>(
                assignments, max_degree, max_linear_comb_size, random_engine));
            // next, generate the rest of them
            for (std::size_t i = 1; i < constraints_amount; ++i) {
                const std::size_t degree = max_degree > 1 ?
                      boost::random::uniform_int_distribution<std::size_t>(1, max_degree)(random_engine)
                    : 1;
                constraints.emplace_back(generate_random_constraint<BlueprintFieldType>(
                    assignments, degree, max_linear_comb_size, random_engine));
            }
            bp.add_gate(constraints);
        }


        template<typename BlueprintFieldType>
        void generate_random_gates(
                const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignments,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                const std::size_t gates_amount,
                const std::size_t max_degree,
                const std::size_t max_linear_comb_size,
                const std::size_t constraints_amount,
                boost::random::mt19937 &random_engine) {

            BOOST_ASSERT_MSG(max_degree > 0, "max_degree must be > 0");
            BOOST_ASSERT_MSG(max_linear_comb_size > 0, "max_linear_comb_size must be > 0");
            BOOST_ASSERT_MSG(constraints_amount > 0, "constraints_amount must be > 0");

            // Generate a gate with a given max_degree
            generate_random_gate(assignments, bp, max_degree, max_linear_comb_size, constraints_amount, random_engine);
            // Generate the rest of the gates with random max degrees
            for (std::size_t i = 1; i < gates_amount; ++i) {
                const std::size_t degree = max_degree > 1 ?
                      boost::random::uniform_int_distribution<std::size_t>(1, max_degree)(random_engine)
                    : 1;
                generate_random_gate(assignments, bp, degree, max_linear_comb_size, constraints_amount, random_engine);
            }
        }
    }   // namespace blueprint
}   // namespace nil
