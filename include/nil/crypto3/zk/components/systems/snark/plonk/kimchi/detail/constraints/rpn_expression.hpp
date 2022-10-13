//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_RPN_EXPRESSION_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_RPN_EXPRESSION_HPP

#include <boost/algorithm/string.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/exponentiation.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/endo_scalar.hpp>
#include <nil/crypto3/zk/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/vanishes_on_last_4_rows.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/unnormalized_lagrange_basis.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // Evaluate an RPN expression
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/circuits/expr.rs#L467
                // Input: RPN expression E, variables values V
                // Output: E(V) \in F_r
                template<typename ArithmetizationType,
                         typename KimchiParamsType,
                         std::size_t NRows,
                         std::size_t... WireIndexes>
                class rpn_expression;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename KimchiParamsType,
                         std::size_t NRows, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                         std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8,
                         std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class rpn_expression<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                     KimchiParamsType,
                                     NRows, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using endo_scalar_component = zk::components::endo_scalar<ArithmetizationType,
                                                                              typename KimchiParamsType::curve_type,
                                                                              KimchiParamsType::scalar_challenge_size,
                                                                              W0,
                                                                              W1,
                                                                              W2,
                                                                              W3,
                                                                              W4,
                                                                              W5,
                                                                              W6,
                                                                              W7,
                                                                              W8,
                                                                              W9,
                                                                              W10,
                                                                              W11,
                                                                              W12,
                                                                              W13,
                                                                              W14>;

                    using poseidon_component = zk::components::poseidon<ArithmetizationType,
                                                                        BlueprintFieldType,
                                                                        W0,
                                                                        W1,
                                                                        W2,
                                                                        W3,
                                                                        W4,
                                                                        W5,
                                                                        W6,
                                                                        W7,
                                                                        W8,
                                                                        W9,
                                                                        W10,
                                                                        W11,
                                                                        W12,
                                                                        W13,
                                                                        W14>;

                    using exponentiation_component = zk::components::exponentiation<ArithmetizationType,
                                                                                    64,
                                                                                    W0,
                                                                                    W1,
                                                                                    W2,
                                                                                    W3,
                                                                                    W4,
                                                                                    W5,
                                                                                    W6,
                                                                                    W7,
                                                                                    W8,
                                                                                    W9,
                                                                                    W10,
                                                                                    W11,
                                                                                    W12,
                                                                                    W13,
                                                                                    W14>;

                    using vanishes_on_last_4_rows_component =
                        zk::components::vanishes_on_last_4_rows<ArithmetizationType,
                                                                W0,
                                                                W1,
                                                                W2,
                                                                W3,
                                                                W4,
                                                                W5,
                                                                W6,
                                                                W7,
                                                                W8,
                                                                W9,
                                                                W10,
                                                                W11,
                                                                W12,
                                                                W13,
                                                                W14>;

                    using unnormalized_lagrange_basis_component =
                        zk::components::unnormalized_lagrange_basis<ArithmetizationType,
                                                                    W0,
                                                                    W1,
                                                                    W2,
                                                                    W3,
                                                                    W4,
                                                                    W5,
                                                                    W6,
                                                                    W7,
                                                                    W8,
                                                                    W9,
                                                                    W10,
                                                                    W11,
                                                                    W12,
                                                                    W13,
                                                                    W14>;

                    using evaluations_type =
                        typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>;

                    constexpr static const std::size_t selector_seed = 0x0f31;

                    constexpr static const std::size_t mds_size = 3;

                    static std::array<std::array<var, mds_size>, mds_size> mds_vars(const std::size_t start_row) {
                        std::array<std::array<var, mds_size>, mds_size> result;
                        std::size_t mds_start_row = start_row;

                        for (std::size_t i = 0; i < mds_size; ++i) {
                            for (std::size_t j = 0; j < mds_size; ++j) {
                                result[i][j] =
                                    var(0, mds_start_row + i * mds_size + j, false, var::column_type::constant);
                            }
                        }
                        return result;
                    }

                    static var var_from_evals(const std::array<evaluations_type, KimchiParamsType::eval_points_amount>
                                                  evaluations,
                                              const std::size_t var_column,
                                              const std::size_t var_row) {
                        auto evals = evaluations[var_row];

                        /// 0 - witness_columns: witnesses
                        /// witness_columns + 1: z
                        /// witness_columns + 2: PoseidonSelector
                        /// witness_columns + 3: GenericSelector
                        /// witness_columns + 4: LookupAggreg
                        /// witness_columns + 5: LookupTable
                        /// witness_columns + 6: LookupRuntimeTable
                        /// witness_columns + 7+: LookupSorted

                        if (var_column < KimchiParamsType::witness_columns) {
                            return evals.w[var_column];
                        }

                        switch (var_column) {
                            case KimchiParamsType::witness_columns + 1:
                                return evals.z;
                            case KimchiParamsType::witness_columns + 2:
                                return evals.poseidon_selector;
                            case KimchiParamsType::witness_columns + 3:
                                return evals.generic_selector;
                            case KimchiParamsType::witness_columns + 4:
                                return evals.lookup.aggreg;
                            case KimchiParamsType::witness_columns + 5:
                                return evals.lookup.table;
                            case KimchiParamsType::witness_columns + 6:
                                return evals.lookup.runtime;
                            default:
                                break;
                        }

                        assert(var_column <= KimchiParamsType::witness_columns + 6 +
                                                 KimchiParamsType::circuit_params::lookup_columns);

                        return evals.lookup.sorted[var_column - KimchiParamsType::witness_columns - 7];
                    }

                    enum token_type {
                        alpha,
                        beta,
                        gamma,
                        joint_combiner,
                        endo_coefficient,
                        mds,
                        literal,
                        cell,
                        dup,
                        pow,
                        add,
                        mul,
                        sub,
                        vanishes_on_last_4_rows,
                        unnormalized_lagrange_basis,
                        store,
                        load
                    };

                    struct token_value_type {
                        token_type type;
                        std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>
                            value;
                        int int_data;
                    };

                    static std::vector<token_value_type> rpn_from_string(const std::string_view expression) {

                        std::vector<std::string> tokens_str;
                        boost::split(tokens_str, expression, boost::is_any_of(";"));
                        for (std::size_t i = 0; i < tokens_str.size(); i++) {
                            boost::trim(tokens_str[i]);
                        }

                        std::vector<token_value_type> tokens;
                        for (std::size_t i = 0; i < tokens_str.size(); i++) {

                            std::string token_str = tokens_str[i];
                            if (token_str.empty()) {
                                continue;
                            }

                            token_value_type token;

                            if (token_str.find("Alpha") != std::string::npos) {
                                token.type = token_type::alpha;
                            } else if (token_str.find("Beta") != std::string::npos) {
                                token.type = token_type::beta;
                            } else if (token_str.find("Gamma") != std::string::npos) {
                                token.type = token_type::gamma;
                            } else if (token_str.find("JointCombiner") != std::string::npos) {
                                token.type = token_type::joint_combiner;
                            } else if (token_str.find("EndoCoefficient") != std::string::npos) {
                                token.type = token_type::endo_coefficient;
                            } else if (token_str.find("Mds") != std::string::npos) {
                                token.type = token_type::mds;
                                std::size_t row_pos = token_str.find("row");
                                row_pos += 5;
                                std::size_t row_end_pos = token_str.find(" ", row_pos);
                                std::string row_str = token_str.substr(row_pos, row_end_pos - row_pos);
                                token.value.first = std::stoi(row_str);

                                std::size_t col_pos = token_str.find("col");
                                col_pos += 5;
                                std::size_t col_end_pos = token_str.find(" ", col_pos);
                                std::string col_str = token_str.substr(col_pos, col_end_pos - col_pos);
                                token.value.second = std::stoi(col_str);
                            } else if (token_str.find("Literal") != std::string::npos) {
                                token.type = token_type::literal;
                                std::size_t value_start_pos = token_str.find("Literal") + 8;
                                std::size_t value_end_pos = token_str.find(";", value_start_pos);
                                std::string value_str =
                                    token_str.substr(value_start_pos, value_end_pos - value_start_pos);
                                token.value.first = multiprecision::cpp_int("0x" + value_str);
                            } else if (token_str.find("Cell") != std::string::npos) {
                                token.type = token_type::cell;

                                std::size_t row_pos = token_str.find("row");
                                std::size_t row;
                                if (token_str.find("Curr", row_pos) != std::string::npos) {
                                    row = 0;
                                } else {    // Next
                                    row = 1;
                                }

                                std::size_t col_pos = token_str.find("col");
                                std::size_t col;
                                if (token_str.find("Witness", col_pos) != std::string::npos) {
                                    // Witness(col)
                                    std::size_t witness_pos = token_str.find("Witness", col_pos);
                                    std::size_t col_start_pow = witness_pos + 8;
                                    std::size_t col_end_pow = token_str.find(")", col_start_pow);
                                    std::string col_str = token_str.substr(col_start_pow, col_end_pow - col_start_pow);
                                    col = std::stoi(col_str);
                                } else {
                                    std::array<std::string, 6> column_types = {"Z",           "Poseidon",
                                                                               "Generic",     "LookupAggreg",
                                                                               "LookupTable", "LookupRuntimeTable"};
                                    for (std::size_t i = 0; i < column_types.size(); i++) {
                                        if (token_str.find(column_types[i]) != std::string::npos) {
                                            col = KimchiParamsType::witness_columns + i + 1;
                                            break;
                                        }
                                    }

                                    // lookup_sorted
                                    if (token_str.find("LookupSorted") != std::string::npos) {
                                        std::size_t col_start_pos = token_str.find("LookupSorted", col_pos) + 14;
                                        std::size_t col_end_pos = token_str.find(")", col_start_pos);
                                        std::string col_str =
                                            token_str.substr(col_start_pos, col_end_pos - col_start_pos);
                                        col = KimchiParamsType::witness_columns + 7 + std::stoi(col_str);
                                    }
                                }

                                token.value.first = col;
                                token.value.second = row;
                            } else if (token_str.find("Dup") != std::string::npos) {
                                token.type = token_type::dup;
                            } else if (token_str.find("Pow") != std::string::npos) {
                                token.type = token_type::pow;

                                std::size_t exp_start_pos = token_str.find("Pow") + 4;
                                std::size_t exp_end_pos = token_str.find(")", exp_start_pos);
                                std::string exp_str = token_str.substr(exp_start_pos, exp_end_pos - exp_start_pos);
                                token.value.first = std::stoi(exp_str);
                            } else if (token_str.find("Add") != std::string::npos) {
                                token.type = token_type::add;
                            } else if (token_str.find("Mul") != std::string::npos) {
                                token.type = token_type::mul;
                            } else if (token_str.find("Sub") != std::string::npos) {
                                token.type = token_type::sub;
                            } else if (token_str.find("VanishesOnLast4Rows") != std::string::npos) {
                                token.type = token_type::vanishes_on_last_4_rows;
                            } else if (token_str.find("UnnormalizedLagrangeBasis") != std::string::npos) {
                                token.type = token_type::unnormalized_lagrange_basis;

                                std::size_t exp_start_pos = token_str.find("UnnormalizedLagrangeBasis");
                                exp_start_pos = token_str.find("(", exp_start_pos) + 1;
                                std::size_t exp_end_pos = token_str.find(")", exp_start_pos);
                                std::string exp_str = token_str.substr(exp_start_pos, exp_end_pos - exp_start_pos);
                                token.int_data = std::stoi(exp_str);
                            } else if (token_str.find("Store") != std::string::npos) {
                                token.type = token_type::store;
                            } else if (token_str.find("Load") != std::string::npos) {
                                token.type = token_type::load;

                                std::size_t idx_start_pos = token_str.find("Load") + 5;
                                std::size_t idx_end_pos = token_str.find(")", idx_start_pos);
                                std::string idx_str = token_str.substr(idx_start_pos, idx_end_pos - idx_start_pos);
                                token.value.first = std::stoi(idx_str);
                            } else {
                                throw std::runtime_error("Unknown token type");
                            }

                            tokens.push_back(token);
                        }

                        return tokens;
                    }

                public:
                    constexpr static const std::size_t rows_amount = NRows;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::string_view expression;

                        var eval_point;    // zeta

                        var alpha;
                        var beta;
                        var gamma;
                        var joint_combiner;

                        std::array<evaluations_type, KimchiParamsType::eval_points_amount> evaluations;

                        var group_gen;
                        std::size_t domain_size;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t start_row_index) {
                            std::size_t row = start_row_index;
                        }

                        result_type() {
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        generate_assignments_constants(assignment, params, start_row_index);

                        std::vector<token_value_type> tokens = rpn_from_string(params.expression);

                        std::vector<var> stack;
                        std::vector<var> cache;

                        var endo_factor(0, row, false, var::column_type::constant);
                        row++;

                        auto mds = mds_vars(row);
                        row += mds_size * mds_size;

                        for (token_value_type t : tokens) {
                            switch (t.type) {
                                case token_type::alpha:
                                    stack.emplace_back(params.alpha);
                                    break;
                                case token_type::beta:
                                    stack.emplace_back(params.beta);
                                    break;
                                case token_type::gamma:
                                    stack.emplace_back(params.gamma);
                                    break;
                                case token_type::joint_combiner:
                                    stack.emplace_back(params.joint_combiner);
                                    break;
                                case token_type::endo_coefficient:
                                    stack.emplace_back(endo_factor);
                                    break;
                                case token_type::mds: {
                                    std::size_t mds_row = (std::size_t)
                                        typename BlueprintFieldType::integral_type(t.value.first.data);
                                    std::size_t mds_col = (std::size_t)
                                        typename BlueprintFieldType::integral_type(t.value.second.data);
                                    stack.emplace_back(mds[mds_row][mds_col]);
                                    break;
                                }
                                case token_type::literal: {
                                    var literal(0, row, false, var::column_type::constant);
                                    stack.emplace_back(literal);
                                    row++;
                                    break;
                                }
                                case token_type::cell: {
                                    std::size_t cell_col = (std::size_t)
                                        typename BlueprintFieldType::integral_type(t.value.first.data);
                                    std::size_t cell_row = (std::size_t)
                                        typename BlueprintFieldType::integral_type(t.value.second.data);
                                    var cell_val = var_from_evals(params.evaluations, cell_col, cell_row);
                                    stack.emplace_back(cell_val);
                                    break;
                                }
                                case token_type::dup:
                                    stack.emplace_back(stack.back());
                                    break;
                                case token_type::pow: {
                                    var exponent(0, row, false, var::column_type::constant);
                                    row++;

                                    var res = zk::components::generate_circuit<exponentiation_component>(
                                                  bp, assignment, {stack.back(), exponent}, row)
                                                  .output;
                                    row += exponentiation_component::rows_amount;
                                    stack[stack.size() - 1] = res;
                                    break;
                                }
                                case token_type::add: {
                                    var x = stack.back();
                                    stack.pop_back();
                                    var y = stack.back();
                                    stack.pop_back();
                                    var res =
                                        zk::components::generate_circuit<add_component>(bp, assignment, {x, y}, row)
                                            .output;
                                    row += add_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::mul: {
                                    var x = stack.back();
                                    stack.pop_back();
                                    var y = stack.back();
                                    stack.pop_back();
                                    var res =
                                        zk::components::generate_circuit<mul_component>(bp, assignment, {x, y}, row)
                                            .output;
                                    row += mul_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::sub: {
                                    var x = stack.back();
                                    stack.pop_back();
                                    var y = stack.back();
                                    stack.pop_back();
                                    var res =
                                        zk::components::generate_circuit<sub_component>(bp, assignment, {y, x}, row)
                                            .output;
                                    row += sub_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::vanishes_on_last_4_rows: {
                                    var res = vanishes_on_last_4_rows_component::generate_circuit(
                                                  bp,
                                                  assignment,
                                                  {params.group_gen, params.domain_size, params.eval_point},
                                                  row)
                                                  .output;
                                    row += vanishes_on_last_4_rows_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::unnormalized_lagrange_basis: {
                                    var res = unnormalized_lagrange_basis_component::generate_circuit(
                                                  bp,
                                                  assignment,
                                                  {params.group_gen, params.domain_size, params.eval_point, t.int_data},
                                                  row)
                                                  .output;
                                    row += unnormalized_lagrange_basis_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::store: {
                                    var x = stack.back();
                                    cache.emplace_back(x);
                                    break;
                                }
                                case token_type::load: {
                                    std::size_t idx = (std::size_t) typename BlueprintFieldType::integral_type(t.value.first.data);
                                    stack.push_back(cache[idx]);
                                    break;
                                }
                            }
                        }

                        assert(row == start_row_index + rows_amount);

                        result_type res;
                        res.output = stack[stack.size() - 1];
                        return res;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::vector<token_value_type> tokens = rpn_from_string(params.expression);

                        std::vector<var> stack;
                        std::vector<var> cache;

                        var endo_factor(0, row, false, var::column_type::constant);
                        row += 1;

                        auto mds = mds_vars(row);
                        row += mds_size * mds_size;

                        for (token_value_type t : tokens) {
                            switch (t.type) {
                                case token_type::alpha:
                                    stack.emplace_back(params.alpha);
                                    break;
                                case token_type::beta:
                                    stack.emplace_back(params.beta);
                                    break;
                                case token_type::gamma:
                                    stack.emplace_back(params.gamma);
                                    break;
                                case token_type::joint_combiner:
                                    stack.emplace_back(params.joint_combiner);
                                    break;
                                case token_type::endo_coefficient:
                                    stack.emplace_back(endo_factor);
                                    break;
                                case token_type::mds: {
                                    std::size_t mds_row = (std::size_t)
                                        typename BlueprintFieldType::integral_type(t.value.first.data);
                                    std::size_t mds_col = (std::size_t)
                                        typename BlueprintFieldType::integral_type(t.value.second.data);
                                    stack.emplace_back(mds[mds_row][mds_col]);
                                    break;
                                }
                                case token_type::literal: {
                                    var literal(0, row, false, var::column_type::constant);
                                    stack.emplace_back(literal);
                                    row++;
                                    break;
                                }
                                case token_type::cell: {
                                    std::size_t cell_col = (std::size_t)
                                        typename BlueprintFieldType::integral_type(t.value.first.data);
                                    std::size_t cell_row = (std::size_t)
                                        typename BlueprintFieldType::integral_type(t.value.second.data);
                                    var cell_val = var_from_evals(params.evaluations, cell_col, cell_row);
                                    stack.emplace_back(cell_val);
                                    break;
                                }
                                case token_type::dup:
                                    stack.emplace_back(stack.back());
                                    break;
                                case token_type::pow: {
                                    var exponent(0, row, false, var::column_type::constant);
                                    row++;

                                    var res = exponentiation_component::generate_assignments(
                                                  assignment, {stack.back(), exponent}, row)
                                                  .output;
                                    row += exponentiation_component::rows_amount;

                                    stack[stack.size() - 1] = res;
                                    break;
                                }
                                case token_type::add: {
                                    var x = stack.back();
                                    stack.pop_back();
                                    var y = stack.back();
                                    stack.pop_back();
                                    var res = add_component::generate_assignments(assignment, {x, y}, row).output;
                                    row += add_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::mul: {
                                    var x = stack.back();
                                    stack.pop_back();
                                    var y = stack.back();
                                    stack.pop_back();
                                    var res = mul_component::generate_assignments(assignment, {x, y}, row).output;
                                    row += mul_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::sub: {
                                    var x = stack.back();
                                    stack.pop_back();
                                    var y = stack.back();
                                    stack.pop_back();
                                    var res = sub_component::generate_assignments(assignment, {y, x}, row).output;
                                    row += sub_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::vanishes_on_last_4_rows: {
                                    var res =
                                        vanishes_on_last_4_rows_component::generate_assignments(
                                            assignment, {params.group_gen, params.domain_size, params.eval_point}, row)
                                            .output;
                                    row += vanishes_on_last_4_rows_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::unnormalized_lagrange_basis: {
                                    var res = unnormalized_lagrange_basis_component::generate_assignments(
                                                  assignment,
                                                  {params.group_gen, params.domain_size, params.eval_point, t.int_data},
                                                  row)
                                                  .output;
                                    row += unnormalized_lagrange_basis_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::store: {
                                    var x = stack.back();
                                    cache.emplace_back(x);
                                    break;
                                }
                                case token_type::load: {
                                    std::size_t idx = (std::size_t) typename BlueprintFieldType::integral_type(t.value.first.data);
                                    stack.push_back(cache[idx]);
                                    break;
                                }
                            }
                        }

                        assert(row == start_row_index + rows_amount);

                        result_type res;
                        res.output = stack[stack.size() - 1];
                        return res;
                    }

                private:
                    static void generate_assignments_constants(
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        typename KimchiParamsType::curve_type::base_field_type::integral_type endo_integral_base =
                            typename KimchiParamsType::curve_type::base_field_type::integral_type(
                                endo_scalar_component::endo_q.data);
                        typename BlueprintFieldType::integral_type endo_integral = endo_integral_base;
                        assignment.constant(0)[row] = typename BlueprintFieldType::value_type(endo_integral);
                        row++;

                        std::array<std::array<typename BlueprintFieldType::value_type, mds_size>, mds_size> mds =
                            poseidon_component::mds_constants();
                        for (std::size_t i = 0; i < mds_size; i++) {
                            for (std::size_t j = 0; j < mds_size; j++) {
                                assignment.constant(0)[row] = mds[i][j];
                                row++;
                            }
                        }

                        std::vector<token_value_type> tokens = rpn_from_string(params.expression);

                        for (token_value_type t : tokens) {
                            switch (t.type) {
                                case token_type::literal: {
                                    assignment.constant(0)[row] = t.value.first;
                                    row++;
                                    break;
                                }
                                case token_type::pow: {
                                    assignment.constant(0)[row] = t.value.first;
                                    row++;
                                    row += exponentiation_component::rows_amount;
                                    break;
                                }
                                case token_type::add: {
                                    row += add_component::rows_amount;
                                    break;
                                }
                                case token_type::mul: {
                                    row += mul_component::rows_amount;
                                    break;
                                }
                                case token_type::sub: {
                                    row += sub_component::rows_amount;
                                    break;
                                }
                                case token_type::vanishes_on_last_4_rows: {
                                    row += vanishes_on_last_4_rows_component::rows_amount;
                                    break;
                                }
                                case token_type::unnormalized_lagrange_basis: {
                                    row += unnormalized_lagrange_basis_component::rows_amount;
                                    break;
                                }
                            }
                        }
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_RPN_EXPRESSION_HPP
