//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_LOOKUP_ARGUMENT_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_LOOKUP_ARGUMENT_HPP

#include <unordered_map>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_scoped_profiler.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType, typename CommitmentSchemeTypePermutation, typename ParamsType>
                class placeholder_lookup_argument_prover {
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using polynomial_dfs_type = math::polynomial_dfs<typename FieldType::value_type>;
                    using VariableType = plonk_variable<typename FieldType::value_type>;
                    using DfsVariableType = plonk_variable<polynomial_dfs_type>;
                    using commitment_scheme_type = CommitmentSchemeTypePermutation;


                    static constexpr std::size_t argument_size = 4;

                    typedef detail::placeholder_policy<FieldType, ParamsType> policy_type;

                public:

                    struct prover_lookup_result {
                        std::array<math::polynomial_dfs<typename FieldType::value_type>, argument_size> F_dfs;
                        typename commitment_scheme_type::commitment_type lookup_commitment;
                    };

                    placeholder_lookup_argument_prover(
                            const plonk_constraint_system<FieldType>
                                &constraint_system,
                            const typename placeholder_public_preprocessor<FieldType, ParamsType>::preprocessed_data_type
                                &preprocessed_data,
                            const plonk_polynomial_dfs_table<FieldType>
                                &plonk_columns,
                            commitment_scheme_type &commitment_scheme,
                            transcript_type &transcript)
                        : constraint_system(constraint_system)
                        , preprocessed_data(preprocessed_data)
                        , plonk_columns(plonk_columns)
                        , commitment_scheme(commitment_scheme)
                        , transcript(transcript)
                        , basic_domain(preprocessed_data.common_data.basic_domain)
                        , lookup_gates(constraint_system.lookup_gates())
                        , lookup_tables(constraint_system.lookup_tables())
                    {
                        // $/theta = \challenge$
                        theta = transcript.template challenge<FieldType>();
                    }

                    prover_lookup_result prove_eval() {
                        PROFILE_PLACEHOLDER_SCOPE("Lookup argument prove eval time");

                        // Construct lookup gates
                        math::polynomial_dfs<typename FieldType::value_type> one_polynomial(
                            0, basic_domain->m, FieldType::value_type::one());
                        math::polynomial_dfs<typename FieldType::value_type> zero_polynomial(
                            0, basic_domain->m, FieldType::value_type::zero());
                        math::polynomial_dfs<typename FieldType::value_type> mask_assignment =
                            one_polynomial -  preprocessed_data.q_last - preprocessed_data.q_blind;

                        std::unique_ptr<std::vector<math::polynomial_dfs<typename FieldType::value_type>>> lookup_value_ptr =
                            prepare_lookup_value(mask_assignment);
                        auto& lookup_value = *lookup_value_ptr;

                        std::unique_ptr<std::vector<math::polynomial_dfs<typename FieldType::value_type>>> lookup_input_ptr =
                            prepare_lookup_input();
                        auto& lookup_input = *lookup_input_ptr;

                        // 3. Lookup_input and lookup_value are ready
                        //    Now sort them!
                        //    Reduce value and input:
                        auto reduced_value_ptr = std::make_unique<std::vector<math::polynomial_dfs<typename FieldType::value_type>>>();
                        auto& reduced_value = *reduced_value_ptr;

                        for( std::size_t i = 0; i < lookup_value.size(); i++ ){
                            reduced_value.push_back(reduce_dfs_polynomial_domain(lookup_value[i], basic_domain->m));
                        }
                        auto reduced_input_ptr = std::make_unique<std::vector<math::polynomial_dfs<typename FieldType::value_type>>>();
                        auto& reduced_input = *reduced_input_ptr;

                        for( std::size_t i = 0; i < lookup_input.size(); i++ ){
                            reduced_input.push_back(reduce_dfs_polynomial_domain(lookup_input[i], basic_domain->m));
                        }
                        //    Sort
                        auto sorted = sort_polynomials(reduced_input, reduced_value, basic_domain->m,
                            preprocessed_data.common_data.usable_rows_amount);

                        // 4. Commit sorted polys
                        for( std::size_t i = 0; i < sorted.size(); i++){
                            commitment_scheme.append_to_batch(LOOKUP_BATCH, sorted[i]);
                        }
                        typename commitment_scheme_type::commitment_type lookup_commitment = commitment_scheme.commit(LOOKUP_BATCH);
                        transcript(lookup_commitment);

                        //5. Compute V_L polynomial.
                        typename FieldType::value_type beta  = transcript.template challenge<FieldType>();
                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();

                        math::polynomial_dfs<typename FieldType::value_type> V_L = compute_V_L(
                            sorted, reduced_input, reduced_value, beta, gamma);

                        // We don't use reduced_input and reduced_value after this line.
                        reduced_input_ptr.reset(nullptr);
                        reduced_value_ptr.reset(nullptr);

                        commitment_scheme.append_to_batch(PERMUTATION_BATCH, V_L);

                        BOOST_CHECK(V_L[preprocessed_data.common_data.usable_rows_amount] ==  FieldType::value_type::one());

                        // After this call of compute_g lookup_input_ptr and lookup_value_ptr are deleted.
                        math::polynomial_dfs<typename FieldType::value_type> g = compute_g(
                            std::move(lookup_input_ptr), std::move(lookup_value_ptr), beta, gamma);

                        math::polynomial_dfs<typename FieldType::value_type> h = compute_h(sorted, beta, gamma);
                        math::polynomial_dfs<typename FieldType::value_type> V_L_shifted =
                            math::polynomial_shift(V_L, 1, basic_domain->m);

                        std::array<math::polynomial_dfs<typename FieldType::value_type>, argument_size> F_dfs;

                        F_dfs[0] = preprocessed_data.common_data.lagrange_0 * (one_polynomial - V_L);
                        F_dfs[1] = preprocessed_data.q_last * ( V_L * V_L - V_L );

                        // Polynomial g is waaay too large, saving memory here, by making code very unreadable.
                        //F_dfs[2] = (one_polynomial - (preprocessed_data.q_last + preprocessed_data.q_blind)) *
                        //           (V_L_shifted * h - V_L * g);
                        g *= V_L;
                        h *= V_L_shifted;
                        g -= h;
                        h = math::polynomial_dfs<typename FieldType::value_type>(); // just clean the memory of h.
                        g *= (preprocessed_data.q_last + preprocessed_data.q_blind) - one_polynomial;
                        F_dfs[2] = std::move(g);

                        F_dfs[3] = zero_polynomial;

                        for (std::size_t i = 1; i < sorted.size(); i++) {
                            typename FieldType::value_type alpha =  transcript.template challenge<FieldType>();
                            math::polynomial_dfs sorted_shifted = math::polynomial_shift(sorted[i-1], preprocessed_data.common_data.usable_rows_amount , basic_domain->m);
                            F_dfs[3] += alpha * preprocessed_data.common_data.lagrange_0 * (sorted[i] - sorted_shifted);
                        }

/*                        for( std::size_t i = 0; i < basic_domain->m; i++){
                            BOOST_CHECK( F_dfs[0].evaluate(basic_domain->get_domain_element(i)) == FieldType::value_type::zero() );
                            BOOST_CHECK( F_dfs[1].evaluate(basic_domain->get_domain_element(i)) == FieldType::value_type::zero() );
                            BOOST_CHECK( F_dfs[2].evaluate(basic_domain->get_domain_element(i)) == FieldType::value_type::zero() );
                            BOOST_CHECK( F_dfs[3].evaluate(basic_domain->get_domain_element(i)) == FieldType::value_type::zero() );
                        }*/

                        return {
                            std::move(F_dfs),
                            std::move(lookup_commitment)
                        };
                    }

                    math::polynomial_dfs<typename FieldType::value_type> compute_g(
                            std::unique_ptr<std::vector<math::polynomial_dfs<typename FieldType::value_type>>> lookup_input_ptr,
                            std::unique_ptr<std::vector<math::polynomial_dfs<typename FieldType::value_type>>> lookup_value_ptr,
                            const typename FieldType::value_type& beta,
                            const typename FieldType::value_type& gamma) {

                        auto& lookup_value = *lookup_value_ptr;
                        auto& lookup_input = *lookup_input_ptr;

                        auto g = math::polynomial_dfs<typename FieldType::value_type>::one();
                        auto one = FieldType::value_type::one();
                        g *= (one + beta).pow(lookup_input.size());

                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> g_multipliers;
                        for (std::size_t i = 0; i < lookup_input.size(); i++) {
                            g_multipliers.push_back(gamma + lookup_input[i]);
                        }

                        // We don't use lookup_input after this line.
                        lookup_input_ptr.reset(nullptr);

                        auto part1 = (one+beta) * gamma;
                        for (std::size_t i = 0; i < lookup_value.size(); i++) {
                            auto lookup_shifted = math::polynomial_shift(lookup_value[i], 1, basic_domain->m);
                            g_multipliers.push_back( part1 + lookup_value[i] + beta * lookup_shifted);
                        }

                        // We don't use lookup_value after this line.
                        lookup_value_ptr.reset(nullptr);

                        g *= math::polynomial_product<FieldType>(std::move(g_multipliers));
                        return g;
                    }

                    math::polynomial_dfs<typename FieldType::value_type> compute_h(
                            const std::vector<math::polynomial_dfs<typename FieldType::value_type>>& sorted,
                            const typename FieldType::value_type& beta,
                            const typename FieldType::value_type& gamma
                        ) {
                        auto one = FieldType::value_type::one();

                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> h_multipliers;
                        for (std::size_t i = 0; i < sorted.size(); i++) {
                            auto sorted_shifted = math::polynomial_shift(sorted[i], 1, basic_domain->m);
                            h_multipliers.push_back((one + beta) * gamma + sorted[i] + beta * sorted_shifted);
                        }
                        return math::polynomial_product<FieldType>(h_multipliers);
                    }

                    math::polynomial_dfs<typename FieldType::value_type> compute_V_L(
                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>>& sorted,
                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>>& reduced_input,
                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>>& reduced_value,
                        const typename FieldType::value_type& beta,
                        const typename FieldType::value_type& gamma) {

                        math::polynomial_dfs<typename FieldType::value_type> V_L(
                            basic_domain->m-1,basic_domain->m, FieldType::value_type::zero());
                        V_L[0] = FieldType::value_type::one();
                        auto one = FieldType::value_type::one();

                        for (std::size_t k = 1; k <= preprocessed_data.common_data.usable_rows_amount; k++) {
                            V_L[k] = V_L[k-1];

                            typename FieldType::value_type g_tmp = (one + beta).pow(reduced_input.size());
                            for (std::size_t i = 0; i < reduced_input.size(); i++) {
                                g_tmp *= gamma + reduced_input[i][k-1];
                            }

                            auto part1 = (one + beta) * gamma;
                            for (std::size_t i = 0; i < reduced_value.size(); i++) {
                                g_tmp *= part1 + reduced_value[i][k-1] + beta * reduced_value[i][k];
                            }

                            V_L[k] *= g_tmp;

                            typename FieldType::value_type h_tmp = FieldType::value_type::one();
                            for (std::size_t i = 0; i < sorted.size(); i++) {
                                h_tmp *= part1 + sorted[i][k-1] + beta * sorted[i][k];
                            }
                            V_L[k] *= h_tmp.inversed();
                        }
                        return V_L;
                    }

                    std::unique_ptr<std::vector<math::polynomial_dfs<typename FieldType::value_type>>> prepare_lookup_value(
                            const math::polynomial_dfs<typename FieldType::value_type>& mask_assignment) {
                        typename FieldType::value_type theta_acc;

                        // Prepare lookup value
                        auto lookup_value_ptr = std::make_unique<std::vector<math::polynomial_dfs<typename FieldType::value_type>>>();
                        for (std::size_t t_id = 0; t_id < lookup_tables.size(); t_id++) {
                            const plonk_lookup_table<FieldType> &l_table = lookup_tables[t_id];
                            const math::polynomial_dfs<typename FieldType::value_type> &lookup_tag = plonk_columns.selector(l_table.tag_index);
                            for (std::size_t o_id = 0; o_id < l_table.lookup_options.size(); o_id++) {
                                math::polynomial_dfs<typename FieldType::value_type> v = (typename FieldType::value_type(t_id + 1)) * lookup_tag;
                                theta_acc = theta;
                                for (std::size_t i = 0; i < l_table.columns_number; i++) {
                                    v += theta_acc * lookup_tag * plonk_columns.constant(l_table.lookup_options[o_id][i].index);
                                    theta_acc *= theta;
                                }
                                v *= mask_assignment;
                                lookup_value_ptr->push_back(v);
                            }
                        }
                        return std::move(lookup_value_ptr);
                    }

                    std::unique_ptr<std::vector<math::polynomial_dfs<typename FieldType::value_type>>> prepare_lookup_input() {
                        // Copied from gate argument.
                        // TODO: remove code duplication.
                        auto value_type_to_polynomial_dfs = [](
                            const typename VariableType::assignment_type& coeff) {
                                return polynomial_dfs_type(0, 1, coeff);
                            };

                        math::expression_variable_type_converter<VariableType, DfsVariableType> converter(
                            value_type_to_polynomial_dfs);

                        auto get_var_value = [&domain=basic_domain, &assignments=plonk_columns]
                        (const DfsVariableType &var) {
                            polynomial_dfs_type assignment;
                            switch (var.type) {
                                case DfsVariableType::column_type::witness:
                                    assignment = assignments.witness(var.index);
                                    break;
                                case DfsVariableType::column_type::public_input:
                                    assignment = assignments.public_input(var.index);
                                    break;
                                case DfsVariableType::column_type::constant:
                                    assignment = assignments.constant(var.index);
                                    break;
                                case DfsVariableType::column_type::selector:
                                    assignment = assignments.selector(var.index);
                                    break;
                            }

                            if (var.rotation != 0) {
                                assignment = math::polynomial_shift(assignment, var.rotation, domain->m);
                            }
                            return assignment;
                        };

                        typename FieldType::value_type theta_acc;

                        // Prepare lookup input
                        auto lookup_input_ptr = std::make_unique<std::vector<math::polynomial_dfs<typename FieldType::value_type>>>();
                        for (const auto &gate : lookup_gates) {
                            math::expression<DfsVariableType> expr;
                            math::polynomial_dfs<typename FieldType::value_type> lookup_selector = plonk_columns.selector(gate.tag_index);
                            for (const auto &constraint : gate.constraints) {
                                math::polynomial_dfs<typename FieldType::value_type> l = lookup_selector * (typename FieldType::value_type(constraint.table_id));
                                theta_acc = theta;
                                for(std::size_t k = 0; k < constraint.lookup_input.size(); k++){
                                    expr = converter.convert(constraint.lookup_input[k]);
                                    math::cached_expression_evaluator<DfsVariableType> evaluator(expr, get_var_value);

                                    l += theta_acc * lookup_selector * evaluator.evaluate();
                                    theta_acc *= theta;
                                }
                                lookup_input_ptr->push_back(l);
                            }
                        }
                        return std::move(lookup_input_ptr);
                    }


                private:

                    math::polynomial_dfs<typename FieldType::value_type> reduce_dfs_polynomial_domain(
                        const math::polynomial_dfs<typename FieldType::value_type> &polynomial,
                        const std::size_t &new_domain_size
                    ) {
                        math::polynomial_dfs<typename FieldType::value_type> reduced(
                            new_domain_size - 1, new_domain_size, FieldType::value_type::zero());

                        BOOST_ASSERT(new_domain_size <= polynomial.size());
                        if (polynomial.size() == new_domain_size) {
                            reduced = polynomial;
                        } else {
                            BOOST_ASSERT(polynomial.size() % new_domain_size == 0);

                            std::size_t step = polynomial.size() / new_domain_size;
                            for (std::size_t i = 0; i < new_domain_size; i++) {
                                reduced[i] = polynomial[i * step];
                            }
                        }
                        return reduced;
                    };

                    math::polynomial_dfs<typename FieldType::value_type> get_constraint_tag_from_gate_tag_column(
                        math::polynomial_dfs<typename FieldType::value_type> tag_column,
                        std::size_t constraints_num,
                        std::size_t constraint_id,
                        std::size_t table_id
                    ){
                        math::polynomial_dfs<typename FieldType::value_type> result = tag_column;
                        for (std::size_t i = 1; i <= constraints_num; i++) {
                            if (i != constraint_id) {
                                auto tmp = tag_column - typename FieldType::value_type(i);
                                tmp /=  (typename FieldType::value_type(constraint_id) - typename FieldType::value_type(i));
                                result *= tmp;
                            }
                        }
                        result /= constraint_id;
                        result *= table_id;
                        return result;
                    }

                    typename FieldType::value_type get_constraint_tag_value_from_gate_tag_value(
                        typename FieldType::value_type tag_value,
                        std::size_t constraints_num,
                        std::size_t constraint_id,
                        std::size_t table_id
                    ) {
                        typename FieldType::value_type result = tag_value;
                        for (std::size_t i = 1; i <= constraints_num; i++) {
                            if (i != constraint_id) {
                                auto tmp = tag_value - typename FieldType::value_type(i);
                                tmp /= typename FieldType::value_type(constraint_id) - typename FieldType::value_type(i);
                                result *= tmp;
                            }
                        }
                        result *= FieldType::value_type::one() / constraint_id;
                        result *= table_id;
                        return result;
                    }

                    // Each lookup table should fill full rectangle inside assignment table
                    // Lookup tables may contain repeated values, but they shoul be placed into one
                    // option one under another.
                    // Because of theta randomness compressed lookup tables' vectors for different table may contain
                    // similar values only with negligible probability.
                    // So similar values in compressed lookup tables vectors repeated values may be only in one column
                    // near each other.
                    std::vector<math::polynomial_dfs<typename FieldType::value_type>> sort_polynomials(
                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>>& reduced_input,
                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>>& reduced_value,
                        std::size_t domain_size,
                        std::size_t usable_rows_amount
                    ) {
                        //  Build sorting map
                        std::unordered_map<typename FieldType::value_type, std::size_t> sorting_map;
                        for (std::size_t i = 0; i < reduced_value.size(); i++) {
                            for (std::size_t j = 0; j < usable_rows_amount; j++) {
                                if(sorting_map.find(reduced_value[i][j]) != sorting_map.end())
                                    sorting_map[reduced_value[i][j]]++;
                                else
                                    sorting_map[reduced_value[i][j]] = 1;
                            }
                        }

                        for (std::size_t i = 0; i < reduced_input.size(); i++) {
                            for (std::size_t j = 0; j < usable_rows_amount; j++) {
                                // This assert means that every value \in keys of sorting_map = set of values of reduced_value
                                BOOST_ASSERT(sorting_map.find(reduced_input[i][j]) != sorting_map.end());
                                sorting_map[reduced_input[i][j]]++;
                            }
                        }

                        math::polynomial_dfs<typename FieldType::value_type> zero_poly(
                            domain_size-1, domain_size, FieldType::value_type::zero());
                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> sorted(
                            reduced_input.size() + reduced_value.size(), zero_poly
                        );
                        std::size_t i1=0;
                        std::size_t j1=0;
                        typename FieldType::value_type prev(0);
                        prev = typename FieldType::value_type(0);
                        auto append_to_sorted = [usable_rows_amount, &sorted, &i1, &j1] (const typename FieldType::value_type& value) {
                            sorted[i1][j1] = value;
                            j1++;
                            if (j1 >= usable_rows_amount){
                                i1++; j1 = 0;
                            }
                        };

                        for (std::size_t i = 0; i < reduced_value.size(); i++) {
                            for (std::size_t j = 0; j < usable_rows_amount; j++) {
                                if (reduced_value[i][j] != prev) {
                                    if (prev == FieldType::value_type::zero()) {
                                        BOOST_ASSERT(j1 < usable_rows_amount);
                                        append_to_sorted(prev);
                                    } else {
                                        for (std::size_t k = 0; k < sorting_map[prev]; k++) {
                                            BOOST_ASSERT(j1 < usable_rows_amount);
                                            append_to_sorted(prev);
                                        }
                                    }
                                    prev = reduced_value[i][j];
                                }
                            }
                        }
                        if (prev != FieldType::value_type::zero()) {
                            for (std::size_t k = 0; k < sorting_map[prev]; k++) {
                                //BOOST_ASSERT(j1 < usable_rows_amount);
                                append_to_sorted(prev);
                            }
                        }

                        for (std::size_t i = 0; i < sorted.size() - 1; i++) {
                            sorted[i][usable_rows_amount] = sorted[i+1][0];
                        }
                        return sorted;
                    }

                    const plonk_constraint_system<FieldType> &constraint_system;
                    const typename placeholder_public_preprocessor<FieldType, ParamsType>::preprocessed_data_type& preprocessed_data;
                    const plonk_polynomial_dfs_table<FieldType> &plonk_columns;
                    commitment_scheme_type& commitment_scheme;
                    transcript_type& transcript;
                    std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain;
                    const std::vector<plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>>>& lookup_gates;
                    const std::vector<plonk_lookup_table<FieldType>>& lookup_tables;
                    typename FieldType::value_type theta;

                };

                template<typename FieldType, typename CommitmentSchemeTypePermutation, typename ParamsType>
                class placeholder_lookup_argument_verifier {
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using polynomial_dfs_type = math::polynomial_dfs<typename FieldType::value_type>;
                    using VariableType = plonk_variable<typename FieldType::value_type>;
                    using DfsVariableType = plonk_variable<polynomial_dfs_type>;
                    using commitment_scheme_type = CommitmentSchemeTypePermutation;


                    static constexpr std::size_t argument_size = 4;

                    typedef detail::placeholder_policy<FieldType, ParamsType> policy_type;

                public:
                    std::array<typename FieldType::value_type, argument_size> verify_eval(
                        const typename placeholder_public_preprocessor<FieldType, ParamsType>::preprocessed_data_type &preprocessed_data,
                        const std::vector<plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>>> &lookup_gates,
                        const std::vector<plonk_lookup_table<FieldType>> &lookup_tables,
                        // y
                        const typename FieldType::value_type &challenge,
                        typename policy_type::evaluation_map &evaluations,
                        // sorted_batch_values. Pair value/shifted_value
                        const std::vector<std::vector<typename FieldType::value_type>> &sorted,
                        // V_L(y), V_L(omega* Y)
                        std::vector<typename FieldType::value_type> V_L_values,
                        // Commitment
                        const typename CommitmentSchemeTypePermutation::commitment_type &lookup_commitment,
                        transcript_type &transcript = transcript_type()
                    ) {
                        std::array<typename FieldType::value_type, argument_size> F;
                        // 1. Get theta
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();
                        typename FieldType::value_type omega = preprocessed_data.common_data.basic_domain->get_domain_element(1);


                        // 2. Add commitments to transcript
                        transcript(lookup_commitment);

                        // 3. Calculate lookup_value compression
                        typename FieldType::value_type one = FieldType::value_type::one();

                        auto mask_value = (one - (preprocessed_data.q_last.evaluate(challenge) + preprocessed_data.q_blind.evaluate(challenge)));
                        auto shifted_mask_value = (one - (preprocessed_data.q_last.evaluate(challenge*omega) + preprocessed_data.q_blind.evaluate(challenge*omega)));


                        typename FieldType::value_type theta_acc = FieldType::value_type::one();
                        std::vector<typename FieldType::value_type> lookup_value;
                        std::vector<typename FieldType::value_type> shifted_lookup_value;
                        for( std::size_t t_id = 0; t_id < lookup_tables.size(); t_id++){
                            const auto &table = lookup_tables[t_id];
                            auto key = std::tuple(table.tag_index, 0, plonk_variable<typename FieldType::value_type>::column_type::selector);
                            auto shifted_key = std::tuple(table.tag_index, 1, plonk_variable<typename FieldType::value_type>::column_type::selector);
                            auto selector_value = evaluations[key];
                            auto shifted_selector_value = evaluations[shifted_key];
                            for( std::size_t o_id = 0; o_id < table.lookup_options.size(); o_id++){
                                typename FieldType::value_type v = selector_value * (t_id + 1);
                                typename FieldType::value_type shifted_v = shifted_selector_value * (t_id + 1);

                                theta_acc = theta;
                                BOOST_ASSERT(table.lookup_options[o_id].size() == table.columns_number);
                                for( std::size_t i = 0; i < table.lookup_options[o_id].size(); i++){
                                    auto key1 = std::tuple(table.lookup_options[o_id][i].index, 0, plonk_variable<typename FieldType::value_type>::column_type::constant);
                                    auto shifted_key1 = std::tuple(table.lookup_options[o_id][i].index, 1, plonk_variable<typename FieldType::value_type>::column_type::constant);
                                    v += theta_acc * evaluations[key1] * selector_value;
                                    shifted_v += theta_acc * evaluations[shifted_key1]* shifted_selector_value;
                                    theta_acc *= theta;
                                }
                                v *= mask_value;
                                shifted_v *= shifted_mask_value;
                                lookup_value.push_back(v);
                                shifted_lookup_value.push_back(shifted_v);
                            }
                        }

                        // 4. Calculate compressed lookup inputs
                        std::vector<typename FieldType::value_type> lookup_input;
                        for( std::size_t g_id = 0; g_id < lookup_gates.size(); g_id++ ){
                            const auto &gate = lookup_gates[g_id];
                            auto key = std::tuple(gate.tag_index, 0, plonk_variable<typename FieldType::value_type>::column_type::selector);
                            auto selector_value = evaluations[key];
                            for( std::size_t c_id = 0; c_id < gate.constraints.size(); c_id++){
                                const auto &constraint = gate.constraints[c_id];
                                typename FieldType::value_type l = selector_value * constraint.table_id;
                                theta_acc = theta;
                                for( std::size_t k = 0; k < constraint.lookup_input.size(); k++ ) {
                                    l += selector_value * theta_acc * constraint.lookup_input[k].evaluate(evaluations);
                                    theta_acc *= theta;
                                }
                                lookup_input.push_back(l);
                            }
                        }

                        typename FieldType::value_type beta = transcript.template challenge<FieldType>();
                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();

                        typename FieldType::value_type g(1);
                        for( std::size_t i = 0; i < lookup_input.size(); i++){
                            g *= (one+beta)*(gamma + lookup_input[i]);
                        }
                        for( std::size_t i = 0; i < lookup_value.size(); i++ ){
                            g *= (one+beta) * gamma + lookup_value[i] + beta * shifted_lookup_value[i];
                        }

                        typename FieldType::value_type h(1);
                        for( std::size_t i = 0; i < sorted.size(); i++){
                            h *= (one+beta) * gamma + sorted[i][0] + beta * sorted[i][1];
                        }

                        auto V_L_value = V_L_values[0];
                        auto V_L_shifted = V_L_values[1];

                        F[0] = (one - V_L_value) * preprocessed_data.common_data.lagrange_0.evaluate(challenge);
                        F[1] = preprocessed_data.q_last.evaluate(challenge) * (V_L_value * V_L_value - V_L_value);
                        F[2] = (one - (preprocessed_data.q_last.evaluate(challenge) + preprocessed_data.q_blind.evaluate(challenge))) *
                                   (V_L_shifted * h - V_L_value * g);
                        F[3] = 0;
                        for( std::size_t i = 1; i < sorted.size(); i++ ){
                            typename FieldType::value_type alpha = transcript.template challenge<FieldType>();
                            F[3] += (sorted[i][0] - sorted[i-1][2]) * alpha * preprocessed_data.common_data.lagrange_0.evaluate(challenge);
                        }
                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // #ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_LOOKUP_ARGUMENT_HPP
