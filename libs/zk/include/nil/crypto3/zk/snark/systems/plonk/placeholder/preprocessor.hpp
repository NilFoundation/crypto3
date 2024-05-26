//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PREPROCESSOR_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_PREPROCESSOR_HPP

#include <set>
#include <iostream>
#include <sstream>
#include <string>
#include <map>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/detail/field_utils.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/permutation.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_scoped_profiler.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/detail/column_polynomial.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/transcript_initialization_context.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template <typename FieldType>
                std::vector<std::size_t> lookup_parts(
                    const plonk_constraint_system<FieldType> &constraint_system,
                    std::size_t max_quotient_chunks
                );

                template<typename FieldType, typename ParamsType>
                class placeholder_public_preprocessor {
                    typedef detail::placeholder_policy<FieldType, ParamsType> policy_type;
                    typedef typename plonk_constraint<FieldType>::variable_type variable_type;
                    typedef typename math::polynomial<typename FieldType::value_type> polynomial_type;
                    typedef typename math::polynomial_dfs<typename FieldType::value_type> polynomial_dfs_type;
                    using params_type = ParamsType;
                    using commitment_scheme_type = typename params_type::commitment_scheme_type;
                    using commitment_type = typename commitment_scheme_type::commitment_type;
                    using transcript_type = typename commitment_scheme_type::transcript_type;
                    using transcript_hash_type = typename commitment_scheme_type::transcript_hash_type;

                public:
                    static std::size_t permutation_partitions_num(
                        std::size_t permutation_size,
                        std::size_t max_quotient_chunks
                    ){
                        if( permutation_size == 0 ) return 0;
                        if( max_quotient_chunks == 0 ){
                            return 1;
                        }
                        return (permutation_size % (max_quotient_chunks - 1) == 0)? permutation_size / (max_quotient_chunks - 1) : permutation_size / (max_quotient_chunks - 1) + 1;
                    }

                    struct preprocessed_data_type {
                        struct public_commitments_type {
                            commitment_type fixed_values;

                            bool operator==(const public_commitments_type &rhs) const {
                                return  fixed_values == rhs.fixed_values;
                            }
                            bool operator!=(const public_commitments_type &rhs) const {
                                return !(rhs == *this);
                            }
                        };

                        struct verification_key {
                            typename transcript_hash_type::digest_type constraint_system_with_params_hash;
                            commitment_type                            fixed_values_commitment;

                            bool operator==(const verification_key &rhs) const {
                                return  constraint_system_with_params_hash == rhs.constraint_system_with_params_hash &&
                                        fixed_values_commitment == rhs.fixed_values_commitment;
                            }

                            bool operator!=(const verification_key &rhs) const {
                                return !(rhs == *this);
                            }


                            std::string to_string() const{
                                std::stringstream ss;

                                // TODO: KZG fixed_values_commitments are vector<uint8_t>
                                // need operator<<(ostream,vector<uint8_t>)?
                                ss << constraint_system_with_params_hash /*<< " " << fixed_values_commitment*/;
                                return ss.str();
                            }
                        };

                        // both prover and verifier use this data
                        // fields outside of the common_data_type are used by prover
                        struct common_data_type {
                            using field_type = FieldType;
                            using columns_rotations_type = std::vector<std::set<int>>;
                            using commitment_scheme_type = typename ParamsType::commitment_scheme_type;
                            using commitments_type = public_commitments_type;
                            using verification_key_type = verification_key;
                            using transcript_hash_type = typename ParamsType::transcript_hash_type;
                            using table_description_type = plonk_table_description<FieldType>;
                            using commitment_scheme_data_type = typename commitment_scheme_type::preprocessed_data_type;
                            using commitment_params_type = typename commitment_scheme_type::params_type;

                            // marshalled
                            public_commitments_type commitments;
                            columns_rotations_type columns_rotations;

                            table_description_type desc;

                            // not marshalled. They can be derived from other fields.
                            polynomial_dfs_type lagrange_0;
                            polynomial_type Z;
                            std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain;
                            std::uint32_t max_gates_degree;
                            verification_key vk;
                            commitment_scheme_data_type commitment_scheme_data;
                            commitment_params_type commitment_params;
                            std::vector<std::size_t> permuted_columns;
                            std::uint32_t max_quotient_chunks;
                            std::uint32_t permutation_parts;
                            std::uint32_t lookup_parts;

                            // Constructor with pregenerated domain
                            common_data_type(
                                std::shared_ptr<math::evaluation_domain<FieldType>> D,
                                public_commitments_type commts,
                                std::vector<std::set<int>> col_rotations,
                                const table_description_type &table_description,
                                std::uint32_t max_gates_degree,
                                std::uint32_t permutation_parts,
                                std::uint32_t lookup_parts,
                                verification_key vk,
                                const std::vector<std::size_t> &_permuted_columns,
                                const commitment_params_type &_commitment_params,
                                const commitment_scheme_data_type &_commitment_scheme_data,
                                std::size_t max_quotient_chunks = 0
                            ):  commitments(commts),
                                columns_rotations(col_rotations),
                                desc(table_description),
                                lagrange_0(D->size() - 1, D->size(), FieldType::value_type::zero()),
                                Z(std::vector<typename FieldType::value_type>(table_description.rows_amount + 1, FieldType::value_type::zero())),
                                basic_domain(D),
                                max_gates_degree(max_gates_degree),
                                vk(vk),
                                commitment_scheme_data(_commitment_scheme_data),
                                commitment_params(_commitment_params),
                                permuted_columns(_permuted_columns),
                                max_quotient_chunks(max_quotient_chunks),
                                permutation_parts(permutation_parts),
                                lookup_parts(lookup_parts)
                            {
                                // Z is polynomial -1, 0,..., 0, 1
                                Z[0] = -FieldType::value_type::one();
                                Z[Z.size()-1] = FieldType::value_type::one();

                                // lagrange_0(in dfs form):  1,0,...,0,0,0,...,0
                                lagrange_0[0] = FieldType::value_type::one();
                            }

                            // Constructor for marshalling. Domain is regenerated.
                            common_data_type(
                                public_commitments_type commts,
                                std::vector<std::set<int>> col_rotations,
                                const table_description_type &table_description,
                                std::uint32_t max_gates_degree,
                                std::uint32_t permutation_parts,
                                std::uint32_t lookup_parts,
                                verification_key vk,
                                const std::vector<std::size_t> &_permuted_columns,
                                const commitment_params_type &_commitment_params,
                                const commitment_scheme_data_type &_commitment_scheme_data,
                                std::size_t max_quotient_chunks
                            ):  commitments(commts),
                                columns_rotations(col_rotations),
                                desc(table_description),
                                lagrange_0(table_description.rows_amount - 1, table_description.rows_amount, FieldType::value_type::zero()),
                                Z(std::vector<typename FieldType::value_type>(table_description.rows_amount + 1, FieldType::value_type::zero())),
                                max_gates_degree(max_gates_degree),
                                vk(vk),
                                commitment_scheme_data(_commitment_scheme_data),
                                commitment_params(_commitment_params),
                                permuted_columns(_permuted_columns),
                                max_quotient_chunks(max_quotient_chunks),
                                permutation_parts(permutation_parts),
                                lookup_parts(lookup_parts)
                            {
                                // Z is polynomial -1, 0,..., 0, 1
                                Z[0] = -FieldType::value_type::one();
                                Z[Z.size()-1] = FieldType::value_type::one();

                                // lagrange_0:  1, 0,...,0
                                lagrange_0[0] = FieldType::value_type::one();

                                basic_domain = math::make_evaluation_domain<FieldType>(table_description.rows_amount);
                            }

                            // These operators are useful for marshalling
                            // They will be implemented with marshalling procedures implementation
                            bool operator==(const common_data_type &rhs) const {
                                return desc == rhs.desc &&
                                columns_rotations == rhs.columns_rotations &&
                                commitments == rhs.commitments &&
                                basic_domain->size() == rhs.basic_domain->size() &&
                                lagrange_0 == rhs.lagrange_0 &&
                                Z == rhs.Z &&
                                max_gates_degree == rhs.max_gates_degree
                                && vk == rhs.vk
                                && permuted_columns == rhs.permuted_columns
                                && commitment_params == rhs.commitment_params
                                && commitment_scheme_data == rhs.commitment_scheme_data
                                && max_quotient_chunks == rhs.max_quotient_chunks
                                && permutation_parts == rhs.permutation_parts
                                && lookup_parts == rhs.lookup_parts
                                ;
                            }
                            bool operator!=(const common_data_type &rhs) const {
                                return !(rhs == *this);
                            }
                        };

                        plonk_public_polynomial_dfs_table<FieldType> public_polynomial_table;

                        // S_sigma
                        std::vector<polynomial_dfs_type>  permutation_polynomials;
                        // S_id
                        std::vector<polynomial_dfs_type>  identity_polynomials;

                        polynomial_dfs_type               q_last;
                        polynomial_dfs_type               q_blind;

                        common_data_type                  common_data;
                    };

                private:
                    static polynomial_dfs_type lagrange_polynomial(
                        std::shared_ptr<math::evaluation_domain<FieldType>> domain,
                        std::size_t number
                    ) {
                        polynomial_dfs_type f(
                            domain->size() - 1,
                            domain->size(),
                            FieldType::value_type::zero()
                        );

                        if (number < domain->size()) {
                            f[number] = FieldType::value_type::one();
                        }

                        return f;
                    }

                    struct cycle_representation {
                        // Using std::uint32_t reduces RAM usage a bit. Our table size (rows_amount * width) will never be > 2^32 elements.
                        typedef std::pair<std::uint32_t, std::uint32_t> key_type;

                        std::map<key_type, key_type> _mapping;
                        std::map<key_type, key_type> _aux;
                        std::map<key_type, std::uint32_t> _sizes;

                        cycle_representation(
                            const plonk_constraint_system<FieldType>  &constraint_system,
                            const plonk_table_description<FieldType> &table_description
                        ) {
                            for (std::size_t i = 0;
                                 i < table_description.table_width() - table_description.selector_columns;
                                 i++) {
                                for (std::size_t j = 0; j < table_description.rows_amount; j++) {
                                    key_type key(i, j);
                                    this->_mapping[key] = key;
                                    this->_aux[key] = key;
                                    this->_sizes[key] = 1;
                                }
                            }

                            std::vector<plonk_copy_constraint<FieldType>> copy_constraints =
                                constraint_system.copy_constraints();
                            for (std::size_t i = 0; i < copy_constraints.size(); i++) {
                                std::size_t x_idx = table_description.global_index(copy_constraints[i].first);
                                key_type x = key_type(x_idx, copy_constraints[i].first.rotation);

                                std::size_t y_idx = table_description.global_index(copy_constraints[i].second);
                                key_type y = key_type(y_idx, copy_constraints[i].second.rotation);
                                this->apply_copy_constraint(x, y);
                            }
                        }

                        void apply_copy_constraint(key_type x, key_type y) {

                            if (!_mapping.count(x)) {
                                _mapping[x] = x;
                                _aux[x] = x;
                                _sizes[x] = 1;
                            }

                            if (!_mapping.count(y)) {
                                _mapping[y] = y;
                                _aux[y] = y;
                                _sizes[y] = 1;
                            }

                            if (_aux[x] != _aux[y]) {
                                key_type &left = x;
                                key_type &right = y;
                                if (_sizes[_aux[left]] < _sizes[_aux[right]]) {
                                    std::swap(left, right);
                                }

                                _sizes[_aux[left]] = _sizes[_aux[left]] + _sizes[_aux[right]];

                                key_type z = _aux[right];
                                key_type exit_condition = _aux[right];

                                do {
                                    _aux[z] = _aux[left];
                                    z = _mapping[z];
                                } while (z != exit_condition);

                                key_type tmp = _mapping[left];
                                _mapping[left] = _mapping[right];
                                _mapping[right] = tmp;
                            }
                        }

                        key_type &operator[](key_type key) {
                            return _mapping[key];
                        }
                    };

                public:
                    static inline std::vector<std::set<int>>
                    columns_rotations(
                        const plonk_constraint_system<FieldType> &constraint_system,
                        const plonk_table_description<FieldType> &table_description
                    ) {
                        std::vector<std::set<int>> result(table_description.table_width());

                        for (auto & s : result) {
                            s.insert(0);
                        }

                        math::expression_for_each_variable_visitor<variable_type> visitor(
                            [&table_description, &result](const variable_type& var) {
                                result[table_description.global_index(var)].insert(var.rotation);
                            }
                        );

                        for (const auto& gate: constraint_system.gates()) {
                            for (const auto& constraint: gate.constraints) {
                               	visitor.visit(constraint);
                            }
                        }

                        if( constraint_system.lookup_gates().size() != 0 ){
                            for (const auto& gate: constraint_system.lookup_gates()) {
                                for (const auto& constraint: gate.constraints) {
                                    for (const auto& expr: constraint.lookup_input) {
                                        visitor.visit(expr);
                                    }
                                }
                            }

                            for ( const auto &table : constraint_system.lookup_tables() ) {
                                result[
                                    table_description.witness_columns +
                                    table_description.public_input_columns +
                                    table_description.constant_columns +
                                    table.tag_index
                                ].insert(1);
                                for( const auto &option:table.lookup_options){
                                    for( const auto &column:option){
                                        result[
                                            table_description.witness_columns +
                                            table_description.public_input_columns +
                                            column.index
                                        ].insert(1);
                                    }
                                }
                            }
                        }

                        return result;
                    }

                    static inline std::vector<polynomial_dfs_type> identity_polynomials(
                        const std::size_t permutation_size,
                        const typename FieldType::value_type &omega,
                        const typename FieldType::value_type &delta,
                        std::shared_ptr<math::evaluation_domain<FieldType>> domain
                    ) {
                        std::vector<polynomial_dfs_type> S_id(permutation_size);

                        for (std::size_t i = 0; i < permutation_size; i++) {
                            S_id[i] = polynomial_dfs_type(
                                domain->size() - 1, domain->size(), FieldType::value_type::zero());

                            S_id[i][0] = delta.pow(i);
                            for (std::size_t j = 1; j < domain->size(); j++) {
                                S_id[i][j] = S_id[i][j-1] * omega;
                             }
                        }

                        return S_id;
                    }

                    static inline std::vector<polynomial_dfs_type> permutation_polynomials(
                        const std::vector<std::size_t> &global_indices, // ordered global indices
                        const typename FieldType::value_type &omega,
                        const typename FieldType::value_type &delta,
                        cycle_representation &permutation,
                        std::shared_ptr<math::evaluation_domain<FieldType>> domain
                    ) {
                        std::vector<polynomial_dfs_type> S_perm(global_indices.size());
                        for (std::size_t i = 0; i < global_indices.size(); i++) {
                            S_perm[i] = polynomial_dfs_type(
                                domain->size() - 1, domain->size(), FieldType::value_type::zero());

                            for (std::size_t j = 0; j < domain->size(); j++) {
                                auto key = std::make_pair(global_indices[i], j);
                                auto permuted_index = find(global_indices.begin(), global_indices.end(), permutation[key].first) - global_indices.begin();
                                S_perm[i][j] = delta.pow(permuted_index) * omega.pow(permutation[key].second);
                            }
                        }

                        return S_perm;
                    }

                    static inline polynomial_dfs_type selector_blind(
                        std::size_t usable_rows,
                        std::shared_ptr<math::evaluation_domain<FieldType>> domain
                    ) {
                        polynomial_dfs_type q_blind(domain->size() - 1, domain->size(), FieldType::value_type::zero());

                        for (std::size_t j = usable_rows + 1; j < domain->size(); j++) {
                            q_blind[j] = FieldType::value_type::one();
                        }

                        return q_blind;
                    }

                    static inline typename preprocessed_data_type::public_commitments_type commitments(
                        const plonk_public_polynomial_dfs_table<FieldType> &public_table,
                        std::vector<polynomial_dfs_type> &id_perm_polys,
                        std::vector<polynomial_dfs_type> &sigma_perm_polys,
                        std::array<polynomial_dfs_type, 2> &q_last_q_blind,
                        commitment_scheme_type &commitment_scheme
                    ) {
                        commitment_scheme.append_to_batch(FIXED_VALUES_BATCH, id_perm_polys);
                        commitment_scheme.append_to_batch(FIXED_VALUES_BATCH, sigma_perm_polys);
                        commitment_scheme.append_to_batch(FIXED_VALUES_BATCH, q_last_q_blind[0]);
                        commitment_scheme.append_to_batch(FIXED_VALUES_BATCH, q_last_q_blind[1]);
                        commitment_scheme.append_to_batch(FIXED_VALUES_BATCH, public_table.constants());
                        commitment_scheme.append_to_batch(FIXED_VALUES_BATCH, public_table.selectors());

                        auto result = typename preprocessed_data_type::public_commitments_type({commitment_scheme.commit(FIXED_VALUES_BATCH)});
                        commitment_scheme.mark_batch_as_fixed(FIXED_VALUES_BATCH);
                        return result;
                    }

                    // TODO: columns_with_copy_constraints -- It should be extracted from constraint_system
                    static inline preprocessed_data_type process(
                        const plonk_constraint_system<FieldType> &constraint_system,
                        typename policy_type::variable_assignment_type::public_table_type public_assignment,
                        const plonk_table_description<FieldType>
                            &table_description,
                        typename ParamsType::commitment_scheme_type &commitment_scheme,
                        // TODO(martun): move delta back to placeholder_params, once template arguments are reduced.
                        // To prevent work with too large polynomials during proof generation
                        //    if 0 -- any degree
                        //    else -- we have a bound for permutations and lookups F-s degree rows_amount * (2 ^ max_quotient_poly_expand)
                        const std::size_t max_quotient_poly_chunks = 0,
                        const typename FieldType::value_type& delta=algebra::fields::arithmetic_params<FieldType>::multiplicative_generator
                    ) {
                        PROFILE_PLACEHOLDER_SCOPE("Placeholder public preprocessor");

                        std::size_t N_rows = table_description.rows_amount;
                        std::size_t usable_rows = table_description.usable_rows_amount;

                        std::uint32_t max_gates_degree = std::max(
                            constraint_system.max_gates_degree(),
                            constraint_system.max_lookup_gates_degree()
                        );
                        assert(max_gates_degree > 0);

                        std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain =
                            math::make_evaluation_domain<FieldType>(N_rows);

                        // TODO: add std::vector<std::size_t> columns_with_copy_constraints;
                        cycle_representation permutation(constraint_system, table_description);

                        auto permuted_columns = constraint_system.permuted_columns();
                        std::vector<std::size_t> global_indices;
                        for( auto it = permuted_columns.begin(); it != permuted_columns.end(); it++ ){
                            global_indices.push_back(table_description.global_index(*it));
                        }

                        std::vector<polynomial_dfs_type> id_perm_polys =
                            identity_polynomials(permuted_columns.size(), basic_domain->get_domain_element(1),
                                                 delta, basic_domain);

                        std::vector<polynomial_dfs_type> sigma_perm_polys =
                            permutation_polynomials(global_indices, basic_domain->get_domain_element(1),
                                                    delta, permutation, basic_domain);

                        polynomial_dfs_type lagrange_0 = lagrange_polynomial(basic_domain, 0);

                        std::array<polynomial_dfs_type, 2> q_last_q_blind;
                        q_last_q_blind[0] = lagrange_polynomial(basic_domain, usable_rows);
                        q_last_q_blind[1] = selector_blind(usable_rows, basic_domain);

                        plonk_public_polynomial_dfs_table<FieldType>
                            public_polynomial_table =
                                plonk_public_polynomial_dfs_table<FieldType>(
                                    detail::column_range_polynomial_dfs<FieldType>(public_assignment.move_public_inputs(),
                                                                                   basic_domain),
                                    detail::column_range_polynomial_dfs<FieldType>(public_assignment.move_constants(),
                                                                                   basic_domain),
                                    detail::column_range_polynomial_dfs<FieldType>(public_assignment.move_selectors(),
                                                                                   basic_domain));

                        // prepare commitments for short verifier
                        //typename preprocessed_data_type::public_precommitments_type public_precommitments =
                        //    precommitments(public_polynomial_table, id_perm_polys, sigma_perm_polys, q_last_q_blind,
                        //                   commitment_params);

                        BOOST_ASSERT(max_quotient_poly_chunks == 0 || max_quotient_poly_chunks > max_gates_degree );
                        std::size_t permutation_parts_num = permutation_partitions_num(permuted_columns.size(), max_quotient_poly_chunks);
                        std::size_t lookup_parts_num = constraint_system.lookup_parts(max_quotient_poly_chunks).size();

                        typename preprocessed_data_type::public_commitments_type public_commitments = commitments(
                            public_polynomial_table, id_perm_polys,
                            sigma_perm_polys, q_last_q_blind, commitment_scheme
                        );

                        std::vector<std::set<int>> c_rotations =
                            columns_rotations(constraint_system, table_description);

                        typename transcript_hash_type::digest_type constraint_system_with_params_hash =
                            nil::crypto3::zk::snark::detail::compute_constraint_system_with_params_hash<ParamsType, transcript_hash_type>(
                                constraint_system,
                                table_description,
                                N_rows,
                                table_description.usable_rows_amount,
                                commitment_scheme.get_commitment_params(),
                                "Default application dependent transcript initialization string",
                                delta);

                        typename preprocessed_data_type::verification_key vk = {constraint_system_with_params_hash, public_commitments.fixed_values};

                        transcript_type transcript(std::vector<std::uint8_t>({}));
                        transcript(vk.constraint_system_with_params_hash);
                        transcript(vk.fixed_values_commitment);

                        typename preprocessed_data_type::common_data_type common_data (
                            std::move(public_commitments), std::move(c_rotations),
                            table_description,
                            max_gates_degree,
                            permutation_parts_num,
                            lookup_parts_num,
                            vk,
                            global_indices,
                            commitment_scheme.get_commitment_params(),
                            commitment_scheme.preprocess(transcript),
                            max_quotient_poly_chunks
                        );

                        // Push circuit description to transcript
                        preprocessed_data_type preprocessed_data({
                            std::move(public_polynomial_table),
                            std::move(sigma_perm_polys),
                            std::move(id_perm_polys),
                            std::move(q_last_q_blind[0]),
                            std::move(q_last_q_blind[1]),
                            std::move(common_data)
                        });

                        return preprocessed_data;
                    }
                };

                template<typename FieldType, typename ParamsType>
                class placeholder_private_preprocessor {
                    using policy_type = detail::placeholder_policy<FieldType, ParamsType>;

                public:
                    struct preprocessed_data_type {
                        std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain;

                        plonk_private_polynomial_dfs_table<FieldType> private_polynomial_table;
                    };

                    static inline preprocessed_data_type process(
                        const plonk_constraint_system<FieldType>  &constraint_system,
                        typename policy_type::variable_assignment_type::private_table_type private_assignment,
                        const plonk_table_description<FieldType>  &table_description
                    ) {
                        std::size_t N_rows = table_description.rows_amount;

                        std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain =
                            math::make_evaluation_domain<FieldType>(N_rows);

                        plonk_private_polynomial_dfs_table<FieldType>
                            private_polynomial_table(detail::column_range_polynomial_dfs<FieldType>(
                                private_assignment.move_witnesses(), basic_domain));
                        return preprocessed_data_type({basic_domain, std::move(private_polynomial_table)});
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_PREPROCESSOR_HPP
