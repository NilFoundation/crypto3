//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP

#include <limits>
#include <map>
#include <ratio>
#include <type_traits>

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>
#include <nil/crypto3/marshalling/math/types/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                using batch_info_type = std::map<std::size_t, std::size_t>; // batch_id->batch_size

                ///////////////////////////////////////////////////
                // fri::merkle_proofs marshalling
                ///////////////////////////////////////////////////
                template<typename TTypeBase, typename FRI>
                using merkle_proof_vector_type = nil::marshalling::types::array_list<
                    TTypeBase,
                    types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>,
                    nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                >;

                template< typename Endianness, typename FRI >
                merkle_proof_vector_type<nil::marshalling::field_type<Endianness>, FRI>
                fill_merkle_proof_vector(const std::vector<typename FRI::merkle_proof_type> &merkle_proofs) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using filled_type = merkle_proof_vector_type<TTypeBase, FRI>;

                    filled_type filled;

                    for( size_t i = 0; i < merkle_proofs.size(); i++){
                        filled.value().push_back(
                            fill_merkle_proof<typename FRI::merkle_proof_type, Endianness>(merkle_proofs[i])
                        );
                    }
                    return filled;
                }

                template<typename Endianness, typename FRI>
                std::vector<typename FRI::merkle_proof_type>
                make_merkle_proof_vector(merkle_proof_vector_type<nil::marshalling::field_type<Endianness>, FRI> &filled) {
                    std::vector<typename FRI::merkle_proof_type> merkle_proofs;
                    for( std::size_t i = 0; i < filled.value().size(); i++ ){
                        merkle_proofs.push_back(
                            make_merkle_proof<typename FRI::merkle_proof_type, Endianness>(filled.value()[i])
                        );
                    }
                    return merkle_proofs;
                }

                ///////////////////////////////////////////////////
                // fri::initial_proof_type marshalling
                ///////////////////////////////////////////////////
                template<typename TTypeBase, typename FRI>
                using fri_initial_proof_type = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // polynomials_values_type values;
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename FRI::field_type::value_type>,
                            nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                        >,
                        // merkle_proof_type p;
                        typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>
                    >
                >;

                template<typename Endianness, typename FRI>
                fri_initial_proof_type<nil::marshalling::field_type<Endianness>, FRI>
                fill_fri_initial_proof(
                    const typename FRI::initial_proof_type &initial_proof
                ) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using filled_type = fri_initial_proof_type<TTypeBase, FRI>;

                    filled_type filled;

                    for (std::size_t i = 0; i < initial_proof.values.size(); i++) {
                        for (std::size_t j = 0; j < initial_proof.values[i].size(); j++) {
                            for (std::size_t k = 0; k < FRI::m; k++) {
                                std::get<0>(filled.value()).value().push_back(
                                    field_element<TTypeBase, typename FRI::field_type::value_type>(
                                        initial_proof.values[i][j][k])
                                );
                            }
                        }
                    }
                    // merkle_proof_type p;
                    std::get<1>(filled.value()) =
                        fill_merkle_proof<typename FRI::merkle_proof_type, Endianness>(initial_proof.p);

                    return filled;
                }

                template<typename Endianness, typename FRI>
                typename FRI::initial_proof_type
                make_fri_initial_proof(
                    const fri_initial_proof_type<nil::marshalling::field_type<Endianness>, FRI> &filled,
                    const std::size_t batch_size,
                    const std::size_t coset_size
                ) {
                    typename FRI::initial_proof_type initial_proof;
                    // polynomials_values_type values;
                    BOOST_ASSERT(std::get<0>(filled.value()).value().size() == batch_size * coset_size * FRI::m);
                    std::size_t cur = 0;
                    initial_proof.values.resize(batch_size);
                    for (std::size_t i = 0; i < batch_size; i++) {
                        initial_proof.values[i].resize(coset_size);
                        for (std::size_t j = 0; j < coset_size; j++) {
                            for (std::size_t k = 0; k < FRI::m; k++) {
                                initial_proof.values[i][j][k] =
                                    std::get<0>(filled.value()).value()[cur++].value();
                            }
                        }
                    }

                    // merkle_proof_type p;
                    initial_proof.p = make_merkle_proof<typename FRI::merkle_proof_type, Endianness>(
                        std::get<1>(filled.value()));

                    return initial_proof;
                }

                ///////////////////////////////////////////////////
                // fri::round_proof_type marshalling
                ///////////////////////////////////////////////////
                template<typename TTypeBase, typename FRI>
                using fri_round_proof_type = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // std::vector<std::array<typename FRI::field_type::value_type, FRI::m>> y;
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename FRI::field_type::value_type>,
                            nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                        >,
                        // merkle_proof_type p;
                        typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>
                    >
                >;

                template<typename Endianness, typename FRI>
                fri_round_proof_type<nil::marshalling::field_type<Endianness>, FRI>
                fill_fri_round_proof(
                    const typename FRI::round_proof_type &round_proof
                ) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using filled_type = fri_round_proof_type<TTypeBase, FRI>;

                    filled_type filled;

                    for (std::size_t i = 0; i < round_proof.y.size(); i++) {
                        for (std::size_t j = 0; j < FRI::m; j++) {
                            std::get<0>(filled.value()).value().push_back(
                                field_element<TTypeBase, typename FRI::field_type::value_type>(
                                    round_proof.y[i][j])
                            );
                        }
                    }
                    // merkle_proof_type p;
                    std::get<1>(filled.value()) =
                        fill_merkle_proof<typename FRI::merkle_proof_type, Endianness>(round_proof.p);

                    return filled;
                }

                template<typename Endianness, typename FRI>
                typename FRI::round_proof_type
                make_fri_round_proof(
                    const fri_round_proof_type<nil::marshalling::field_type<Endianness>, FRI> &filled,
                    const std::size_t coset_size
                ) {
                    typename FRI::round_proof_type round_proof;
                    // std::vector<std::array<typename FRI::field_type::value_type, FRI::m>> y;
                    BOOST_ASSERT(std::get<0>(filled.value()).value().size() == coset_size * FRI::m);
                    std::size_t cur = 0;
                    round_proof.y.resize(coset_size);
                    for (std::size_t i = 0; i < coset_size; i++) {
                        for (std::size_t j = 0; j < FRI::m; j++) {
                            round_proof.y[i][j] = std::get<0>(filled.value()).value()[cur++].value();
                        }
                    }

                    // merkle_proof_type p;
                    round_proof.p = make_merkle_proof<typename FRI::merkle_proof_type, Endianness>(
                        std::get<1>(filled.value()));

                    return round_proof;
                }

                ///////////////////////////////////////////////////
                // fri::query_proof_type marshalling
                ///////////////////////////////////////////////////
                template<typename TTypeBase, typename FRI>
                using fri_query_proof_type = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // std::map<std::size_t, initial_proof_type> initial_proof;
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fri_initial_proof_type<TTypeBase, FRI>,
                            nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                        >,
                        // std::vector<round_proof_type> round_proofs;
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fri_round_proof_type<TTypeBase, FRI>,
                            nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                        >
                    >
                >;

                template<typename Endianness, typename FRI>
                fri_query_proof_type<nil::marshalling::field_type<Endianness>, FRI>
                fill_fri_query_proof(
                    const typename FRI::query_proof_type &query_proof
                ) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using filled_type = fri_query_proof_type<TTypeBase, FRI>;

                    filled_type filled;

                    for (auto &[key, value] : query_proof.initial_proof) {
                        std::get<0>(filled.value()).value().push_back(
                            fill_fri_initial_proof<Endianness, FRI>(value)
                        );
                    }

                    for (std::size_t i = 0; i < query_proof.round_proofs.size(); i++) {
                        std::get<1>(filled.value()).value().push_back(
                            fill_fri_round_proof<Endianness, FRI>(query_proof.round_proofs[i])
                        );
                    }

                    return filled;
                }

                template<typename Endianness, typename FRI>
                typename FRI::query_proof_type
                make_fri_query_proof(
                    const fri_query_proof_type<nil::marshalling::field_type<Endianness>, FRI> &filled,
                    const batch_info_type &batch_info,
                    const std::vector<std::uint8_t> &step_list
                ) {
                    typename FRI::query_proof_type query_proof;
                    // std::map<std::size_t, initial_proof_type> initial_proof;
                    std::size_t cur = 0;
                    std::size_t coset_size = 1 << (step_list[0] - 1);
                    for (const auto &[batch_id, batch_size] : batch_info) {
                        query_proof.initial_proof[batch_id] =
                            make_fri_initial_proof<Endianness, FRI>(
                                std::get<0>(filled.value()).value()[cur++], batch_size, coset_size
                            );
                    }
                    // std::vector<round_proof_type> round_proofs;
                    cur = 0;
                    for (std::size_t r = 0; r < step_list.size(); r++) {
                        coset_size = r == step_list.size() - 1 ? 1 : (1 << (step_list[r+1]-1));
                        query_proof.round_proofs.push_back(
                            make_fri_round_proof<Endianness, FRI>(
                                std::get<1>(filled.value()).value()[cur++], coset_size
                            )
                        );
                    }

                    return query_proof;
                }

                ///////////////////////////////////////////////////
                // fri::partial_proof_type marshalling
                ///////////////////////////////////////////////////
                template<typename TTypeBase, typename FRI>
                using fri_partial_proof_type = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // std::vector<commitment_type> fri_roots;
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            typename types::merkle_node_value<TTypeBase, typename FRI::commitment_type>::type,
                            nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                        >,
                        // math::polynomial<typename field_type::value_type> final_polynomial;
                        typename polynomial<TTypeBase, typename FRI::polynomial_type>::type,
                        // typename GrindingType::output_type proof_of_work;
                        nil::marshalling::types::integral<TTypeBase, typename FRI::grinding_type::output_type>
                    >
                >;

                template<typename Endianness, typename FRI>
                fri_partial_proof_type<nil::marshalling::field_type<Endianness>, FRI>
                fill_partial_proof(
                    const typename FRI::partial_proof_type &partial_proof
                ) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using filled_type = fri_partial_proof_type<TTypeBase, FRI>;

                    filled_type filled;

                    for (size_t i = 0; i < partial_proof.fri_roots.size(); i++) {
                        std::get<0>(filled.value()).value().push_back(
                            fill_merkle_node_value<typename FRI::commitment_type, Endianness>(partial_proof.fri_roots[i])
                        );
                    }

                    std::get<1>(filled.value()) = fill_polynomial<Endianness, typename FRI::polynomial_type>(
                        partial_proof.final_polynomial
                    );

                    std::get<2>(filled.value()) =
                        nil::marshalling::types::integral<TTypeBase, typename FRI::grinding_type::output_type>(
                            partial_proof.proof_of_work
                        );

                    return filled;
                }

                template<typename Endianness, typename FRI>
                typename FRI::partial_proof_type
                make_fri_partial_proof(
                    const fri_partial_proof_type<nil::marshalling::field_type<Endianness>, FRI> &filled
                ) {
                    typename FRI::partial_proof_type partial_proof;
                    // std::vector<commitment_type> fri_roots;
                    for (std::size_t i = 0; i < std::get<0>(filled.value()).value().size(); i++) {
                        partial_proof.fri_roots.push_back(
                            make_merkle_node_value<typename FRI::commitment_type, Endianness>(
                                std::get<0>(filled.value()).value()[i]
                            )
                        );
                    }

                    // math::polynomial<typename field_type::value_type> final_polynomial;
                    partial_proof.final_polynomial = make_polynomial<Endianness, typename FRI::polynomial_type>(
                        std::get<1>(filled.value())
                    );

                    // typename GrindingType::output_type proof_of_work;
                    partial_proof.proof_of_work = std::get<2>(filled.value()).value();

                    return partial_proof;
                }

                ///////////////////////////////////////////////////
                // fri::proof_type marshalling
                ///////////////////////////////////////////////////
                template<typename TTypeBase, typename FRI>
                struct fri_proof {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // partial_proof
                            fri_partial_proof_type<TTypeBase, FRI>,
                            // step_list.
                            // We'll check is it good for current EVM instance
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::integral<TTypeBase, uint8_t>,
                                nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                            >,
                            // (lambda) query proofs
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                fri_query_proof_type<TTypeBase, FRI>,
                                nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                            >
                        >
                    >;
                };

                template <typename Endianness, typename FRI>
                typename fri_proof<nil::marshalling::field_type<Endianness>, FRI>::type
                fill_fri_proof(
                    const typename FRI::proof_type &proof,
                    const batch_info_type &batch_info,
                    const typename FRI::params_type& params
                ) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    // partial_proof
                    auto filled_partial_proof = fill_partial_proof<Endianness, FRI>(
                        proof
                    );

                    // step_list
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                        nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                    > filled_step_list;
                    for (const auto& step : params.step_list) {
                        filled_step_list.value().push_back(
                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>(step));
                    }

                    // lambda query proofs
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        fri_query_proof_type<TTypeBase, FRI>,
                        nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                    > filled_query_proofs;
                    for (std::size_t i = 0; i < proof.query_proofs.size(); i++) {
                        filled_query_proofs.value().push_back(
                            fill_fri_query_proof<Endianness, FRI>(proof.query_proofs[i])
                        );
                    }

                    return typename fri_proof<nil::marshalling::field_type<Endianness>, FRI>::type(
                        std::tuple(
                            filled_partial_proof, filled_step_list, filled_query_proofs
                        )
                    );
                }

                template <typename Endianness, typename FRI>
                typename FRI::proof_type
                make_fri_proof(
                    const typename fri_proof<nil::marshalling::field_type<Endianness>, FRI>::type &filled_proof,
                    const batch_info_type &batch_info
                ){
                    typename FRI::proof_type proof;
                    // partial_proof
                    proof = make_fri_partial_proof<Endianness, FRI>(
                        std::get<0>(filled_proof.value())
                    );
                    // step_list
                    std::vector<std::uint8_t> step_list;
                    for(std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); i++){
                        auto c = std::get<1>(filled_proof.value()).value()[i].value();
                        step_list.push_back(c);
                    }
                    const std::size_t lambda = std::get<2>(filled_proof.value()).value().size();
                    proof.query_proofs.resize(lambda);
                    for (std::size_t i = 0; i < lambda; i++) {
                        proof.query_proofs[i] = make_fri_query_proof<Endianness, FRI>(
                            std::get<2>(filled_proof.value()).value()[i], batch_info, step_list
                        );
                    }

                    return proof;
                }

                ///////////////////////////////////////////////////
                // fri::aggregated_proof_type marshalling
                ///////////////////////////////////////////////////
                template<typename TTypeBase, typename FRI>
                using fri_aggregated_proof_type = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // std::vector<partial_proof_type> partial_proofs;
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fri_partial_proof_type<TTypeBase, FRI>,
                            nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                        >,
                        // std::vector<std::uint8_t> step_list;
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                            nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                        >,
                        // std::vector<query_proof_type> query_proofs;
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fri_query_proof_type<TTypeBase, FRI>,
                            nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                        >
                    >
                >;

                template<typename Endianness, typename FRI>
                fri_aggregated_proof_type<nil::marshalling::field_type<Endianness>, FRI>
                fill_fri_aggregated_proof(
                    const typename FRI::aggregated_proof_type &aggregated_proof,
                    const typename FRI::params_type& params
                ) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    // partial_proofs
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        fri_partial_proof_type<TTypeBase, FRI>,
                        nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                    > filled_partial_proofs;
                    for (std::size_t i = 0; i < aggregated_proof.partial_proofs.size(); i++) {
                        filled_partial_proofs.value().push_back(
                            fill_partial_proof<Endianness, FRI>(aggregated_proof.partial_proofs[i])
                        );
                    }

                    // step_list
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                        nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                    > filled_step_list;
                    for (const auto& step : params.step_list) {
                        filled_step_list.value().push_back(
                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>(step));
                    }

                    // query_proofs
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        fri_query_proof_type<TTypeBase, FRI>,
                        nil::marshalling::option::size_t_sequence_size_field_prefix<TTypeBase>
                    > filled_query_proofs;
                    for (std::size_t i = 0; i < aggregated_proof.query_proofs.size(); i++) {
                        filled_query_proofs.value().push_back(
                            fill_fri_query_proof<Endianness, FRI>(aggregated_proof.query_proofs[i])
                        );
                    }

                    return fri_aggregated_proof_type<nil::marshalling::field_type<Endianness>, FRI>(
                        std::tuple(
                            filled_partial_proofs, filled_step_list, filled_query_proofs
                        )
                    );
                }

                template<typename Endianness, typename FRI>
                typename FRI::aggregated_proof_type
                make_fri_aggregated_proof(
                    const fri_aggregated_proof_type<nil::marshalling::field_type<Endianness>, FRI> &filled,
                    const batch_info_type &batch_info
                ) {
                    typename FRI::aggregated_proof_type aggregated_proof;
                    // partial_proofs
                    for (std::size_t i = 0; i < std::get<0>(filled.value()).value().size(); i++) {
                        aggregated_proof.partial_proofs.push_back(
                            make_fri_partial_proof<Endianness, FRI>(
                                std::get<0>(filled.value()).value()[i]
                            )
                        );
                    }

                    // step_list
                    std::vector<std::uint8_t> step_list;
                    for(std::size_t i = 0; i < std::get<1>(filled.value()).value().size(); i++){
                        auto c = std::get<1>(filled.value()).value()[i].value();
                        step_list.push_back(c);
                    }

                    // query_proofs
                    const std::size_t lambda = std::get<2>(filled.value()).value().size();
                    aggregated_proof.query_proofs.resize(lambda);
                    for (std::size_t i = 0; i < lambda; i++) {
                        aggregated_proof.query_proofs[i] = make_fri_query_proof<Endianness, FRI>(
                            std::get<2>(filled.value()).value()[i], batch_info, step_list
                        );
                    }

                    return aggregated_proof;
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP
