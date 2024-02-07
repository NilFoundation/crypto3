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

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template <typename TTypeBase, typename FieldElementType>
                using field_element_vector_type = nil::marshalling::types::array_list<
                    TTypeBase,
                    field_element<TTypeBase, FieldElementType>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                ///////////////////////////////////////////////
                // math::polynomial marshalling
                ///////////////////////////////////////////////
                template<typename TTypeBase, typename PolynomialType>
                using fri_math_polynomial =  field_element_vector_type<TTypeBase, typename PolynomialType::value_type>;

                template<typename Endianness, typename PolynomialType, typename Range>
                fri_math_polynomial<nil::marshalling::field_type<Endianness>, PolynomialType>
                fill_fri_math_polynomial(const Range &f){
                    std::vector<typename PolynomialType::value_type> val;
                    for( auto it=f.begin(); it != f.end(); it++){ val.push_back(*it); }

                    return nil::crypto3::marshalling::types::fill_field_element_vector<
                        typename PolynomialType::value_type,
                        Endianness
                    >(val);
                }

                template<typename Endianness, typename PolynomialType>
                PolynomialType
                make_fri_math_polynomial( const fri_math_polynomial<nil::marshalling::field_type<Endianness>, PolynomialType> &filled_polynomial){
                    auto val = nil::crypto3::marshalling::types::make_field_element_vector<
                        typename PolynomialType::value_type,
                        Endianness
                    >(filled_polynomial);

                    return PolynomialType(val);
                }



                ///////////////////////////////////////////////////
                // fri::merkle_proofs marshalling
                ///////////////////////////////////////////////////
                template<typename TTypeBase, typename FRI>
                using merkle_proof_vector_type = nil::marshalling::types::array_list<
                    TTypeBase,
                    types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
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
                // fri::proof_type marshalling
                ///////////////////////////////////////////////////
                template <typename TTypeBase, typename FRI, bool b = FRI::use_grinding> struct fri_proof;
                template <typename TTypeBase, typename FRI> struct fri_proof<TTypeBase, FRI, true>  {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // step_list.size() merkle roots
                            // Fixed size. It's Ok
                            nil::marshalling::types::array_list<
                                TTypeBase, typename types::merkle_node_value<TTypeBase, typename FRI::merkle_proof_type>::type,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,

                            // step_list.
                            // We'll check is it good for current EVM instance
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::integral<TTypeBase, uint8_t>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,

                            // Polynomials' values for initial proofs
                            // Fixed size
                            // lambda * polynomials_num * m
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                field_element<TTypeBase, typename FRI::field_type::value_type>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,

                            // Polynomials' values for round proofs
                            // Fixed size
                            // lambda * \sum_rounds{m^{r_i}}
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                field_element<TTypeBase, typename FRI::field_type::value_type>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,

                            // Merkle proofs for initial proofs
                            // Fixed size lambda * batches_num
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,

                            // Merkle proofs for round proofs
                            // Fixed size lambda * |step_list|
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,

                            // std::select_container<math::polynomial> final_polynomials
                            // May be different size, because real degree may be less than before. So put int in the end
                            fri_math_polynomial<TTypeBase, typename FRI::polynomial_type>,


                            // proof of work. TODO: how to do it optional?
                            nil::marshalling::types::integral<TTypeBase, typename FRI::grinding_type::output_type>  //proof of work*/
                        >
                    >;
                };
                template <typename TTypeBase, typename FRI> struct fri_proof<TTypeBase, FRI, false> {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // step_list.size() merkle roots
                            // Fixed size. It's Ok
                            nil::marshalling::types::array_list<
                                TTypeBase, typename types::merkle_node_value<TTypeBase, typename FRI::merkle_proof_type>::type,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,

                            // step_list.
                            // We'll check is it good for current EVM instance
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::integral<TTypeBase, uint8_t>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,

                            // Polynomials' values for initial proofs
                            // Fixed size
                            // lambda * polynomials_num * m
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                field_element<TTypeBase, typename FRI::field_type::value_type>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,

                            // Polynomials' values for round proofs
                            // Fixed size
                            // lambda * \sum_rounds{m^{r_i}}
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                field_element<TTypeBase, typename FRI::field_type::value_type>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,

                            // Merkle proofs for initial proofs
                            // Fixed size lambda * batches_num
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,

                            // Merkle proofs for round proofs
                            // Fixed size lambda * |step_list|
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,

                            // std::select_container<math::polynomial> final_polynomials
                            // May be different size, because real degree may be less than before. So put int in the end
                            fri_math_polynomial<TTypeBase, typename FRI::polynomial_type>
                        >
                    >;
                };

                using batch_info_type = std::map<std::size_t, std::size_t>;// batch_id->batch_size

                template <typename Endianness, typename FRI>
                typename fri_proof<nil::marshalling::field_type<Endianness>, FRI>::type
                fill_fri_proof(const typename FRI::proof_type &proof, const batch_info_type &batch_info, const typename FRI::params_type& params) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    // merkle roots
                    nil::marshalling::types::array_list<
                        TTypeBase, typename types::merkle_node_value<TTypeBase, typename FRI::merkle_proof_type>::type,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_fri_roots;
                    for( size_t i = 0; i < proof.fri_roots.size(); i++){
                        filled_fri_roots.value().push_back(fill_merkle_node_value<typename FRI::commitment_type, Endianness>(proof.fri_roots[i]));
                    }

                    // initial_polynomials values
                    std::vector<typename FRI::field_type::value_type> initial_val;
                    for( std::size_t i = 0; i < FRI::lambda; i++ ){
                        auto &query_proof = proof.query_proofs[i];
                        for( const auto &it: query_proof.initial_proof){
                            auto &initial_proof = it.second;
                            BOOST_ASSERT(initial_proof.values.size() == batch_info.at(it.first));
                            for( std::size_t j = 0; j < initial_proof.values.size(); j++ ){
                                for(std::size_t k = 0; k < initial_proof.values[j].size(); k++ ){
                                    for( std::size_t l = 0; l < FRI::m; l++ ){
                                        initial_val.push_back(initial_proof.values[j][k][l]);
                                    }
                                }
                                BOOST_ASSERT(std::size_t(1 << (params.step_list[0] - 1)) == initial_proof.values[j].size());
                            }
                        }
                    }
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        field_element<TTypeBase, typename FRI::field_type::value_type>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_initial_val = fill_field_element_vector<typename FRI::field_type::value_type, Endianness>(initial_val);

                    // fill round values
                    std::vector<typename FRI::field_type::value_type> round_val;
                    for( std::size_t i = 0; i < FRI::lambda; i++ ){
                        auto &query_proof = proof.query_proofs[i];
                        for( std::size_t j = 0; j < query_proof.round_proofs.size(); j++ ){
                            auto &round_proof = query_proof.round_proofs[j];
                            for( std::size_t k = 0; k < round_proof.y.size(); k++){
                                round_val.push_back(round_proof.y[k][0]);
                                round_val.push_back(round_proof.y[k][1]);
                            }
                        }
                    }
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        field_element<TTypeBase, typename FRI::field_type::value_type>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_round_val = fill_field_element_vector<typename FRI::field_type::value_type, Endianness>(round_val);

                    // step_list
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_step_list;
                    for (const auto& step : params.step_list) {
                        filled_step_list.value().push_back(nil::marshalling::types::integral<TTypeBase, std::uint8_t>(step));
                    }

                    // initial merkle proofs
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_initial_merkle_proofs;
                    for( std::size_t i = 0; i < FRI::lambda; i++){
                        const auto &query_proof = proof.query_proofs[i];
                        for( const auto &it:query_proof.initial_proof){
                            const auto &initial_proof = it.second;
                            filled_initial_merkle_proofs.value().push_back(
                                fill_merkle_proof<typename FRI::merkle_proof_type, Endianness>(initial_proof.p)
                            );
                        }
                    }

                    // round merkle proofs
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_round_merkle_proofs;
                    for( std::size_t i = 0; i < FRI::lambda; i++){
                        const auto &query_proof = proof.query_proofs[i];
                        for( const auto &round_proof:query_proof.round_proofs){
                            filled_round_merkle_proofs.value().push_back(
                                fill_merkle_proof<typename FRI::merkle_proof_type, Endianness>(round_proof.p)
                            );
                        }
                    }

                    auto filled_final_polynomial = fill_fri_math_polynomial<Endianness, typename FRI::polynomial_type>(
                        proof.final_polynomial
                    );

                    // proof_of_work
                    if constexpr(FRI::use_grinding){
                        return typename fri_proof<nil::marshalling::field_type<Endianness>, FRI>::type(
                            std::tuple(
                                filled_fri_roots, filled_step_list, filled_initial_val, filled_round_val,
                                filled_initial_merkle_proofs, filled_round_merkle_proofs, filled_final_polynomial,
                                nil::marshalling::types::integral<TTypeBase, typename FRI::grinding_type::output_type>(proof.proof_of_work)
                            )
                        );
                    } else {
                        return typename fri_proof<nil::marshalling::field_type<Endianness>, FRI>::type(
                            std::tuple(
                                filled_fri_roots, filled_step_list, filled_initial_val, filled_round_val,
                                filled_initial_merkle_proofs, filled_round_merkle_proofs, filled_final_polynomial
                            )
                        );
                    }
                }

                template <typename Endianness, typename FRI>
                typename FRI::proof_type
                make_fri_proof(
                    const typename fri_proof<nil::marshalling::field_type<Endianness>, FRI>::type &filled_proof, const batch_info_type &batch_info
                ){
                    typename FRI::proof_type proof;
                    // merkle roots
                    for( std::size_t i = 0; i < std::get<0>(filled_proof.value()).value().size(); i++){
                        proof.fri_roots.push_back(
                            make_merkle_node_value<typename FRI::commitment_type, Endianness>(std::get<0>(filled_proof.value()).value()[i])
                        );
                    }
                    // step_list
                    std::vector<std::uint8_t> step_list;
                    for( std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); i++){
                        auto c = std::get<1>(filled_proof.value()).value()[i].value();
                        step_list.push_back(c);
                    }

                    // initial_polynomials values
                    std::size_t coset_size = 1 << (step_list[0] - 1);
                    std::size_t cur = 0;
                    for( std::size_t i = 0; i < FRI::lambda; i++ ){
                        for( const auto &it:batch_info){
                            proof.query_proofs[i].initial_proof[it.first] = typename FRI::initial_proof_type();
                            proof.query_proofs[i].initial_proof[it.first].values.resize(it.second);
                            for( std::size_t j = 0; j < it.second; j++ ){
                                proof.query_proofs[i].initial_proof[it.first].values[j].resize(coset_size);
                                for( std::size_t k = 0; k < coset_size; k++){
                                    for( std::size_t l = 0; l < FRI::m; l++, cur++ ){
                                        BOOST_ASSERT(cur < std::get<2>(filled_proof.value()).value().size());
                                        proof.query_proofs[i].initial_proof[it.first].values[j][k][l] = std::get<2>(filled_proof.value()).value()[cur].value();
                                    }
                                }
                            }
                        }
                    }

                    // round polynomials values
                    cur = 0;
                    for(std::size_t i = 0; i < FRI::lambda; i++ ){
                        proof.query_proofs[i].round_proofs.resize(step_list.size());
                        for(std::size_t r = 0; r < step_list.size(); r++ ){
                            coset_size = r == step_list.size() - 1? 1: (1 << (step_list[r+1]-1));
                            proof.query_proofs[i].round_proofs[r].y.resize(coset_size);
                            for( std::size_t j = 0; j < coset_size; j++){
                                for( std::size_t k = 0; k < FRI::m; k++, cur++){
                                    BOOST_ASSERT(cur < std::get<3>(filled_proof.value()).value().size());
                                    proof.query_proofs[i].round_proofs[r].y[j][k] = std::get<3>(filled_proof.value()).value()[cur].value();
                                }
                            }
                        }
                    }
                    // initial merkle proofs
                    cur = 0;
                    for( std::size_t i = 0; i < FRI::lambda; i++ ){
                        for( const auto &it:batch_info){
                            proof.query_proofs[i].initial_proof[it.first].p = make_merkle_proof<typename FRI::merkle_proof_type, Endianness>(
                                std::get<4>(filled_proof.value()).value()[cur++]
                            );
                        }
                    }

                    // round merkle proofs
                    cur = 0;
                    for( std::size_t i = 0; i < FRI::lambda; i++ ){
                        for( std::size_t r = 0; r < step_list.size(); r++, cur++ ){
                            proof.query_proofs[i].round_proofs[r].p = make_merkle_proof<typename FRI::merkle_proof_type, Endianness>(
                                std::get<5>(filled_proof.value()).value()[cur]
                            );
                        }
                    }

                    // final_polynomial
                    proof.final_polynomial = make_fri_math_polynomial<Endianness, typename FRI::polynomial_type>(
                        std::get<6>(filled_proof.value())
                    );
                    // proof_of_work
                    if constexpr(FRI::use_grinding){
                        proof.proof_of_work = std::get<7>(filled_proof.value()).value();
                    }
                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP
