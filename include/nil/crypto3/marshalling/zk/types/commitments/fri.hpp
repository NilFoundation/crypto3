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

#include <ratio>
#include <limits>
#include <type_traits>

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>

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

                /*
                 * math::polynomial marshalling
                 */
                template<typename TTypeBase, typename ValueType>
                using fri_math_polynomial =  field_element_vector_type<TTypeBase, ValueType>;

                template<typename Endianness, typename ValueType, typename Range>
                fri_math_polynomial<nil::marshalling::field_type<Endianness>, ValueType>
                fill_fri_math_polynomial(const Range &f){
                    std::vector<ValueType> val;
                    for( auto it=f.begin(); it != f.end(); it++){ val.push_back(*it); }

                    return nil::crypto3::marshalling::types::fill_field_element_vector<
                        ValueType,
                        Endianness
                    >(val);
                }

                template<typename Endianness, typename ValueType>
                math::polynomial<ValueType>
                make_fri_math_polynomial( const fri_math_polynomial<nil::marshalling::field_type<Endianness>, ValueType> &filled_polynomial){
                    auto val = nil::crypto3::marshalling::types::make_field_element_vector<
                        ValueType,
                        Endianness
                    >(filled_polynomial);

                    return math::polynomial<ValueType>(val);
                }

                /*
                 * fri::values_type marshalling
                 * [polynomial_id][x_index] = [][]
                 */
                template<typename TTypeBase, typename FRI>
                using fri_polynomial_values = nil::marshalling::types::array_list<
                    TTypeBase,
                    field_element<TTypeBase, typename FRI::field_type::value_type>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                template< typename FRI, typename Endianness>
                fri_polynomial_values<nil::marshalling::field_type<Endianness>, FRI>
                fill_fri_polynomial_values(const typename FRI::polynomial_values_type &values) {
                    fri_polynomial_values<nil::marshalling::field_type<Endianness>, FRI> blob;
                    for( size_t i = 0; i < values.size(); i++ ){
                        for( size_t j = 0; j < FRI::m; j++){
                            blob.value().push_back(
                                field_element<nil::marshalling::field_type<Endianness>, typename FRI::field_type::value_type>(values[i][j])
                            );
                        }
                    }
                    return blob;
                }

                template<typename FRI, typename Endianness>
                typename FRI::polynomial_values_type
                make_fri_polynomial_values(const fri_polynomial_values<nil::marshalling::field_type<Endianness>, FRI> &blob) {
                    typename FRI::polynomial_values_type val;
                    val.resize(blob.value().size()/FRI::m);

                    for( size_t i = 0; i < blob.value().size()/FRI::m; i++ ){
                        typename FRI::polynomial_value_type dot;
                        for( size_t j = 0; j < FRI::m; j++){
                            dot[j] = blob.value()[i*FRI::m + j].value();
                        }
                        val[i] = dot;
                    }
                    return val;
                }

                /****************************************************************************************
                 * fri::round_proof_type marshalling
                 ****************************************************************************************/
                template<typename TTypeBase, typename FRI>
                using fri_round_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>,           // p,
                        fri_polynomial_values<TTypeBase, FRI>                                               //y
                    >
                >;

                template<typename Endianness, typename FRI>
                fri_round_proof<nil::marshalling::field_type<Endianness>, FRI>
                fill_fri_round_proof(const typename FRI::round_proof_type &proof) {
                    auto p = fill_merkle_proof<typename FRI::merkle_proof_type, Endianness>(proof.p);
                    auto y = fill_fri_polynomial_values<FRI, Endianness>(proof.y);
                    return fri_round_proof<nil::marshalling::field_type<Endianness>, FRI> (std::make_tuple(p, y));
                }

                template<typename Endianness, typename FRI>
                typename FRI::round_proof_type
                make_fri_round_proof(const fri_round_proof<nil::marshalling::field_type<Endianness>, FRI> &blob) {
                    typename FRI::round_proof_type rp;
                    rp.p = make_merkle_proof<typename FRI::merkle_proof_type, Endianness>(std::get<0>(blob.value()));
                    rp.y = make_fri_polynomial_values<FRI, Endianness>(std::get<1>(blob.value()));
                    return rp;
                }

                /*
                 * fri::initial_proof_type marshalling
                 */
                template<typename TTypeBase, typename FRI>
                using fri_initial_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>, //p
                        // Polynomials_values. In fact it's three-dimentional array.[polynomial_type][coset_size/m][m]
                        // We don't need to store sizes of internal arrays. So, we should 
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,  //number of polynomials;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,  //coset_size*m
                        nil::marshalling::types::array_list<
                            TTypeBase, typename types::field_element<TTypeBase, typename FRI::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >
                    >
                >;

                template<typename Endianness, typename FRI>
                fri_initial_proof<nil::marshalling::field_type<Endianness>, FRI>
                fill_fri_initial_proof(const typename FRI::initial_proof_type &initial_proof) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    auto p = fill_merkle_proof<typename FRI::merkle_proof_type, Endianness>(initial_proof.p);
                    auto polys_num = initial_proof.values.size();
                    auto coset_size = initial_proof.values[0].size() * FRI::m;

                    nil::marshalling::types::integral<TTypeBase, std::size_t> filled_polys_num(polys_num);
                    nil::marshalling::types::integral<TTypeBase, std::size_t> filled_coset_size(coset_size);

                    nil::marshalling::types::array_list<
                        TTypeBase, field_element<nil::marshalling::field_type<Endianness>, typename FRI::field_type::value_type>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > val;

                    for( size_t i = 0; i < polys_num; i++ ){
                        for( size_t j = 0; j < coset_size/FRI::m; j++){
                            val.value().push_back(
                                field_element<nil::marshalling::field_type<Endianness>, typename FRI::field_type::value_type>(
                                    initial_proof.values[i][j][0]
                                )
                            );
                            val.value().push_back(
                                field_element<nil::marshalling::field_type<Endianness>, typename FRI::field_type::value_type>(
                                    initial_proof.values[i][j][1]
                                )
                            );
                        }
                    }
                    return fri_initial_proof<TTypeBase, FRI> (
                       std::make_tuple(p, filled_polys_num, filled_coset_size, val)
                    );
                }

                template<typename Endianness, typename FRI>
                typename FRI::initial_proof_type
                make_fri_initial_proof(const fri_initial_proof<nil::marshalling::field_type<Endianness>, FRI> &blob) {
                    typename FRI::initial_proof_type ip;
                    ip.p = make_merkle_proof<typename FRI::merkle_proof_type, Endianness>(std::get<0>(blob.value()));
                    auto polynomial_number = std::get<1>(blob.value()).value();
                    auto coset_size = std::get<2>(blob.value()).value();

                    ip.values.resize(polynomial_number);
                    for( std::size_t i = 0; i < polynomial_number; i++){
                        ip.values[i].resize(coset_size/FRI::m);
                        for( size_t j = 0; j < coset_size/FRI::m; j++ ){
                            for( size_t k = 0; k < FRI::m; k++){
                                ip.values[i][j][k] = std::get<3>(blob.value()).value()[i*coset_size + j*FRI::m + k].value();
                            }
                        }
                    }
                    return ip;
                }

                /*
                 * fri::query_proof_type marshalling
                 */
                template<typename TTypeBase, typename FRI>
                using fri_query_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fri_initial_proof<TTypeBase, FRI>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,                                   // batches_num of initial_proofs
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fri_round_proof<TTypeBase, FRI>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >                                    // step_list.size() of round_proofs
                    >
                >;

                template<typename Endianness, typename FRI>
                fri_query_proof<nil::marshalling::field_type<Endianness>, FRI>
                fill_fri_query_proof(const typename FRI::query_proof_type &query_proof) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    nil::marshalling::types::array_list<
                        TTypeBase,
                        fri_initial_proof<TTypeBase, FRI>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > initial_proofs;
                    for( std::size_t k=0; k < query_proof.initial_proof.size(); k++ ){
                        initial_proofs.value().push_back(
                            fill_fri_initial_proof<Endianness, FRI>(query_proof.initial_proof[k])
                        );                        
                    }

                    nil::marshalling::types::array_list<
                        TTypeBase,
                        fri_round_proof<TTypeBase, FRI>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    >  round_proofs;
                    for( std::size_t i=0; i < query_proof.round_proofs.size(); i++ ){
                        round_proofs.value().push_back(
                            fill_fri_round_proof<Endianness, FRI>(query_proof.round_proofs[i])
                        );                        
                    }
                    return fri_query_proof<TTypeBase, FRI>(std::tuple(initial_proofs, round_proofs));
                }

                template<typename Endianness, typename FRI>
                typename FRI::query_proof_type
                make_fri_query_proof(const fri_query_proof<nil::marshalling::field_type<Endianness>, FRI> &blob) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    typename FRI::query_proof_type qp;

                    for( std::size_t k=0; k < FRI::batches_num; k++ ){
                        qp.initial_proof[k] = make_fri_initial_proof<Endianness, FRI>(std::get<0>(blob.value()).value()[k]);
                    }

                    qp.round_proofs.resize(std::get<1>(blob.value()).value().size());
                    for( std::size_t i = 0; i < qp.round_proofs.size(); i++ ){
                        qp.round_proofs[i] = make_fri_round_proof<Endianness, FRI>(std::get<1>(blob.value()).value()[i]);
                    }

                    return qp;
                }
                /*
                 * fri::proof_type marshalling
                 */
                template<typename TTypeBase, typename FRI>
                using fri_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // step_list.size() merkle roots
                        nil::marshalling::types::array_list<
                            TTypeBase, typename types::merkle_node_value<TTypeBase, typename FRI::merkle_proof_type>::type,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,

                        // std::select_container<math::polynomial> final_polynomials
                        fri_math_polynomial<TTypeBase, typename FRI::field_type::value_type>,

                         // lambda query proofs 
                        nil::marshalling::types::array_list<
                            TTypeBase, fri_query_proof<TTypeBase, FRI>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >
                    >
                >;

                template<typename Endianness, typename FRI>
                fri_proof<nil::marshalling::field_type<Endianness>, FRI>
                fill_fri_proof(const typename FRI::proof_type &proof) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    // fri_roots
                    nil::marshalling::types::array_list<
                        TTypeBase, typename types::merkle_node_value<TTypeBase, typename FRI::merkle_proof_type>::type,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_fri_roots;
                    for( size_t i = 0; i < proof.fri_roots.size(); i++){
                        filled_fri_roots.value().push_back(fill_merkle_node_value<typename FRI::commitment_type, Endianness>(proof.fri_roots[i]));
                    }


                    // final_polynomial
                    auto filled_final_polynomial = fill_fri_math_polynomial<Endianness, typename FRI::field_type::value_type>(
                        proof.final_polynomial
                    );

                    // query_proofs
                    nil::marshalling::types::array_list<
                        TTypeBase, fri_query_proof<TTypeBase, FRI>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_query_proofs;
                    for( size_t i = 0; i < proof.query_proofs.size(); i++){
                        filled_query_proofs.value().push_back(fill_fri_query_proof<Endianness, FRI>(proof.query_proofs[i]));
                    }

                    return fri_proof <nil::marshalling::field_type<Endianness>, FRI>(
                        std::tuple(filled_fri_roots, filled_final_polynomial, filled_query_proofs)
                    );
                }

                template<typename Endianness, typename FRI>
                typename FRI::proof_type
                make_fri_proof(const fri_proof<nil::marshalling::field_type<Endianness>, FRI> &filled_proof) {
                    typename FRI::proof_type proof;

                    proof.fri_roots.resize(std::get<0>(filled_proof.value()).value().size());
                    for( size_t i = 0; i < std::get<0>(filled_proof.value()).value().size(); i++){
                        proof.fri_roots[i] = make_merkle_node_value<typename FRI::commitment_type, Endianness>(
                            std::get<0>(filled_proof.value()).value()[i]
                        );
                    }

                    proof.final_polynomial = make_fri_math_polynomial<Endianness, typename FRI::field_type::value_type>(
                        std::get<1>(filled_proof.value())
                    );

                    for( size_t i = 0; i < FRI::lambda; i++){
                        proof.query_proofs[i] = make_fri_query_proof<Endianness, FRI>(std::get<2>(filled_proof.value()).value()[i]);
                    }

/*                  auto vals = std::get<1>(filled_proof.value());
                    proof.values = make_fri_rounds_polynomials_values<Endianness, FRI>(vals);

                    auto fp = std::get<2>(filled_proof.value());
                    //proof.final_polynomials.resize(fp.value().size());
                    for( size_t i = 0; i < fp.value().size(); i++){
                        if constexpr( FRI::is_const_size){
                            proof.final_polynomials[i] = make_fri_math_polynomial<Endianness, FRI>(fp.value()[i]);
                        } else {
                            proof.final_polynomials.push_back(make_fri_math_polynomial<Endianness, FRI>(fp.value()[i]));
                        }
                    }
*/
                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP
