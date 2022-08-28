//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Ilias Khairullin <ilias@nil.foundation>
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
                /*
                 * math::polynomial marshalling
                 */
                template<typename TTypeBase, typename FRIScheme>
                using fri_math_polynomial =  nil::marshalling::types::array_list<
                    TTypeBase,
                    field_element<TTypeBase, typename FRIScheme::field_type::value_type>,
                    nil::marshalling::option::sequence_size_field_prefix<
                        nil::marshalling::types::integral<TTypeBase, std::size_t>
                    >
                >;

                template<typename Endianness, typename FRIScheme>
                fri_math_polynomial<nil::marshalling::field_type<Endianness>, FRIScheme>
                fill_fri_math_polynomial(const math::polynomial<typename FRIScheme::field_type::value_type> &f){
                    std::vector<typename FRIScheme::field_type::value_type> val;
                    for( auto it=f.begin(); it != f.end(); it++){ val.push_back(*it); }

                    return nil::crypto3::marshalling::types::fill_field_element_vector<
                        typename FRIScheme::field_type::value_type,    
                        Endianness
                    >(val);
                }

                template<typename Endianness, typename FRIScheme>
                math::polynomial<typename FRIScheme::field_type::value_type>
                make_fri_math_polynomial( const fri_math_polynomial<nil::marshalling::field_type<Endianness>, FRIScheme> &filled_polynomial){
                    auto val = nil::crypto3::marshalling::types::make_field_element_vector<
                        typename FRIScheme::field_type::value_type,    
                        Endianness
                    >(filled_polynomial);

                    return math::polynomial<typename FRIScheme::field_type::value_type>(val);
                }

                /*
                 * fri::round_proof_type marshalling
                 */
                template<typename TTypeBase, typename FRIScheme>
                using fri_round_proof = nil::marshalling::types::bundle<
                    TTypeBase,  
                    std::tuple<
                        typename types::merkle_proof<TTypeBase,      typename FRIScheme::merkle_proof_type>,  // p,
                        typename types::merkle_node_value<TTypeBase, typename FRIScheme::merkle_proof_type>::type,  // T_root,
                        typename types::merkle_proof<TTypeBase,      typename FRIScheme::merkle_proof_type>   // colinear_path*/
                    >      
                >;                        

                template<typename Endianness, typename FRIScheme>
                fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme>
                fill_fri_round_proof(const typename FRIScheme::round_proof_type &proof) {
                    auto p = fill_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(proof.p);
                    auto T_root = fill_merkle_node_value<typename FRIScheme::commitment_type, Endianness>(proof.T_root);
                    auto colinear_path = fill_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(proof.colinear_path);
                    return fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme> (std::make_tuple(p, T_root, colinear_path));
                }

                template<typename Endianness, typename FRIScheme>
                typename FRIScheme::round_proof_type
                make_fri_round_proof(const fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme> &blob) {
                    typename FRIScheme::round_proof_type rp;
                    rp.p = make_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(std::get<0>(blob.value()));
                    rp.T_root = make_merkle_node_value<typename FRIScheme::merkle_proof_type, Endianness>(std::get<1>(blob.value()));
                    rp.colinear_path = make_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(std::get<2>(blob.value()));
                    return rp;
                }

                /*
                 * fri::values_type marshalling
                 *           y-s and colinear_values
                 * values[round_id][polynomial_id][x_index] = [][]
                 */
                template<typename TTypeBase, typename FRIScheme>
                using fri_polynomial_values = nil::marshalling::types::array_list<
                    TTypeBase,
                    field_element<TTypeBase, typename FRIScheme::field_type::value_type>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                template<typename Endianness, typename FRIScheme>
                fri_polynomial_values<nil::marshalling::field_type<Endianness>, FRIScheme>
                fill_fri_polynomial_values(const typename FRIScheme::polynomial_values_type &values) {
                    fri_polynomial_values<nil::marshalling::field_type<Endianness>, FRIScheme> blob;
                    for( size_t i = 0; i < values.size(); i++ ){
                        for( size_t j = 0; j < FRIScheme::m; j++){
                            blob.value().push_back( 
                                field_element<nil::marshalling::field_type<Endianness>, typename FRIScheme::field_type::value_type>(values[i][j])
                            );
                        }
                    }
                    return blob;
                }

                template<typename Endianness, typename FRIScheme>
                typename FRIScheme::polynomial_values_type
                make_fri_polynomial_values(const fri_polynomial_values<nil::marshalling::field_type<Endianness>, FRIScheme> &blob) {
                    typename FRIScheme::polynomial_values_type val;
                    val.resize(blob.value().size()/FRIScheme::m);

                    for( size_t i = 0; i < blob.value().size()/FRIScheme::m; i++ ){
                        typename FRIScheme::polynomial_value_type dot;
                        for( size_t j = 0; j < FRIScheme::m; j++){
                            dot[j] = blob.value()[i*FRIScheme::m + j].value();
                        }
                        val[i] = dot;
                    }
                    return val;
                }

                /*
                 * fri::polynomials_values_type marshalling
                 *           y-s and colinear_values
                 */
                template<typename TTypeBase, typename FRIScheme>
                using fri_polynomials_values = nil::marshalling::types::array_list<
                    TTypeBase,
                    fri_polynomial_values<TTypeBase, FRIScheme>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                template<typename Endianness, typename FRIScheme>
                fri_polynomials_values<nil::marshalling::field_type<Endianness>, FRIScheme>
                fill_fri_polynomials_values(const typename FRIScheme::polynomials_values_type &values) {
                    fri_polynomials_values<nil::marshalling::field_type<Endianness>, FRIScheme> blob;
                    for( size_t i = 0; i < values.size(); i++ ){
                        blob.value().push_back( 
                            fill_fri_polynomial_values<Endianness, FRIScheme>(values[i])
                        );
                    }
                    return blob;
                }

                template<typename Endianness, typename FRIScheme>
                typename FRIScheme::polynomials_values_type
                make_fri_polynomials_values(const fri_polynomials_values<nil::marshalling::field_type<Endianness>, FRIScheme> &blob) {
                    typename FRIScheme::polynomials_values_type val;

                    for( size_t i = 0; i < blob.value().size(); i++ ){
                        if constexpr ( FRIScheme::is_const_size ){
                            val[i] = make_fri_polynomial_values<Endianness, FRIScheme>(blob.value()[i]);
                        } else {
                            val.push_back(make_fri_polynomial_values<Endianness, FRIScheme>(blob.value()[i]));
                        }
                    }

                    return val;
                }


                /*
                 * fri::rounds_polynomials_values_type marshalling
                 *           y-s and colinear_values
                 */
                template<typename TTypeBase, typename FRIScheme>
                using fri_rounds_polynomials_values = nil::marshalling::types::array_list<
                    TTypeBase,
                    fri_polynomials_values<TTypeBase, FRIScheme>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                template<typename Endianness, typename FRIScheme>
                fri_rounds_polynomials_values<nil::marshalling::field_type<Endianness>, FRIScheme>
                fill_fri_rounds_polynomials_values(const typename FRIScheme::rounds_polynomials_values_type &values) {
                    fri_rounds_polynomials_values<nil::marshalling::field_type<Endianness>, FRIScheme> blob;
                    for( size_t i = 0; i < values.size(); i++ ){
                        blob.value().push_back( 
                            fill_fri_polynomials_values<Endianness, FRIScheme>(values[i])
                        );
                    }
                    return blob;
                }

                template<typename Endianness, typename FRIScheme>
                typename FRIScheme::rounds_polynomials_values_type
                make_fri_rounds_polynomials_values(const fri_rounds_polynomials_values<nil::marshalling::field_type<Endianness>, FRIScheme> &blob) {
                    typename FRIScheme::rounds_polynomials_values_type val;
//                    val.resize(blob.value().size());

                    for( size_t i = 0; i < blob.value().size(); i++ ){
                        val.push_back(make_fri_polynomials_values<Endianness, FRIScheme>(blob.value()[i]));
                    }

                    return val;
                }

                /**
                 * fri::proof_type marshalling
                 */
                template<typename TTypeBase, typename FRIScheme>
                using fri_proof = nil::marshalling::types::bundle<
                    TTypeBase,  
                    std::tuple<
                        // merkle_tree::root target_commitment
                        typename types::merkle_node_value<TTypeBase, typename FRIScheme::merkle_proof_type>::type,

                         // std::vector<round_proof_type> round_proofs;  // 0..r-2
                         // Don't want sequense_prefix option
                        nil::marshalling::types::array_list< 
                            TTypeBase, fri_round_proof<TTypeBase, FRIScheme>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,

                        // values
                        fri_rounds_polynomials_values<TTypeBase, FRIScheme>,

                         // std::select_container<math::polynomial> final_polynomials
                        nil::marshalling::types::array_list<
                            TTypeBase, 
                            fri_math_polynomial<TTypeBase, FRIScheme>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >
                    >      
                >;

                template<typename Endianness, typename FRIScheme>
                fri_proof<nil::marshalling::field_type<Endianness>, FRIScheme>
                fill_fri_proof(const typename FRIScheme::proof_type &proof) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    // target_commitment
                    auto filled_target_commitment = fill_merkle_node_value<typename FRIScheme::commitment_type, Endianness>(proof.target_commitment);

                    // values: y-s and colinear_values
                    auto filled_values = fill_fri_rounds_polynomials_values<Endianness, FRIScheme>(proof.values);

                    // round_proofs
                    nil::marshalling::types::array_list< 
                        TTypeBase, fri_round_proof<TTypeBase, FRIScheme>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_round_proofs;
                    for( size_t i = 0; i < proof.round_proofs.size(); i++){
                        filled_round_proofs.value().push_back(fill_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[i]));
                    }
    
                    // final_polynomials
                    nil::marshalling::types::array_list<
                        TTypeBase,  
                        fri_math_polynomial<TTypeBase, FRIScheme>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_final_polynomials;
                    for( size_t i = 0; i < proof.final_polynomials.size(); i++){
                        filled_final_polynomials.value().push_back(fill_fri_math_polynomial<Endianness, FRIScheme>(proof.final_polynomials[i]));
                    }

                    return fri_proof <TTypeBase, FRIScheme>(std::tuple(
                        filled_target_commitment,
                        filled_round_proofs,
                        filled_values,
                        filled_final_polynomials
                    ));
                }

                template<typename Endianness, typename FRIScheme>
                typename FRIScheme::proof_type
                make_fri_proof(const fri_proof<nil::marshalling::field_type<Endianness>, FRIScheme> &filled_proof) {
                    typename FRIScheme::proof_type proof;

                    auto tc = std::get<0>(filled_proof.value());
                    proof.target_commitment = make_merkle_node_value<typename FRIScheme::commitment_type, Endianness>(tc);

                    auto rp = std::get<1>(filled_proof.value());
                    proof.round_proofs.resize(rp.value().size());
                    for( size_t i = 0; i < rp.value().size(); i++){
                        proof.round_proofs[i] = make_fri_round_proof<Endianness, FRIScheme>(rp.value()[i]);
                    }

                    auto vals = std::get<2>(filled_proof.value());
                    proof.values = make_fri_rounds_polynomials_values<Endianness, FRIScheme>(vals);

                    auto fp = std::get<3>(filled_proof.value());
                    //proof.final_polynomials.resize(fp.value().size());
                    for( size_t i = 0; i < fp.value().size(); i++){
                        if constexpr( FRIScheme::is_const_size){
                            proof.final_polynomials[i] = make_fri_math_polynomial<Endianness, FRIScheme>(fp.value()[i]);
                        } else {
                            proof.final_polynomials.push_back(make_fri_math_polynomial<Endianness, FRIScheme>(fp.value()[i]));
                        }
                    }

                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP
