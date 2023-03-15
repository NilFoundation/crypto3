//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP

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
#include <nil/crypto3/marshalling/zk/types/commitments/fri.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template < typename TTypeBase, typename LPCScheme >                
                    using lpc_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // lpc::proof::T_root
                        typename merkle_node_value<TTypeBase, typename LPCScheme::commitment_type>::type,

                        // lpc::proof::z it is std::array<std::array<std::vector<field_element>>,4> or std::array<std::vector<std::vector<field_element>>,4>
                        // Vectors in array are not fixed size. So we need sequence_size_field_prefix option
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::crypto3::marshalling::types::field_element_vector_type<TTypeBase, typename LPCScheme::field_type::value_type>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                            >,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                        >,

                        // lpc::proof::fri_proofs array_elements are not fixed size. So we need sequence_size_field_prefix option
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fri_proof<TTypeBase, typename LPCScheme::basic_fri>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                        >
                    >
                >;

                template<typename Endianness, typename LPCScheme>
                lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme> 
                fill_lpc_proof( const typename LPCScheme::proof_type &proof ){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    auto filled_T_root = fill_merkle_node_value<typename LPCScheme::commitment_type, Endianness>(proof.T_root);
                   
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::crypto3::marshalling::types::field_element_vector_type<TTypeBase, typename LPCScheme::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                        >,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>> 
                    > filled_z;
                    for( size_t j = 0; j < 4; j++){
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::crypto3::marshalling::types::field_element_vector_type<TTypeBase, typename LPCScheme::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                        > filled;

                        for( size_t i = 0; i < proof.z[j].size(); i++){
                            filled.value().push_back(
                                fill_field_element_vector<typename LPCScheme::field_type::value_type, Endianness>(proof.z[j][i])
                            );
                        }
                        filled_z.value().push_back(filled);
                    }

                    nil::marshalling::types::array_list<
                        TTypeBase,
                        fri_proof<TTypeBase, typename LPCScheme::basic_fri>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                    > filled_fri_proofs;
                    for( size_t i = 0; i < proof.fri_proof.size(); i++){
                        filled_fri_proofs.value().push_back(
                            fill_fri_proof<Endianness, typename LPCScheme::basic_fri>(proof.fri_proof[i])
                        );
                    }

                    return lpc_proof<TTypeBase, LPCScheme>(std::tuple(
                        filled_T_root,
                        filled_z,
                        filled_fri_proofs
                    ));
                }

                template<typename Endianness, typename LPCScheme>
                typename LPCScheme::proof_type 
                make_lpc_proof(const lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme> &filled_proof){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    typename LPCScheme::proof_type proof;
                    proof.T_root = make_merkle_node_value<typename LPCScheme::commitment_type, Endianness>(std::get<0>(filled_proof.value()));

                    auto filled_z = std::get<1>(filled_proof.value());
                    for(size_t k = 0; k < 4; k++ ){
                        auto filled = filled_z.value()[k];
                        if constexpr(LPCScheme::is_const_size){
                            for( size_t i = 0; i < filled.value().size(); i ++){
                                proof.z[k][i] = make_field_element_vector<typename LPCScheme::field_type::value_type, Endianness>(filled.value()[i]);
                            }
                        } else {
                          for( size_t i = 0; i < filled.value().size(); i ++){
                                proof.z[k].push_back(make_field_element_vector<typename LPCScheme::field_type::value_type, Endianness>(filled.value()[i]));
                            }
                        }
                    }

                    auto filled_fri_proofs = std::get<2>(filled_proof.value());
                    for( size_t i = 0; i < filled_fri_proofs.value().size(); i ++){
                        proof.fri_proof[i] = make_fri_proof<Endianness, typename LPCScheme::basic_fri>(filled_fri_proofs.value()[i]);
                    }

                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
