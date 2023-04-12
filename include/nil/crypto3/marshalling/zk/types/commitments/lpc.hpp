//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
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
                template < typename TTypeBase, typename LPC >                
                    using lpc_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // lpc::proof::z is std::array<std::vector<std::vector>>, batches_num>
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::crypto3::marshalling::types::field_element_vector_type<TTypeBase, typename LPC::field_type::value_type>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                            >,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                        >,

                        // One fri proof
                        fri_proof<TTypeBase, typename LPC::basic_fri>
                    >
                >;

                template<typename Endianness, typename LPC>
                lpc_proof<nil::marshalling::field_type<Endianness>, LPC> 
                fill_lpc_proof( const typename LPC::proof_type &proof ){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::crypto3::marshalling::types::field_element_vector_type<TTypeBase, typename LPC::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                        >,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>> 
                    > filled_z;

                    for( size_t j = 0; j < LPC::basic_fri::batches_num; j++){
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::crypto3::marshalling::types::field_element_vector_type<TTypeBase, typename LPC::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                        > filled;

                        for( size_t i = 0; i < proof.z[j].size(); i++){
                            filled.value().push_back(
                                fill_field_element_vector<typename LPC::field_type::value_type, Endianness>(proof.z[j][i])
                            );
                        }
                        filled_z.value().push_back(filled);
                    }

                    auto filled_fri_proof = fill_fri_proof<Endianness, typename LPC::basic_fri>(proof.fri_proof);
                    return lpc_proof<TTypeBase, LPC>(
                        std::tuple( filled_z, filled_fri_proof )
                    );
                }

                template<typename Endianness, typename LPC>
                typename LPC::proof_type make_lpc_proof(const lpc_proof<nil::marshalling::field_type<Endianness>, LPC> &filled_proof){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    typename LPC::proof_type proof;

                    auto filled_z = std::get<0>(filled_proof.value());
                    for(size_t k = 0; k < LPC::basic_fri::batches_num; k++ ){
                        auto filled = filled_z.value()[k];
                        for( size_t i = 0; i < filled.value().size(); i ++){
                            proof.z[k].push_back(make_field_element_vector<typename LPC::field_type::value_type, Endianness>(filled.value()[i]));
                        }
                    }

                    proof.fri_proof = make_fri_proof<Endianness, typename LPC::basic_fri>(std::get<1>(filled_proof.value()));
                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
