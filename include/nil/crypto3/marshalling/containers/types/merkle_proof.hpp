//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_MERKLE_PROOF_HPP
#define CRYPTO3_MARSHALLING_MERKLE_PROOF_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/merkle/merkle.hpp>
#include <nil/crypto3/merkle/proof.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase,
                         typename MerkleProof,
                         typename = typename std::enable_if<
                             std::is_same<MerkleProof, 
                                nil::crypto3::merkletree::MerkleProof<
                                    typename MerkleProof::hash_type,
                                    MerkleProof::arity
                                >
                             >::value,
                             bool>::type,
                         typename... TOptions>
                using merkle_proof = 
                    nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // leaf_index
                            nil::marshalling::types::integral<
                                TTypeBase, 
                                std::size_t
                            >,
                            // element root
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::integral<
                                    TTypeBase, 
                                    std::uint8_t
                                >,
                                nil::marshalling::option::fixed_size_storage<MerkleProof::hash_type::digest_size>
                            >,
                            // std::vector<std::array<path_element_t, Arity - 1>> path
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                // layer path
                                nil::marshalling::types::array_list<
                                    TTypeBase,
                                    // path_element_t
                                    nil::marshalling::types::bundle<
                                        TTypeBase,
                                        std::tuple<
                                            // hash
                                            nil::marshalling::types::array_list<
                                                TTypeBase,
                                                nil::marshalling::types::integral<
                                                    TTypeBase, 
                                                    std::uint8_t
                                                >,
                                                nil::marshalling::option::fixed_size_storage<MerkleProof::hash_type::digest_size>
                                            >,
                                            // position
                                            nil::marshalling::types::integral<
                                                TTypeBase, 
                                                std::size_t
                                            >
                                        >
                                    >,
                                    nil::marshalling::option::fixed_size_storage<MerkleProof::arity - 1>
                                >,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<
                                        TTypeBase, 
                                        std::size_t
                                    >
                                > 
                            >
                        >
                    >;

            }    // namespace types
        }        // namespace marshalling
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_MERKLE_PROOF_HPP
