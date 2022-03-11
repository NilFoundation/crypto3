//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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
                template<typename TTypeBase, typename LPCScheme,
                         typename = typename std::enable_if<
                             std::is_same<LPCScheme, nil::crypto3::zk::commitments::list_polynomial_commitment<
                                                         typename LPCScheme::field_type, typename LPCScheme::lpc_params,
                                                         LPCScheme::k>>::value,
                             bool>::type,
                         typename... TOptions>
                using lpc_proof = nil::marshalling::types::bundle<
                    TTypeBase, std::tuple<
                                   // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                                   // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                                   // typename merkle_tree_type::value_type T_root;
                                   nil::marshalling::types::array_list<
                                       TTypeBase, nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                       nil::marshalling::option::sequence_size_field_prefix<
                                           nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                                   // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                                   // std::array<typename FieldType::value_type, k> z;
                                   nil::marshalling::types::array_list<
                                       TTypeBase, field_element<TTypeBase, typename LPCScheme::field_type>,
                                       nil::marshalling::option::sequence_size_field_prefix<
                                           nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                                   // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                                   // std::array<typename fri_type::proof_type, lambda> fri_proof;
                                   nil::marshalling::types::array_list<
                                       TTypeBase, fri_proof<TTypeBase, typename LPCScheme::fri_type>,
                                       nil::marshalling::option::sequence_size_field_prefix<
                                           nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<typename LPCScheme, typename Endianness>
                lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme>
                    fill_lpc_proof(const typename LPCScheme::proof_type &proof) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using octet_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint8_t>;
                    using digest_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, octet_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using field_marhsalling_type = field_element<TTypeBase, typename LPCScheme::field_type>;
                    using field_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, field_marhsalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using fri_proof_marshalling_type = fri_proof<TTypeBase, typename LPCScheme::fri_type>;
                    using fri_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, fri_proof<TTypeBase, typename LPCScheme::fri_type>,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;

                    // typename merkle_tree_type::value_type T_root;
                    digest_marshalling_type filled_T_root;
                    for (const auto c : proof.T_root) {
                        filled_T_root.value().push_back(octet_marshalling_type(c));
                    }

                    // std::array<typename FieldType::value_type, k> z;
                    field_vector_marshalling_type filled_z;
                    for (const auto &c : proof.z) {
                        filled_z.value().push_back(field_marhsalling_type(c));
                    }

                    // std::array<typename fri_type::proof_type, lambda> fri_proof;
                    fri_proof_vector_marshalling_type filled_fri_proof;
                    for (const auto &p : proof.fri_proof) {
                        filled_fri_proof.value().push_back(fill_fri_proof<typename LPCScheme::fri_type, Endianness>(p));
                    }

                    return lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme>(
                        std::make_tuple(filled_T_root, filled_z, filled_fri_proof));
                }

                template<typename LPCScheme, typename Endianness>
                typename LPCScheme::proof_type
                    make_lpc_proof(const lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme> &filled_proof) {

                    typename LPCScheme::proof_type proof;

                    // typename merkle_tree_type::value_type T_root;
                    assert(proof.T_root.size() == std::get<0>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<0>(filled_proof.value()).value().size(); ++i) {
                        proof.T_root.at(i) = std::get<0>(filled_proof.value()).value().at(i).value();
                    }

                    // std::array<typename FieldType::value_type, k> z;
                    assert(proof.z.size() == std::get<1>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        proof.z.at(i) = std::get<1>(filled_proof.value()).value().at(i).value();
                    }

                    // std::array<typename fri_type::proof_type, lambda> fri_proof;
                    assert(proof.fri_proof.size() == std::get<2>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<2>(filled_proof.value()).value().size(); ++i) {
                        proof.fri_proof.at(i) = make_fri_proof<typename LPCScheme::fri_type, Endianness>(
                            std::get<2>(filled_proof.value()).value().at(i));
                    }

                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
