//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_MARSHALLING_EDDSA_HPP
#define CRYPTO3_PUBKEY_MARSHALLING_EDDSA_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/tag.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase,
                         typename PublicKey,
                         typename =
                             typename std::enable_if<std::is_same<PublicKey,
                                                                  pubkey::public_key<pubkey::eddsa<
                                                                      typename PublicKey::scheme_type::curve_type,
                                                                      PublicKey::scheme_type::block_bits>>>::value,
                                                     bool>::type,
                         typename... TOptions>
                using eddsa_public_key = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // pubkey_point
                        curve_element<TTypeBase, typename PublicKey::group_value_type>,
                        // pubkey
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            integral<TTypeBase, typename PublicKey::public_key_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<typename TTypeBase,
                         typename PrivateKey,
                         typename =
                             typename std::enable_if<std::is_same<PrivateKey,
                                                                  pubkey::private_key<pubkey::eddsa<
                                                                      typename PrivateKey::scheme_type::curve_type,
                                                                      PrivateKey::scheme_type::block_bits>>>::value,
                                                     bool>::type,
                         typename... TOptions>
                using eddsa_private_key = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // privkey
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            integral<TTypeBase, typename PrivateKey::public_key_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // h_privkey
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            integral<TTypeBase, typename PrivateKey::hash_type::digest_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // s_reduced
                        nil::marshalling::types::field_element<TTypeBase,
                            typename PrivateKey::scalar_field_value_type>>>;
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_PUBKEY_MARSHALLING_EDDSA_HPP
