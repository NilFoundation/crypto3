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

#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase, typename PublicKey, typename... TOptions>
                using eddsa_public_key = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // pubkey_point
                        curve_element<TTypeBase, typename PublicKey::group_type>,
                        // pubkey
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::integral<TTypeBase,
                                                              typename PublicKey::public_key_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<typename TTypeBase, typename PrivateKey, typename... TOptions>
                using eddsa_private_key = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // privkey
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::integral<TTypeBase,
                                                              typename PrivateKey::private_key_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // h_privkey
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::integral<TTypeBase,
                                                              typename PrivateKey::hash_type::digest_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // s_reduced
                        nil::crypto3::marshalling::types::field_element<TTypeBase,
                                                                        typename PrivateKey::scalar_field_value_type>>>;

                template<typename PublicKey, typename Endianness>
                eddsa_public_key<nil::marshalling::field_type<Endianness>, PublicKey>
                    fill_eddsa_public_key(const PublicKey &key_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    using curve_element_type = curve_element<TTypeBase, typename PublicKey::group_type>;

                    curve_element_type filled_pubkey_point = curve_element_type(key_inp.pubkey_point);

                    using integral_vector_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, typename PublicKey::public_key_type::value_type>,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<TTypeBase, std::size_t>>>;

                    integral_vector_type pubkey_data;

                    std::vector<
                        nil::marshalling::types::integral<TTypeBase, typename PublicKey::public_key_type::value_type>>
                        &val = pubkey_data.value();
                    for (std::size_t i = 0; i < key_inp.pubkey.size(); i++) {
                        val.push_back(
                            nil::marshalling::types::integral<TTypeBase,
                                                              typename PublicKey::public_key_type::value_type>(
                                key_inp.pubkey[i]));
                    }

                    return eddsa_public_key<nil::marshalling::field_type<Endianness>, PublicKey>(
                        std::make_tuple(filled_pubkey_point, pubkey_data));
                }

                template<typename PublicKey, typename Endianness>
                PublicKey make_eddsa_public_key(
                    const eddsa_public_key<nil::marshalling::field_type<Endianness>, PublicKey> &filled_key_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    typename PublicKey::public_key_type result;

                    const std::vector<
                        nil::marshalling::types::integral<TTypeBase, typename PublicKey::public_key_type::value_type>>
                        &values = std::get<1>(filled_key_inp.value()).value();

                    std::size_t size = values.size();

                    for (std::size_t i = 0; i < size; i++) {
                        result[i] = values[i].value();
                    }

                    PublicKey res(result);
                    res.pubkey_point = std::get<0>(filled_key_inp.value()).value();

                    return res;
                }

                template<typename PrivateKey, typename Endianness>
                eddsa_private_key<nil::marshalling::field_type<Endianness>, PrivateKey>
                    fill_eddsa_private_key(const PrivateKey &key_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    using integral_vector_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, typename PrivateKey::private_key_type::value_type>,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<TTypeBase, std::size_t>>>;

                    integral_vector_type privkey_data;

                    std::vector<
                        nil::marshalling::types::integral<TTypeBase, typename PrivateKey::private_key_type::value_type>>
                        &val = privkey_data.value();
                    for (std::size_t i = 0; i < key_inp.privkey.size(); i++) {
                        val.push_back(
                            nil::marshalling::types::integral<TTypeBase,
                                                              typename PrivateKey::private_key_type::value_type>(
                                key_inp.privkey[i]));
                    }

                    integral_vector_type h_privkey_data;

                    std::vector<
                        nil::marshalling::types::integral<TTypeBase, typename PrivateKey::private_key_type::value_type>>
                        &h_val = h_privkey_data.value();
                    for (std::size_t i = 0; i < key_inp.h_privkey.size(); i++) {
                        h_val.push_back(
                            nil::marshalling::types::integral<TTypeBase,
                                                              typename PrivateKey::private_key_type::value_type>(
                                key_inp.h_privkey[i]));
                    }

                    using field_element_type = field_element<TTypeBase, typename PrivateKey::scalar_field_value_type>;

                    field_element_type s_reduced_data = field_element_type(key_inp.s_reduced);

                    return eddsa_private_key<nil::marshalling::field_type<Endianness>, PrivateKey>(
                        std::make_tuple(privkey_data, h_privkey_data, s_reduced_data));
                }

                template<typename PrivateKey, typename Endianness>
                PrivateKey make_eddsa_private_key(
                    const eddsa_private_key<nil::marshalling::field_type<Endianness>, PrivateKey> &filled_key_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    typename PrivateKey::private_key_type privkey;

                    const std::vector<
                        nil::marshalling::types::integral<TTypeBase, typename PrivateKey::private_key_type::value_type>>
                        &values = std::get<0>(filled_key_inp.value()).value();

                    std::size_t size = values.size();

                    for (std::size_t i = 0; i < size; i++) {
                        privkey[i] = values[i].value();
                    }

                    typename PrivateKey::hash_type::digest_type h_privkey;

                    const std::vector<
                        nil::marshalling::types::integral<TTypeBase, typename PrivateKey::private_key_type::value_type>>
                        &h_values = std::get<1>(filled_key_inp.value()).value();

                    std::size_t h_size = h_values.size();

                    for (std::size_t i = 0; i < h_size; i++) {
                        h_privkey[i] = h_values[i].value();
                    }

                    PrivateKey res(privkey);
                    res.h_privkey = h_privkey;
                    res.s_reduced = std::get<2>(filled_key_inp.value()).value();

                    return res;
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_PUBKEY_MARSHALLING_EDDSA_HPP
