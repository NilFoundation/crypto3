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

                template<typename TTypeBase,
                         typename PublicKey,
                         typename... TOptions>
                using eddsa_public_key = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // pubkey_point
                        curve_element<TTypeBase, typename PublicKey::group_type>,
                        // pubkey
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            integral<TTypeBase, typename PublicKey::public_key_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<typename TTypeBase,
                         typename PrivateKey,
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
                        nil::crypto3::marshalling::types::field_element<TTypeBase,
                            typename PrivateKey::scalar_field_value_type>>>;

                template<typename PublicKey, typename Endianness>
                eddsa_public_key<nil::marshalling::field_type<Endianness>, PublicKey>
                    fill_eddsa_public_key(const PublicKey &key_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    using curve_element_type = curve_element<TTypeBase, typename PublicKey::g1_type>;

                    curve_element_type filled_pubkey_point = curve_element_type(key_inp.pubkey_point);

                    using integral_vector_type = nil::marshalling::types::array_list<
                            TTypeBase,
                            integral<TTypeBase, typename PublicKey::public_key_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>;

                    integral_vector_type pubkey_data;

                    std::vector<integral<TTypeBase, typename PublicKey::public_key_type::value_type>> &val
                        = pubkey_data.value();
                    for (std::size_t i = 0; i < key_inp.pubkey.size(); i++) {
                        val.push_back(integral<TTypeBase,
                            typename PublicKey::public_key_type::value_type>(key_inp.pubkey[i]));
                    }

                    return eddsa_public_key<nil::marshalling::field_type<Endianness>, PublicKey>(
                        std::make_tuple(
                            filled_pubkey_point,
                            pubkey_data));
                }

                template<typename PublicKey, typename Endianness>
                PublicKey make_public_key(const eddsa_public_key<nil::marshalling::field_type<Endianness>,
                                                                              PublicKey> &filled_key_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    typename PublicKey::public_key_type result;

                    const std::vector<integral<TTypeBase,
                        typename PublicKey::public_key_type::value_type>> &values =
                        std::get<1>(filled_key_inp.value()).value();

                    std::size_t size = values.size();

                    for (std::size_t i = 0; i < size; i++) {
                        result.push_back(values[i].value());
                    }

                    return PublicKey(std::move(std::get<0>(filled_key_inp.value()).value()),
                                     std::move(result));
                }

                // template<typename Private, typename Endianness>
                // eddsa_public_key<nil::marshalling::field_type<Endianness>, Private>
                //     fill_eddsa_private_key(const Private &key_inp) {

                //     using TTypeBase = nil::marshalling::field_type<Endianness>;

                //     using curve_element_type = curve_element<TTypeBase, typename PublicKey::g1_type>;

                //     curve_element_type filled_pubkey_point = curve_element_type(key_inp.pubkey_point);

                //     using integral_vector_type = nil::marshalling::types::array_list<
                //             TTypeBase,
                //             integral<TTypeBase, typename PublicKey::public_key_type::value_type>,
                //             nil::marshalling::option::sequence_size_field_prefix<
                //                 nil::marshalling::types::integral<TTypeBase, std::size_t>>>;

                //     integral_vector_type pubkey_data;

                //     std::vector<integral<TTypeBase, typename PublicKey::public_key_type::value_type>> &val
                //         = pubkey_data.value();
                //     for (std::size_t i = 0; i < key_inp.pubkey.size(); i++) {
                //         val.push_back(integral<TTypeBase,
                //             typename PublicKey::public_key_type::value_type>(key_inp.pubkey[i]));
                //     }

                //     return eddsa_public_key<nil::marshalling::field_type<Endianness>, PublicKey>(
                //         std::make_tuple(
                //             filled_pubkey_point,
                //             pubkey_data));
                // }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_PUBKEY_MARSHALLING_EDDSA_HPP
