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

#ifndef CRYPTO3_PUBKEY_MARSHALLING_ELGAMAL_VERIFIABLE_HPP
#define CRYPTO3_PUBKEY_MARSHALLING_ELGAMAL_VERIFIABLE_HPP

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

#include <nil/crypto3/pubkey/elgamal_verifiable.hpp>

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
                                                                  pubkey::public_key<pubkey::elgamal_verifiable<
                                                                      typename PublicKey::scheme_type::curve_type,
                                                                      PublicKey::scheme_type::block_bits>>>::value,
                                                     bool>::type,
                         typename... TOptions>
                using elgamal_verifiable_public_key = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // delta_g1
                        curve_element<TTypeBase, typename PublicKey::g1_type>,
                        // delta_sum_s_g1
                        curve_element<TTypeBase, typename PublicKey::g1_type>,
                        // gamma_inverse_sum_s_g1
                        curve_element<TTypeBase, typename PublicKey::g1_type>,
                        // delta_s_g1
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            curve_element<TTypeBase, typename PublicKey::g1_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // t_g1
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            curve_element<TTypeBase, typename PublicKey::g1_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // t_g2
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            curve_element<TTypeBase, typename PublicKey::g2_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<typename TTypeBase,
                         typename PrivateKey,
                         typename =
                             typename std::enable_if<std::is_same<PrivateKey,
                                                                  pubkey::private_key<pubkey::elgamal_verifiable<
                                                                      typename PrivateKey::scheme_type::curve_type,
                                                                      PrivateKey::scheme_type::block_bits>>>::value,
                                                     bool>::type,
                         typename... TOptions>
                using elgamal_verifiable_private_key = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // rho
                        field_element<TTypeBase, typename PrivateKey::scalar_field_type::value_type>>>;

                template<typename TTypeBase,
                         typename VerificationKey,
                         typename = typename std::enable_if<
                             std::is_same<VerificationKey,
                                          pubkey::verification_key<pubkey::elgamal_verifiable<
                                              typename VerificationKey::scheme_type::curve_type,
                                              VerificationKey::scheme_type::block_bits>>>::value,
                             bool>::type,
                         typename... TOptions>
                using elgamal_verifiable_verification_key = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // rho_g2
                        curve_element<TTypeBase, typename VerificationKey::g2_type>,
                        // rho_sv_g2
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            curve_element<TTypeBase, typename VerificationKey::g2_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // rho_rhov_g2
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            curve_element<TTypeBase, typename VerificationKey::g2_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<typename PublicKey, typename Endianness>
                elgamal_verifiable_public_key<nil::marshalling::field_type<Endianness>, PublicKey>
                    fill_public_key(const PublicKey &key_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    using curve_g1_element_type = curve_element<TTypeBase, typename PublicKey::g1_type>;

                    curve_g1_element_type filled_delta_g1 = curve_g1_element_type(key_inp.delta_g1);

                    curve_g1_element_type filled_delta_sum_s_g1 = curve_g1_element_type(key_inp.delta_sum_s_g1);

                    curve_g1_element_type filled_gamma_inverse_sum_s_g1 =
                        curve_g1_element_type(key_inp.gamma_inverse_sum_s_g1);

                    return elgamal_verifiable_public_key<nil::marshalling::field_type<Endianness>, PublicKey>(
                        std::make_tuple(
                            filled_delta_g1,
                            filled_delta_sum_s_g1,
                            filled_gamma_inverse_sum_s_g1,
                            fill_curve_element_vector<typename PublicKey::g1_type, Endianness>(key_inp.delta_s_g1),
                            fill_curve_element_vector<typename PublicKey::g1_type, Endianness>(key_inp.t_g1),
                            fill_curve_element_vector<typename PublicKey::g2_type, Endianness>(key_inp.t_g2)));
                }

                template<typename PublicKey, typename Endianness>
                PublicKey make_public_key(const elgamal_verifiable_public_key<nil::marshalling::field_type<Endianness>,
                                                                              PublicKey> &filled_key_inp) {

                    return PublicKey(std::move(std::get<0>(filled_key_inp.value()).value()),
                                     std::move(make_curve_element_vector<typename PublicKey::g1_type, Endianness>(
                                         std::get<3>(filled_key_inp.value()))),
                                     std::move(make_curve_element_vector<typename PublicKey::g1_type, Endianness>(
                                         std::get<4>(filled_key_inp.value()))),
                                     std::move(make_curve_element_vector<typename PublicKey::g2_type, Endianness>(
                                         std::get<5>(filled_key_inp.value()))),
                                     std::move(std::get<1>(filled_key_inp.value()).value()),
                                     std::move(std::get<2>(filled_key_inp.value()).value()));
                }

                template<typename PrivateKey, typename Endianness>
                elgamal_verifiable_private_key<nil::marshalling::field_type<Endianness>, PrivateKey>
                    fill_private_key(const PrivateKey &key_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using field_element_marshalling_type =
                        field_element<TTypeBase, typename PrivateKey::scalar_field_type::value_type>;

                    field_element_marshalling_type filled_rho(key_inp.rho);

                    return elgamal_verifiable_private_key<TTypeBase, PrivateKey>(std::make_tuple(filled_rho));
                }

                template<typename PrivateKey, typename Endianness>
                PrivateKey
                    make_private_key(const elgamal_verifiable_private_key<nil::marshalling::field_type<Endianness>,
                                                                          PrivateKey> &filled_key_inp) {
                    return PrivateKey(std::move(std::get<0>(filled_key_inp.value()).value()));
                }

                template<typename VerificationKey, typename Endianness>
                elgamal_verifiable_verification_key<nil::marshalling::field_type<Endianness>, VerificationKey>
                    fill_verification_key(const VerificationKey &key_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using curve_g2_element_type = curve_element<TTypeBase, typename VerificationKey::g2_type>;

                    curve_g2_element_type filled_rho_g2 = curve_g2_element_type(key_inp.rho_g2);
                    return elgamal_verifiable_verification_key<TTypeBase, VerificationKey>(std::make_tuple(
                        filled_rho_g2,
                        fill_curve_element_vector<typename VerificationKey::g2_type, Endianness>(key_inp.rho_sv_g2),
                        fill_curve_element_vector<typename VerificationKey::g2_type, Endianness>(key_inp.rho_rhov_g2)));
                }

                template<typename VerificationKey, typename Endianness>
                VerificationKey make_verification_key(
                    const elgamal_verifiable_verification_key<nil::marshalling::field_type<Endianness>, VerificationKey>
                        &filled_key_inp) {

                    return VerificationKey(
                        std::move(std::get<0>(filled_key_inp.value()).value()),
                        std::move(make_curve_element_vector<typename VerificationKey::g2_type, Endianness>(
                            std::get<1>(filled_key_inp.value()))),
                        std::move(make_curve_element_vector<typename VerificationKey::g2_type, Endianness>(
                            std::get<2>(filled_key_inp.value()))));
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_PUBKEY_MARSHALLING_ELGAMAL_VERIFIABLE_HPP
