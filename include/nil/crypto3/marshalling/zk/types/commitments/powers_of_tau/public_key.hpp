//---------------------------------------------------------------------------//
// Copyright (c) 2022 Noam Y <@NoamDev>
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

#ifndef CRYPTO3_MARSHALLING_POWERS_OF_TAU_PUBLIC_KEY_HPP
#define CRYPTO3_MARSHALLING_POWERS_OF_TAU_PUBLIC_KEY_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/zk/commitments/detail/polynomial/powers_of_tau/public_key.hpp>

#include <nil/crypto3/marshalling/zk/types/commitments/proof_of_knowledge.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase,
                         typename PublicKey,
                         typename = typename std::enable_if<
                             std::is_same<PublicKey,
                                          zk::commitments::detail::powers_of_tau_public_key <typename PublicKey::curve_type>>::value,
                             bool>::type,
                         typename... TOptions>
                using powers_of_tau_public_key = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // tau_pok
                        element_pok<TTypeBase, typename PublicKey::pok_type>,
                        // alpha_pok
                        element_pok<TTypeBase, typename PublicKey::pok_type>,
                        // beta_pok
                        element_pok<TTypeBase, typename PublicKey::pok_type>>>;

                template<typename PublicKey, typename Endianness>
                powers_of_tau_public_key<nil::marshalling::field_type<Endianness>, PublicKey>
                    fill_powers_of_tau_public_key(const PublicKey &public_key) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    return powers_of_tau_public_key<TTypeBase, PublicKey>(
                        std::make_tuple(
                            std::move(
                                fill_element_pok<typename PublicKey::pok_type, Endianness>(
                                    public_key.tau_pok)),
                            std::move(
                                fill_element_pok<typename PublicKey::pok_type, Endianness>(
                                    public_key.alpha_pok)),
                            std::move(
                                fill_element_pok<typename PublicKey::pok_type, Endianness>(
                                    public_key.beta_pok))
                    ));
                }

                template<typename PublicKey, typename Endianness>
                PublicKey make_powers_of_tau_public_key(
                    const powers_of_tau_public_key<nil::marshalling::field_type<Endianness>, PublicKey>
                        &filled_public_key) {

                    return PublicKey(
                        std::move(
                            make_element_pok<typename PublicKey::pok_type, Endianness>(
                                std::get<0>(filled_public_key.value()))),
                        std::move(
                            make_element_pok<typename PublicKey::pok_type, Endianness>(
                                std::get<1>(filled_public_key.value()))),
                        std::move(
                            make_element_pok<typename PublicKey::pok_type, Endianness>(
                                std::get<2>(filled_public_key.value())))
                    );
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_POWERS_OF_TAU_PUBLIC_KEY_HPP
