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

#ifndef CRYPTO3_MARSHALLING_PROOF_OF_KNOWLEDGE_HPP
#define CRYPTO3_MARSHALLING_PROOF_OF_KNOWLEDGE_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/zk/commitments/detail/polynomial/element_proof_of_knowledge.hpp>

#include <nil/crypto3/marshalling/algebra/types/fast_curve_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase,
                         typename POK,
                         typename = typename std::enable_if<
                             std::is_same<POK,
                                          zk::commitments::detail::element_pok <typename POK::curve_type>>::value,
                             bool>::type,
                         typename... TOptions>
                using element_pok = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // g1_s
                        fast_curve_element<TTypeBase, typename POK::curve_type::template g1_type<>>,
                        // g1_s_x
                        fast_curve_element<TTypeBase, typename POK::curve_type::template g1_type<>>,
                        // g2_s_x
                        fast_curve_element<TTypeBase, typename POK::curve_type::template g2_type<>>>>;

                template<typename POK, typename Endianness>
                element_pok<nil::marshalling::field_type<Endianness>, POK>
                    fill_element_pok(const POK &pok) {

                    return element_pok<nil::marshalling::field_type<Endianness>, POK>(
                        std::make_tuple(
                            std::move(
                                fill_fast_curve_element<typename POK::curve_type::template g1_type<>, Endianness>(
                                    pok.g1_s)),
                            std::move(
                                fill_fast_curve_element<typename POK::curve_type::template g1_type<>, Endianness>(
                                    pok.g1_s_x)),
                            std::move(
                                fill_fast_curve_element<typename POK::curve_type::template g2_type<>, Endianness>(
                                    pok.g2_s_x))
                        ));
                }

                template<typename POK, typename Endianness>
                POK make_element_pok(
                    const element_pok<nil::marshalling::field_type<Endianness>, POK>
                        &filled_pok) {

                    return POK(
                        std::move(
                            make_fast_curve_element<typename POK::curve_type::template g1_type<>, Endianness>(
                                std::get<0>(filled_pok.value()))),
                        std::move(
                            make_fast_curve_element<typename POK::curve_type::template g1_type<>, Endianness>(
                                std::get<1>(filled_pok.value()))),
                        std::move(
                            make_fast_curve_element<typename POK::curve_type::template g2_type<>, Endianness>(
                                std::get<2>(filled_pok.value())))
                    );
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_PROOF_OF_KNOWLEDGE_HPP
