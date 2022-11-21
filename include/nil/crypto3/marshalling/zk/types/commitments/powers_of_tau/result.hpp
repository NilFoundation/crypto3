//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_POWERS_OF_TAO_RESULT_HPP
#define CRYPTO3_MARSHALLING_POWERS_OF_TAO_RESULT_HPP

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

#include <nil/crypto3/container/accumulation_vector.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/powers_of_tau/result.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/algebra/types/fast_curve_element.hpp>
#include <nil/crypto3/marshalling/zk/types/accumulation_vector.hpp>
#include <nil/crypto3/marshalling/zk/types/sparse_vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase,
                         typename Result,
                         typename = typename std::enable_if<
                             std::is_same<Result,
                                          zk::commitments::detail::powers_of_tau_result<
                                              typename Result::curve_type>>::value,
                             bool>::type,
                         typename... TOptions>
                using powers_of_tau_result = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // alpha_g1
                        fast_curve_element<TTypeBase, typename Result::curve_type::template g1_type<>>,
                        // beta_g1
                        fast_curve_element<TTypeBase, typename Result::curve_type::template g1_type<>>,
                        // beta_g2
                        fast_curve_element<TTypeBase, typename Result::curve_type::template g2_type<>>,
                        // coeffs_g1
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fast_curve_element<TTypeBase, typename Result::curve_type::template g1_type<>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // coeffs_g2
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fast_curve_element<TTypeBase, typename Result::curve_type::template g2_type<>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // alpha_coeffs_g1
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fast_curve_element<TTypeBase, typename Result::curve_type::template g1_type<>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // beta_coeffs_g1
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fast_curve_element<TTypeBase, typename Result::curve_type::template g1_type<>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // h
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fast_curve_element<TTypeBase, typename Result::curve_type::template g1_type<>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>
                    >>;

                template<typename Result, typename Endianness>
                powers_of_tau_result<nil::marshalling::field_type<Endianness>, Result>
                    fill_powers_of_tau_result(const Result &result) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using curve_g1_element_type =
                        fast_curve_element<TTypeBase, typename Result::curve_type::template g1_type<>>;
                    using curve_g2_element_type =
                        fast_curve_element<TTypeBase, typename Result::curve_type::template g2_type<>>;

                    return powers_of_tau_result<TTypeBase, Result>(std::make_tuple(
                         std::move(
                            fill_fast_curve_element<typename Result::curve_type::template g1_type<>, Endianness>(
                                result.alpha_g1)),
                         std::move(
                            fill_fast_curve_element<typename Result::curve_type::template g1_type<>, Endianness>(
                                result.beta_g1)),
                         std::move(
                            fill_fast_curve_element<typename Result::curve_type::template g2_type<>, Endianness>(
                                result.beta_g2)),
                        std::move(
                            fill_fast_curve_element_vector<typename Result::curve_type::template g1_type<>, Endianness>(
                                result.coeffs_g1)),
                        std::move(
                            fill_fast_curve_element_vector<typename Result::curve_type::template g2_type<>, Endianness>(
                                result.coeffs_g2)),
                        std::move(
                            fill_fast_curve_element_vector<typename Result::curve_type::template g1_type<>, Endianness>(
                                result.alpha_coeffs_g1)),
                        std::move(
                            fill_fast_curve_element_vector<typename Result::curve_type::template g1_type<>, Endianness>(
                                result.beta_coeffs_g1)),
                        std::move(
                            fill_fast_curve_element_vector<typename Result::curve_type::template g1_type<>, Endianness>(
                                result.h))
                       ));
                }

                template<typename Result, typename Endianness>
                Result make_powers_of_tau_result(
                    const powers_of_tau_result<nil::marshalling::field_type<Endianness>, Result>
                        &filled_result) {

                    return Result(
                        std::move(
                            make_fast_curve_element<typename Result::curve_type::template g1_type<>, Endianness>(
                                std::get<0>(filled_result.value()))),
                        std::move(
                            make_fast_curve_element<typename Result::curve_type::template g1_type<>, Endianness>(
                                std::get<1>(filled_result.value()))),
                        std::move(
                            make_fast_curve_element<typename Result::curve_type::template g2_type<>, Endianness>(
                                std::get<2>(filled_result.value()))),
                        std::move(
                            make_fast_curve_element_vector<typename Result::curve_type::template g1_type<>, Endianness>(
                                std::get<3>(filled_result.value()))),
                        std::move(
                            make_fast_curve_element_vector<typename Result::curve_type::template g2_type<>, Endianness>(
                                std::get<4>(filled_result.value()))),
                        std::move(
                            make_fast_curve_element_vector<typename Result::curve_type::template g1_type<>, Endianness>(
                                std::get<5>(filled_result.value()))),
                        std::move(
                            make_fast_curve_element_vector<typename Result::curve_type::template g1_type<>, Endianness>(
                                std::get<6>(filled_result.value()))),
                        std::move(
                            make_fast_curve_element_vector<typename Result::curve_type::template g1_type<>, Endianness>(
                                std::get<7>(filled_result.value())))
                    );
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_POWERS_OF_TAO_RESULT_HPP
