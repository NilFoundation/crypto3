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

#ifndef CRYPTO3_MARSHALLING_POWERS_OF_TAO_ACCUMULATOR_HPP
#define CRYPTO3_MARSHALLING_POWERS_OF_TAO_ACCUMULATOR_HPP

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
#include <nil/crypto3/zk/commitments/detail/polynomial/powers_of_tau/accumulator.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/algebra/types/fast_curve_element.hpp>
#include <nil/crypto3/marshalling/zk/types/accumulation_vector.hpp>
#include <nil/crypto3/marshalling/zk/types/sparse_vector.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase,
                         typename Accumulator,
                         typename = typename std::enable_if<
                             std::is_same<Accumulator,
                                          zk::commitments::detail::powers_of_tau_accumulator<
                                              typename Accumulator::curve_type,
                                              Accumulator::tau_powers_length>>::value,
                             bool>::type,
                         typename... TOptions>
                using powers_of_tau_accumulator = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // tau_powers_g1
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fast_curve_element<TTypeBase, typename Accumulator::curve_type::template g1_type<>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // tau_powers_g2
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fast_curve_element<TTypeBase, typename Accumulator::curve_type::template g2_type<>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // alpha_tau_powers_g1
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fast_curve_element<TTypeBase, typename Accumulator::curve_type::template g1_type<>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // beta_tau_powers_g1
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fast_curve_element<TTypeBase, typename Accumulator::curve_type::template g1_type<>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // beta_g2
                        fast_curve_element<TTypeBase, typename Accumulator::curve_type::template g2_type<>>
                    >>;

                template<typename Accumulator, typename Endianness>
                powers_of_tau_accumulator<nil::marshalling::field_type<Endianness>, Accumulator>
                    fill_powers_of_tau_accumulator(const Accumulator &accumulator) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    return powers_of_tau_accumulator<TTypeBase, Accumulator>(std::make_tuple(
                        std::move(
                            fill_fast_curve_element_vector<typename Accumulator::curve_type::template g1_type<>, Endianness>(
                                accumulator.tau_powers_g1)),
                        std::move(
                            fill_fast_curve_element_vector<typename Accumulator::curve_type::template g2_type<>, Endianness>(
                                accumulator.tau_powers_g2)),
                        std::move(
                            fill_fast_curve_element_vector<typename Accumulator::curve_type::template g1_type<>, Endianness>(
                                accumulator.alpha_tau_powers_g1)),
                        std::move(
                            fill_fast_curve_element_vector<typename Accumulator::curve_type::template g1_type<>, Endianness>(
                                accumulator.beta_tau_powers_g1)),
                        std::move(
                            fill_fast_curve_element<typename Accumulator::curve_type::template g2_type<>, Endianness>(
                                accumulator.beta_g2))));
                }

                template<typename Accumulator, typename Endianness>
                Accumulator make_powers_of_tau_accumulator(
                    const powers_of_tau_accumulator<nil::marshalling::field_type<Endianness>, Accumulator>
                        &filled_accumulator) {

                    return Accumulator(
                        std::move(
                            make_fast_curve_element_vector<typename Accumulator::curve_type::template g1_type<>, Endianness>(
                                std::get<0>(filled_accumulator.value()))),
                        std::move(
                            make_fast_curve_element_vector<typename Accumulator::curve_type::template g2_type<>, Endianness>(
                                std::get<1>(filled_accumulator.value()))),
                        std::move(
                            make_fast_curve_element_vector<typename Accumulator::curve_type::template g1_type<>, Endianness>(
                                std::get<2>(filled_accumulator.value()))),
                        std::move(
                            make_fast_curve_element_vector<typename Accumulator::curve_type::template g1_type<>, Endianness>(
                                std::get<3>(filled_accumulator.value()))),
                        std::move(
                            make_fast_curve_element<typename Accumulator::curve_type::template g2_type<>, Endianness>(
                                std::get<4>(filled_accumulator.value())))
                    );
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_POWERS_OF_TAO_ACCUMULATOR_HPP
