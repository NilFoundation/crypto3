//---------------------------------------------------------------------------//
// Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/kzg.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                // ******************* Marshalling of commitment params for Basic Fri and KZG. ********************************* //
                template<typename TTypeBase, typename CommitmentParamsType,
                    typename std::enable_if<
                        std::is_same<CommitmentParamsType, nil::crypto3::zk::commitments::detail::basic_batched_fri::params_type<typename Proof::field_type, typename Proof::params_type>>::value,
                        bool
                    >::type = true
                >
                using commitment_params = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<






//                      constexpr static const std::size_t witness_columns = PlaceholderParamsType::witness_columns;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      constexpr static const std::size_t public_input_columns = PlaceholderParamsType::public_input_columns;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      constexpr static const std::size_t constant_columns = PlaceholderParamsType::constant_columns;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      constexpr static const std::size_t selector_columns = PlaceholderParamsType::selector_columns;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      constexpr static const typename field_type::value_type delta = PlaceholderParamsType::delta;
                        field_element<TTypeBase, typename Proof::field_type::value_type>,
//                      std::size_t rows_amount;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      std::size_t usable_rows_amount;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      typename commitment_type::params_type commitment_params;
                        typename commitment_params<TTypeBase, CommitmentParamsType>::type,
//                      constexpr static const typename field_type::value_type modulus = field_type::modulus;
                        field_element<TTypeBase, typename Proof::field_type::value_type>,
//                      std::string application_id;
                        marshalling_string_type
                    >
                >;

                template<typename Endianness, typename CommitmentParamsType>
                commitment_params<nil::marshalling::field_type<Endianness>, CommitmentParamsType>
                fill_commitment_params(const CommitmentParamsType &init_context){
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;
                    using result_type = commitment_params<TTypeBase, CommitmentParamsType>;
                    using field_element_marshalling_type field_element<TTypeBase, typename Proof::field_type::value_type>;

                    result_type result;
                    using FieldType = typename CommitmentParamsType::field_type;

                    auto filled_commitment_params =
                        fill_commitment_params<Endianness, typename CommitmentParamsType::commitment_type>(
                            init_context.commitment_params
                    );

                    return result_type(std::make_tuple(
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(init_context.witness_columns),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(init_context.public_input_columns),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(init_context.constant_columns),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(init_context.selector_columns),
                        field_element_marshalling_type(init_context.delta),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(init_context.rows_amount),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(init_context.usable_rows_amount),
                        filled_commitment_params,
                        field_element_marshalling_type(init_context.modulus),
                        marshalling_string_type
                    ));
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP
