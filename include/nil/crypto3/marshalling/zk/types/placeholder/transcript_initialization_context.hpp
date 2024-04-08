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

#ifndef CRYPTO3_MARSHALLING_PLACEHOLDER_TRANSCRIPT_INITIALIZATION_CONTEXT_HPP
#define CRYPTO3_MARSHALLING_PLACEHOLDER_TRANSCRIPT_INITIALIZATION_CONTEXT_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/types/string.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/commitment_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase>
                using marshalling_string_type = nil::marshalling::types::string<TTypeBase>;

                // ******************* placeholder transcript initialization context ********************************* //
                template<typename TTypeBase, typename TranscriptInitializationContextType>
                using transcript_initialization_context = nil::marshalling::types::bundle<
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
                        field_element<TTypeBase, typename TranscriptInitializationContextType::field_type::value_type>,
//                      std::size_t rows_amount;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      std::size_t usable_rows_amount;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      typename commitment_type::params_type commitment_params;
                        typename commitment_params<TTypeBase,
                            typename TranscriptInitializationContextType::commitment_scheme_type>::type,
//                      constexpr static const typename field_type::value_type modulus = field_type::modulus;
                        field_element<TTypeBase, typename TranscriptInitializationContextType::field_type::value_type>,
//                      std::string application_id;
                        marshalling_string_type<TTypeBase>
                    >
                >;

                template<typename Endianness, typename TranscriptInitializationContextType>
                transcript_initialization_context<nil::marshalling::field_type<Endianness>, TranscriptInitializationContextType>
                fill_transcript_initialization_context(const TranscriptInitializationContextType &init_context) {
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;
                    using result_type = transcript_initialization_context<TTypeBase, TranscriptInitializationContextType>;
                    using field_element_marshalling_type = field_element<TTypeBase, typename TranscriptInitializationContextType::field_type::value_type>;

                    result_type result;

                    auto filled_commitment_params =
                        fill_commitment_params<Endianness, typename TranscriptInitializationContextType::commitment_scheme_type>(
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
                        marshalling_string_type<TTypeBase>(init_context.application_id)
                    ));
                }

                // TODO(martun): We don't need the opposite conversion for now, only for testing purposes.
                // template<typename Endianness, typename TranscriptInitializationContextType>
                // TranscriptInitializationContextType
                // make_transcript_initialization_context(
                //     const transcript_initialization_context<nil::marshalling::field_type<Endianness>, TranscriptInitializationContextType> &filled_init_context
                // ) {
                // }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_PLACEHOLDER_TRANSCRIPT_INITIALIZATION_CONTEXT_HPP
