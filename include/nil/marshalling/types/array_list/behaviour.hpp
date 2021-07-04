//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef MARSHALLING_ARRAY_LIST_BEHAVIOUR_HPP
#define MARSHALLING_ARRAY_LIST_BEHAVIOUR_HPP

#include <vector>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/container/static_vector.hpp>
#include <nil/marshalling/container/array_view.hpp>
#include <nil/marshalling/types/array_list/basic_type.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/types/detail/options_parser.hpp>

#include <nil/marshalling/types/tag.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<bool THasOrigDataViewStorage>
                struct array_list_orig_data_view_storage_type;

                template<>
                struct array_list_orig_data_view_storage_type<true> {
                    template<typename TElement>
                    using type = nil::marshalling::container::array_view<TElement>;
                };

                template<>
                struct array_list_orig_data_view_storage_type<false> {
                    template<typename TElement>
                    using type = std::vector<TElement>;
                };

                template<bool THasSequenceFixedSizeUseFixedSizeStorage>
                struct array_list_sequence_fixed_size_use_fixed_size_storage_type;

                template<>
                struct array_list_sequence_fixed_size_use_fixed_size_storage_type<true> {
                    template<typename TElement, typename TOpt>
                    using type = nil::marshalling::container::static_vector<TElement, TOpt::sequence_fixed_size>;
                };

                template<>
                struct array_list_sequence_fixed_size_use_fixed_size_storage_type<false> {
                    template<typename TElement, typename TOpt>
                    using type = typename array_list_orig_data_view_storage_type<
                        TOpt::has_orig_data_view && std::is_integral<TElement>::value
                        && (sizeof(TElement) == sizeof(std::uint8_t))>::template type<TElement>;
                };

                template<bool THasFixedSizeStorage>
                struct array_list_fixed_size_storage_type;

                template<>
                struct array_list_fixed_size_storage_type<true> {
                    template<typename TElement, typename TOpt>
                    using type = nil::marshalling::container::static_vector<TElement, TOpt::fixed_size_storage>;
                };

                template<>
                struct array_list_fixed_size_storage_type<false> {
                    template<typename TElement, typename TOpt>
                    using type = typename array_list_sequence_fixed_size_use_fixed_size_storage_type<
                        TOpt::has_sequence_fixed_size_use_fixed_size_storage>::template type<TElement, TOpt>;
                };

                template<bool THasCustomStorage>
                struct array_list_custom_array_list_storage_type;

                template<>
                struct array_list_custom_array_list_storage_type<true> {
                    template<typename TElement, typename TOpt>
                    using type = typename TOpt::custom_storage_type;
                };

                template<>
                struct array_list_custom_array_list_storage_type<false> {
                    template<typename TElement, typename TOpt>
                    using type = typename array_list_fixed_size_storage_type<
                        TOpt::has_fixed_size_storage>::template type<TElement, TOpt>;
                };

                template<typename TElement, typename TOpt>
                using array_list_storage_type_type = typename array_list_custom_array_list_storage_type<
                    TOpt::has_custom_storage_type>::template type<TElement, TOpt>;

                template<typename TFieldBase, typename TElement, typename... TOptions>
                using array_list_base_type = adapt_basic_field_type<
                    basic_array_list<
                        TFieldBase, array_list_storage_type_type<TElement, options_parser<TOptions...>>>,
                    TOptions...>;

            }    // namespace detail
        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_ARRAY_LIST_BEHAVIOUR_HPP
