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

#ifndef MARSHALLING_STRING_BEHAVIOUR_HPP
#define MARSHALLING_STRING_BEHAVIOUR_HPP

#include <vector>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/container/static_string.hpp>
#include <nil/marshalling/container/string_view.hpp>
#include <nil/marshalling/types/string/basic_type.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/types/detail/options_parser.hpp>

#include <nil/marshalling/types/tag.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<bool THasOrigDataViewStorage>
                struct string_orig_data_view_storage_type;

                template<>
                struct string_orig_data_view_storage_type<true> {
                    using type = nil::marshalling::container::string_view;
                };

                template<>
                struct string_orig_data_view_storage_type<false> {
                    using type = std::string;
                };

                template<bool THasSequenceFixedSizeUseFixedSizeStorage>
                struct string_fixed_size_use_fixed_size_storage_type;

                template<>
                struct string_fixed_size_use_fixed_size_storage_type<true> {
                    template<typename TOpt>
                    using type = nil::marshalling::container::static_string<TOpt::sequence_fixed_size>;
                };

                template<>
                struct string_fixed_size_use_fixed_size_storage_type<false> {
                    template<typename TOpt>
                    using type = typename string_orig_data_view_storage_type<TOpt::has_orig_data_view>::type;
                };

                template<bool THasFixedSizeStorage>
                struct string_fixed_size_storage_type;

                template<>
                struct string_fixed_size_storage_type<true> {
                    template<typename TOpt>
                    using type = nil::marshalling::container::static_string<TOpt::fixed_size_storage>;
                };

                template<>
                struct string_fixed_size_storage_type<false> {
                    template<typename TOpt>
                    using type = typename string_fixed_size_use_fixed_size_storage_type<
                        TOpt::has_sequence_fixed_size_use_fixed_size_storage>::template type<TOpt>;
                };

                template<bool THasCustomStorage>
                struct string_custom_string_storage_type;

                template<>
                struct string_custom_string_storage_type<true> {
                    template<typename TOpt>
                    using type = typename TOpt::custom_storage_type;
                };

                template<>
                struct string_custom_string_storage_type<false> {
                    template<typename TOpt>
                    using type =
                        typename string_fixed_size_storage_type<TOpt::has_fixed_size_storage>::template type<TOpt>;
                };

                template<typename TOpt>
                using string_storage_type =
                    typename string_custom_string_storage_type<TOpt::has_custom_storage_type>::template type<TOpt>;

                template<typename TFieldBase, typename... TOptions>
                using string_base_type = adapt_basic_field_type<
                    basic_string<TFieldBase, string_storage_type<options_parser<TOptions...>>>,
                    TOptions...>;

            }    // namespace detail
        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_STRING_BEHAVIOUR_HPP
