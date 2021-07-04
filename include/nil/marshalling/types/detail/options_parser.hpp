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

#ifndef MARSHALLING_OPTIONS_PARSER_HPP
#define MARSHALLING_OPTIONS_PARSER_HPP

#include <tuple>
#include <ratio>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/compile_control.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<typename... TOptions>
                class options_parser;

                template<>
                class options_parser<> {
                public:
                    static const bool has_custom_value_reader = false;
                    static const bool has_custom_read = false;
                    static const bool has_ser_offset = false;
                    static const bool has_fixed_length_limit = false;
                    static const bool has_fixed_bit_length_limit = false;
                    static const bool has_var_length_limits = false;
                    static const bool has_sequence_elem_length_forcing = false;
                    static const bool has_sequence_size_forcing = false;
                    static const bool has_sequence_length_forcing = false;
                    static const bool has_sequence_fixed_size = false;
                    static const bool has_sequence_fixed_size_use_fixed_size_storage = false;
                    static const bool has_sequence_size_field_prefix = false;
                    static const bool has_sequence_ser_length_field_prefix = false;
                    static const bool has_sequence_elem_ser_length_field_prefix = false;
                    static const bool has_sequence_elem_fixed_ser_length_field_prefix = false;
                    static const bool has_sequence_trailing_field_suffix = false;
                    static const bool has_sequence_termination_field_suffix = false;
                    static const bool has_default_value_initializer = false;
                    static const bool has_custom_validator = false;
                    static const bool has_contents_refresher = false;
                    static const bool has_custom_refresh = false;
                    static const bool has_fail_on_invalid = false;
                    static const bool has_ignore_invalid = false;
                    static const bool has_invalid_by_default = false;
                    static const bool has_fixed_size_storage = false;
                    static const bool has_custom_storage_type = false;
                    static const bool has_scaling_ratio = false;
                    static const bool has_units = false;
                    static const bool has_orig_data_view = false;
                    static const bool has_empty_serialization = false;
                    static const bool has_multi_range_validation = false;
                    static const bool has_custom_version_update = false;
                    static const bool has_versions_range = false;
                    static const bool has_version_storage = false;
                };

                template<typename T, typename... TOptions>
                class options_parser<nil::marshalling::option::custom_value_reader<T>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_custom_value_reader = true;
                    using custom_value_reader = T;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::has_custom_read, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_custom_read = true;
                };

                template<std::intmax_t TOffset, typename... TOptions>
                class options_parser<nil::marshalling::option::num_value_ser_offset<TOffset>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_ser_offset = true;
                    static const auto ser_offset = TOffset;
                };

                template<std::size_t TLen, bool TSignExtend, typename... TOptions>
                class options_parser<nil::marshalling::option::fixed_length<TLen, TSignExtend>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_fixed_length_limit = true;
                    static const std::size_t fixed_length = TLen;
                    static const bool fixed_length_sign_extend = TSignExtend;
                };

                template<std::size_t TLen, typename... TOptions>
                class options_parser<nil::marshalling::option::fixed_bit_length<TLen>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_fixed_bit_length_limit = true;
                    static const std::size_t fixed_bit_length = TLen;
                };

                template<std::size_t TMinLen, std::size_t TMaxLen, typename... TOptions>
                class options_parser<nil::marshalling::option::var_length<TMinLen, TMaxLen>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_var_length_limits = true;
                    static const std::size_t min_var_length = TMinLen;
                    static const std::size_t max_var_length = TMaxLen;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::sequence_size_forcing_enabled, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_size_forcing = true;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::sequence_length_forcing_enabled, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_length_forcing = true;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::sequence_elem_length_forcing_enabled, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_elem_length_forcing = true;
                };

                template<std::size_t TSize, typename... TOptions>
                class options_parser<nil::marshalling::option::sequence_fixed_size<TSize>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_fixed_size = true;
                    static const auto sequence_fixed_size = TSize;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::sequence_fixed_size_use_fixed_size_storage, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_fixed_size_use_fixed_size_storage = true;
                };

                template<typename TSizeField, typename... TOptions>
                class options_parser<nil::marshalling::option::sequence_size_field_prefix<TSizeField>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_size_field_prefix = true;
                    using sequence_size_field_prefix_type = TSizeField;
                };

                template<typename TField, status_type TReadErrorStatus, typename... TOptions>
                class options_parser<
                    nil::marshalling::option::sequence_ser_length_field_prefix<TField, TReadErrorStatus>,
                    TOptions...> : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_ser_length_field_prefix = true;
                    using sequence_ser_length_field_prefix_type = TField;
                    static const status_type sequence_ser_length_field_read_error_status
                        = TReadErrorStatus;
                };

                template<typename TField, status_type TReadErrorStatus, typename... TOptions>
                class options_parser<
                    nil::marshalling::option::sequence_elem_ser_length_field_prefix<TField, TReadErrorStatus>,
                    TOptions...> : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_elem_ser_length_field_prefix = true;
                    using sequence_elem_ser_length_field_prefix_type = TField;
                    static const status_type sequence_elem_ser_length_field_read_error_status
                        = TReadErrorStatus;
                };

                template<typename TField, status_type TReadErrorStatus, typename... TOptions>
                class options_parser<
                    nil::marshalling::option::sequence_elem_fixed_ser_length_field_prefix<TField, TReadErrorStatus>,
                    TOptions...> : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_elem_fixed_ser_length_field_prefix = true;
                    using sequence_elem_fixed_ser_length_field_prefix_type = TField;
                    static const status_type sequence_elem_fixed_ser_length_field_read_error_status
                        = TReadErrorStatus;
                };

                template<typename TTrailField, typename... TOptions>
                class options_parser<nil::marshalling::option::sequence_trailing_field_suffix<TTrailField>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_trailing_field_suffix = true;
                    using sequence_trailing_field_suffix = TTrailField;
                };

                template<typename TTermField, typename... TOptions>
                class options_parser<nil::marshalling::option::sequence_termination_field_suffix<TTermField>,
                                     TOptions...> : public options_parser<TOptions...> {
                public:
                    static const bool has_sequence_termination_field_suffix = true;
                    using sequence_termination_field_suffix = TTermField;
                };

                template<typename TInitialiser, typename... TOptions>
                class options_parser<nil::marshalling::option::default_value_initialiser<TInitialiser>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_default_value_initializer = true;
                    using default_value_initializer = TInitialiser;
                };

                template<typename TValidator, typename... TOptions>
                class options_parser<nil::marshalling::option::contents_validator<TValidator>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_custom_validator = true;
                    using custom_validator = TValidator;
                };

                template<typename TRefresher, typename... TOptions>
                class options_parser<nil::marshalling::option::contents_refresher<TRefresher>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_contents_refresher = true;
                    using custom_refresher = TRefresher;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::has_custom_refresh, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_custom_refresh = true;
                };

                template<status_type TStatus, typename... TOptions>
                class options_parser<nil::marshalling::option::fail_on_invalid<TStatus>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_fail_on_invalid = true;
                    static const status_type fail_on_invalid_status = TStatus;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::ignore_invalid, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_ignore_invalid = true;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::invalid_by_default, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_invalid_by_default = true;
                };

                template<std::size_t TSize, typename... TOptions>
                class options_parser<nil::marshalling::option::fixed_size_storage<TSize>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_fixed_size_storage = true;
                    static const std::size_t fixed_size_storage = TSize;
                };

                template<typename TType, typename... TOptions>
                class options_parser<nil::marshalling::option::custom_storage_type<TType>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_custom_storage_type = true;
                    using custom_storage_type = TType;
                };

                template<std::intmax_t TNum, std::intmax_t TDenom, typename... TOptions>
                class options_parser<nil::marshalling::option::scaling_ratio<TNum, TDenom>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_scaling_ratio = true;
                    using scaling_ratio_type = std::ratio<TNum, TDenom>;
                };

                template<typename TType, typename TRatio, typename... TOptions>
                class options_parser<nil::marshalling::option::units<TType, TRatio>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_units = true;
                    using units_type = TType;
                    using units_ratio = TRatio;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::orig_data_view, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_orig_data_view = true;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::empty_serialization, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_empty_serialization = true;
                };

                template<bool THasMultiRangeValidation>
                struct multi_range_assembler;

                template<>
                struct multi_range_assembler<false> {
                    template<typename TBase, typename T, T TMinValue, T TMaxValue>
                    using type = std::tuple<
                        std::tuple<std::integral_constant<T, TMinValue>, std::integral_constant<T, TMaxValue>>>;
                };

                template<>
                struct multi_range_assembler<true> {
                    using false_assembler_type = multi_range_assembler<false>;

                    template<typename TBase, typename T, T TMinValue, T TMaxValue>
                    using type = typename std::decay<decltype(std::tuple_cat(
                        std::declval<typename TBase::multi_range_validation_ranges>(),
                        std::declval<
                            typename false_assembler_type::template type<TBase, T, TMinValue, TMaxValue>>()))>::type;
                };

                template<typename TBase, typename T, T TMinValue, T TMaxValue>
                using multi_range_assembler_type = typename multi_range_assembler<
                    TBase::has_multi_range_validation>::template type<TBase, T, TMinValue, TMaxValue>;

                template<std::intmax_t TMinValue, std::intmax_t TMaxValue, typename... TOptions>
                class options_parser<nil::marshalling::option::valid_num_value_range<TMinValue, TMaxValue>, TOptions...>
                    : public options_parser<TOptions...> {
                    using base_impl_type = options_parser<TOptions...>;

                public:
#ifdef CC_COMPILER_GCC47
                    static_assert(
                        !base_impl_type::has_multi_range_validation,
                        "Sorry gcc-4.7 fails to compile valid C++11 code that allows multiple usage"
                        "of nil::marshalling::option::valid_num_value_range options. Either use it only once or"
                        "upgrade your compiler.");
#endif
                    using multi_range_validation_ranges
                        = multi_range_assembler_type<base_impl_type, std::intmax_t, TMinValue, TMaxValue>;
                    static const bool has_multi_range_validation = true;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::valid_ranges_clear, TOptions...>
                    : public options_parser<TOptions...> {
                    using base_impl_type = options_parser<TOptions...>;

                public:
                    using multi_range_validation_ranges = void;
                    static const bool has_multi_range_validation = false;
                };

                template<std::uintmax_t TMinValue, std::uintmax_t TMaxValue, typename... TOptions>
                class options_parser<nil::marshalling::option::valid_big_unsigned_num_value_range<TMinValue, TMaxValue>,
                                     TOptions...> : public options_parser<TOptions...> {
                    using base_impl_type = options_parser<TOptions...>;

                public:
#ifdef CC_COMPILER_GCC47
                    static_assert(
                        !base_impl_type::has_multi_range_validation,
                        "Sorry gcc-4.7 fails to compile valid C++11 code that allows multiple usage"
                        "of nil::marshalling::option::valid_num_value_range options. Either use it only once or"
                        "upgrade your compiler.");
#endif
                    using multi_range_validation_ranges
                        = multi_range_assembler_type<base_impl_type, std::uintmax_t, TMinValue, TMaxValue>;
                    static const bool has_multi_range_validation = true;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::has_custom_version_update, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_custom_version_update = true;
                };

                template<std::uintmax_t TFrom, std::uintmax_t TUntil, typename... TOptions>
                class options_parser<nil::marshalling::option::exists_between_versions<TFrom, TUntil>, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_versions_range = true;
                    static const std::uintmax_t exists_from_version = TFrom;
                    static const std::uintmax_t exists_until_version = TUntil;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::version_storage, TOptions...>
                    : public options_parser<TOptions...> {
                public:
                    static const bool has_version_storage = true;
                };

                template<typename... TOptions>
                class options_parser<nil::marshalling::option::empty_option, TOptions...>
                    : public options_parser<TOptions...> { };

                template<typename... TTupleOptions, typename... TOptions>
                class options_parser<std::tuple<TTupleOptions...>, TOptions...>
                    : public options_parser<TTupleOptions..., TOptions...> { };

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_OPTIONS_PARSER_HPP
