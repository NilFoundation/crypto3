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

#ifndef MARSHALLING_ADAPT_BASIC_FIELD_HPP
#define MARSHALLING_ADAPT_BASIC_FIELD_HPP

#include <nil/marshalling/types/adapter/custom_value_reader.hpp>
#include <nil/marshalling/types/adapter/ser_offset.hpp>
#include <nil/marshalling/types/adapter/fixed_length.hpp>
#include <nil/marshalling/types/adapter/fixed_bit_length.hpp>
#include <nil/marshalling/types/adapter/var_length.hpp>
#include <nil/marshalling/types/adapter/sequence_elem_length_forcing.hpp>
#include <nil/marshalling/types/adapter/sequence_size_forcing.hpp>
#include <nil/marshalling/types/adapter/sequence_length_forcing.hpp>
#include <nil/marshalling/types/adapter/sequence_fixed_size.hpp>
#include <nil/marshalling/types/adapter/sequence_size_field_prefix.hpp>
#include <nil/marshalling/types/adapter/sequence_ser_length_field_prefix.hpp>
#include <nil/marshalling/types/adapter/sequence_elem_ser_length_field_prefix.hpp>
#include <nil/marshalling/types/adapter/sequence_elem_fixed_ser_length_field_prefix.hpp>
#include <nil/marshalling/types/adapter/sequence_trailing_field_suffix.hpp>
#include <nil/marshalling/types/adapter/sequence_termination_field_suffix.hpp>
#include <nil/marshalling/types/adapter/default_value_initialiser.hpp>
#include <nil/marshalling/types/adapter/num_value_multi_range_validator.hpp>
#include <nil/marshalling/types/adapter/custom_validator.hpp>
#include <nil/marshalling/types/adapter/custom_refresher.hpp>
#include <nil/marshalling/types/adapter/fail_on_invalid.hpp>
#include <nil/marshalling/types/adapter/ignore_invalid.hpp>
#include <nil/marshalling/types/adapter/empty_serialization.hpp>
#include <nil/marshalling/types/adapter/exists_between_versions.hpp>
#include <nil/marshalling/types/adapter/invalid_by_default.hpp>
#include <nil/marshalling/types/adapter/version_storage.hpp>

#include <nil/marshalling/types/detail/options_parser.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<bool T1 = false,
                         bool T2 = false,
                         bool T3 = false,
                         bool T4 = false,
                         bool T5 = false,
                         bool T6 = false>
                struct fields_options_compatibility_calc {
                    static const std::size_t value = static_cast<std::size_t>(T1) + static_cast<std::size_t>(T2)
                                                     + static_cast<std::size_t>(T3) + static_cast<std::size_t>(T4)
                                                     + static_cast<std::size_t>(T5) + static_cast<std::size_t>(T6);
                };

                template<bool THasVersionStorage>
                struct adapt_field_version_storage;

                template<>
                struct adapt_field_version_storage<true> {
                    template<typename TField>
                    using type = types::adapter::version_storage<TField>;
                };

                template<>
                struct adapt_field_version_storage<false> {
                    template<typename TField>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_version_storage_type =
                    typename adapt_field_version_storage<TOpts::has_version_storage>::template type<TField>;

                template<bool THasInvalidByDefault>
                struct adapt_field_invalid_by_default;

                template<>
                struct adapt_field_invalid_by_default<true> {
                    template<typename TField>
                    using type = types::adapter::invalid_by_default<TField>;
                };

                template<>
                struct adapt_field_invalid_by_default<false> {
                    template<typename TField>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_invalid_by_default_type =
                    typename adapt_field_invalid_by_default<TOpts::has_invalid_by_default>::template type<TField>;

                template<bool THascustom_value_reader>
                struct adapt_field_custom_value_reader;

                template<>
                struct adapt_field_custom_value_reader<true> {
                    template<typename TField, typename TOpts>
                    using type
                        = types::adapter::custom_value_reader<typename TOpts::custom_value_reader,
                                                                                TField>;
                };

                template<>
                struct adapt_field_custom_value_reader<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_custom_value_reader_type =
                    typename adapt_field_custom_value_reader<TOpts::has_custom_value_reader>::template type<TField,
                                                                                                            TOpts>;

                template<bool THasSerOffset>
                struct adapt_field_ser_offset;

                template<>
                struct adapt_field_ser_offset<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::ser_offset<TOpts::ser_offset, TField>;
                };

                template<>
                struct adapt_field_ser_offset<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_ser_offset_type =
                    typename adapt_field_ser_offset<TOpts::has_ser_offset>::template type<TField, TOpts>;

                template<bool THasVersionsRange>
                struct adapt_field_versions_range;

                template<>
                struct adapt_field_versions_range<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::
                        exists_between_versions<TOpts::exists_from_version, TOpts::exists_until_version, TField>;
                };

                template<>
                struct adapt_field_versions_range<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_versions_range_type =
                    typename adapt_field_versions_range<TOpts::has_versions_range>::template type<TField, TOpts>;

                template<bool THasFixedLength>
                struct adapt_field_fixed_length;

                template<>
                struct adapt_field_fixed_length<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::
                        fixed_length<TOpts::fixed_length, TOpts::fixed_length_sign_extend, TField>;
                };

                template<>
                struct adapt_field_fixed_length<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_fixed_length_type =
                    typename adapt_field_fixed_length<TOpts::has_fixed_length_limit>::template type<TField, TOpts>;

                template<bool THasFixedBitLength>
                struct adapt_field_fixed_bit_length;

                template<>
                struct adapt_field_fixed_bit_length<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::fixed_bit_length<TOpts::fixed_bit_length, TField>;
                };

                template<>
                struct adapt_field_fixed_bit_length<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_fixed_bit_length_type =
                    typename adapt_field_fixed_bit_length<TOpts::has_fixed_bit_length_limit>::template type<TField,
                                                                                                            TOpts>;

                template<bool THasVarLengths>
                struct adapt_field_var_length;

                template<>
                struct adapt_field_var_length<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::
                        var_length<TOpts::min_var_length, TOpts::max_var_length, TField>;
                };

                template<>
                struct adapt_field_var_length<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_var_length_type =
                    typename adapt_field_var_length<TOpts::has_var_length_limits>::template type<TField, TOpts>;

                template<bool THasSequenceElemLengthForcing>
                struct adapt_field_sequence_elem_length_forcing;

                template<>
                struct adapt_field_sequence_elem_length_forcing<true> {
                    template<typename TField>
                    using type = types::adapter::sequence_elem_length_forcing<TField>;
                };

                template<>
                struct adapt_field_sequence_elem_length_forcing<false> {
                    template<typename TField>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_sequence_elem_length_forcing_type = typename adapt_field_sequence_elem_length_forcing<
                    TOpts::has_sequence_elem_length_forcing>::template type<TField>;

                template<bool THasSequenceSizeForcing>
                struct adapt_field_sequence_size_forcing;

                template<>
                struct adapt_field_sequence_size_forcing<true> {
                    template<typename TField>
                    using type = types::adapter::sequence_size_forcing<TField>;
                };

                template<>
                struct adapt_field_sequence_size_forcing<false> {
                    template<typename TField>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_sequence_size_forcing_type =
                    typename adapt_field_sequence_size_forcing<TOpts::has_sequence_size_forcing>::template type<TField>;

                template<bool THasSequenceLengthForcing>
                struct adapt_field_sequence_length_forcing;

                template<>
                struct adapt_field_sequence_length_forcing<true> {
                    template<typename TField>
                    using type = types::adapter::sequence_length_forcing<TField>;
                };

                template<>
                struct adapt_field_sequence_length_forcing<false> {
                    template<typename TField>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_sequence_length_forcing_type = typename adapt_field_sequence_length_forcing<
                    TOpts::has_sequence_length_forcing>::template type<TField>;

                template<bool THasSequenceFixedSize>
                struct adapt_field_sequence_fixed_size;

                template<>
                struct adapt_field_sequence_fixed_size<true> {
                    template<typename TField, typename TOpts>
                    using type
                        = types::adapter::sequence_fixed_size<TOpts::sequence_fixed_size, TField>;
                };

                template<>
                struct adapt_field_sequence_fixed_size<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_sequence_fixed_size_type =
                    typename adapt_field_sequence_fixed_size<TOpts::has_sequence_fixed_size>::template type<TField,
                                                                                                            TOpts>;

                template<bool THasSequenceSizeFieldPrefix>
                struct adapt_field_sequence_size_field_prefix;

                template<>
                struct adapt_field_sequence_size_field_prefix<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::
                        sequence_size_field_prefix<typename TOpts::sequence_size_field_prefix_type, TField>;
                };

                template<>
                struct adapt_field_sequence_size_field_prefix<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_sequence_size_field_prefix_type = typename adapt_field_sequence_size_field_prefix<
                    TOpts::has_sequence_size_field_prefix>::template type<TField, TOpts>;

                //--
                template<bool THasSequenceSerLengthFieldPrefix>
                struct adapt_field_sequence_ser_length_field_prefix;

                template<>
                struct adapt_field_sequence_ser_length_field_prefix<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::sequence_ser_length_field_prefix<
                        typename TOpts::sequence_ser_length_field_prefix_type,
                        TOpts::sequence_ser_length_field_read_error_status,
                        TField>;
                };

                template<>
                struct adapt_field_sequence_ser_length_field_prefix<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_sequence_ser_length_field_prefix_type =
                    typename adapt_field_sequence_ser_length_field_prefix<
                        TOpts::has_sequence_ser_length_field_prefix>::template type<TField, TOpts>;

                //--

                template<bool THasSequenceElemSerLengthFieldPrefix>
                struct adapt_field_sequence_elem_ser_length_field_prefix;

                template<>
                struct adapt_field_sequence_elem_ser_length_field_prefix<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::sequence_elem_ser_length_field_prefix<
                        typename TOpts::sequence_elem_ser_length_field_prefix_type,
                        TOpts::sequence_elem_ser_length_field_read_error_status,
                        TField>;
                };

                template<>
                struct adapt_field_sequence_elem_ser_length_field_prefix<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_sequence_elem_ser_length_field_prefix_type =
                    typename adapt_field_sequence_elem_ser_length_field_prefix<
                        TOpts::has_sequence_elem_ser_length_field_prefix>::template type<TField, TOpts>;

                //--

                template<bool THasSequenceElemFixedSerLengthFieldPrefix>
                struct adapt_field_sequence_elem_fixed_ser_length_field_prefix;

                template<>
                struct adapt_field_sequence_elem_fixed_ser_length_field_prefix<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::sequence_elem_fixed_ser_length_field_prefix<
                        typename TOpts::sequence_elem_fixed_ser_length_field_prefix_type,
                        TOpts::sequence_elem_fixed_ser_length_field_read_error_status,
                        TField>;
                };

                template<>
                struct adapt_field_sequence_elem_fixed_ser_length_field_prefix<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_sequence_elem_fixed_ser_length_field_prefix_type =
                    typename adapt_field_sequence_elem_fixed_ser_length_field_prefix<
                        TOpts::has_sequence_elem_fixed_ser_length_field_prefix>::template type<TField, TOpts>;

                //--

                template<bool THasSequenceTrailingFieldSuffix>
                struct adapt_field_sequence_trailing_field_suffix;

                template<>
                struct adapt_field_sequence_trailing_field_suffix<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::
                        sequence_trailing_field_suffix<typename TOpts::sequence_trailing_field_suffix, TField>;
                };

                template<>
                struct adapt_field_sequence_trailing_field_suffix<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_sequence_trailing_field_suffix_type =
                    typename adapt_field_sequence_trailing_field_suffix<
                        TOpts::has_sequence_trailing_field_suffix>::template type<TField, TOpts>;

                template<bool THasSequenceTerminationFieldSuffix>
                struct adapt_field_sequence_termination_field_suffix;

                template<>
                struct adapt_field_sequence_termination_field_suffix<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::
                        sequence_termination_field_suffix<typename TOpts::sequence_termination_field_suffix, TField>;
                };

                template<>
                struct adapt_field_sequence_termination_field_suffix<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_sequence_termination_field_suffix_type =
                    typename adapt_field_sequence_termination_field_suffix<
                        TOpts::has_sequence_termination_field_suffix>::template type<TField, TOpts>;

                template<bool THasDefaultValueInitialiser>
                struct adapt_field_default_value_initialiser;

                template<>
                struct adapt_field_default_value_initialiser<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::
                        default_value_initialiser<typename TOpts::default_value_initializer, TField>;
                };

                template<>
                struct adapt_field_default_value_initialiser<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_default_value_initialiser_type = typename adapt_field_default_value_initialiser<
                    TOpts::has_default_value_initializer>::template type<TField, TOpts>;

                template<bool THasMultiRangeValidation>
                struct adapt_field_num_value_multi_range_validator;

                template<>
                struct adapt_field_num_value_multi_range_validator<true> {
                    template<typename TField, typename TOpts>
                    using type = types::adapter::
                        num_value_multi_range_validator<typename TOpts::multi_range_validation_ranges, TField>;
                };

                template<>
                struct adapt_field_num_value_multi_range_validator<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_num_value_multi_range_validator_type =
                    typename adapt_field_num_value_multi_range_validator<
                        TOpts::has_multi_range_validation>::template type<TField, TOpts>;

                template<bool THasCustomValidator>
                struct adapt_field_custom_validator;

                template<>
                struct adapt_field_custom_validator<true> {
                    template<typename TField, typename TOpts>
                    using type
                        = types::adapter::custom_validator<typename TOpts::custom_validator, TField>;
                };

                template<>
                struct adapt_field_custom_validator<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_custom_validator_type =
                    typename adapt_field_custom_validator<TOpts::has_custom_validator>::template type<TField, TOpts>;

                template<bool THasContentsRefresher>
                struct adapt_field_custom_refresher;

                template<>
                struct adapt_field_custom_refresher<true> {
                    template<typename TField, typename TOpts>
                    using type
                        = types::adapter::custom_refresher<typename TOpts::custom_refresher, TField>;
                };

                template<>
                struct adapt_field_custom_refresher<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_custom_refresher_type =
                    typename adapt_field_custom_refresher<TOpts::has_contents_refresher>::template type<TField, TOpts>;

                template<bool THasFailOnInvalid>
                struct adapt_field_fail_on_invalid;

                template<>
                struct adapt_field_fail_on_invalid<true> {
                    template<typename TField, typename TOpts>
                    using type
                        = types::adapter::fail_on_invalid<TOpts::fail_on_invalid_status, TField>;
                };

                template<>
                struct adapt_field_fail_on_invalid<false> {
                    template<typename TField, typename TOpts>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_fail_on_invalid_type =
                    typename adapt_field_fail_on_invalid<TOpts::has_fail_on_invalid>::template type<TField, TOpts>;

                template<bool THasIgnoreInvalid>
                struct adapt_field_ignore_invalid;

                template<>
                struct adapt_field_ignore_invalid<true> {
                    template<typename TField>
                    using type = types::adapter::ignore_invalid<TField>;
                };

                template<>
                struct adapt_field_ignore_invalid<false> {
                    template<typename TField>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_ignore_invalid_type =
                    typename adapt_field_ignore_invalid<TOpts::has_ignore_invalid>::template type<TField>;

                template<bool THasEmptySerialization>
                struct adapt_field_empty_serialization;

                template<>
                struct adapt_field_empty_serialization<true> {
                    template<typename TField>
                    using type = types::adapter::empty_serialization<TField>;
                };

                template<>
                struct adapt_field_empty_serialization<false> {
                    template<typename TField>
                    using type = TField;
                };

                template<typename TField, typename TOpts>
                using adapt_field_empty_serialization_type =
                    typename adapt_field_empty_serialization<TOpts::has_empty_serialization>::template type<TField>;

                template<typename TBasic, typename... TOptions>
                class adapt_basic_field {
                    using parsed_options_type = options_parser<TOptions...>;

                    static const bool custom_reader_incompatible
                        = parsed_options_type::has_ser_offset || parsed_options_type::has_fixed_length_limit
                          || parsed_options_type::has_fixed_bit_length_limit
                          || parsed_options_type::has_var_length_limits
                          || parsed_options_type::has_sequence_elem_length_forcing
                          || parsed_options_type::has_sequence_size_forcing
                          || parsed_options_type::has_sequence_length_forcing
                          || parsed_options_type::has_sequence_fixed_size
                          || parsed_options_type::has_sequence_size_field_prefix
                          || parsed_options_type::has_sequence_ser_length_field_prefix
                          || parsed_options_type::has_sequence_elem_ser_length_field_prefix
                          || parsed_options_type::has_sequence_elem_fixed_ser_length_field_prefix
                          || parsed_options_type::has_sequence_trailing_field_suffix
                          || parsed_options_type::has_sequence_termination_field_suffix
                                 | parsed_options_type::has_empty_serialization;

                    static_assert((!parsed_options_type::has_custom_value_reader) || (!custom_reader_incompatible),
                                  "custom_value_reader option is incompatible with following options: "
                                  "num_value_ser_offset, fixed_length, fixed_bit_length, var_length, "
                                  "has_sequence_elem_length_forcing, "
                                  "SequenceSizeForcingEnabled, SequenceLengthForcingEnabled, sequence_fixed_size, "
                                  "sequence_size_field_prefix, "
                                  "sequence_ser_length_field_prefix, sequence_elem_ser_length_field_prefix, "
                                  "sequence_elem_fixed_ser_length_field_prefix, sequence_trailing_field_suffix, "
                                  "sequence_termination_field_suffix, empty_serialization");

                    static const bool var_length_incompatible = parsed_options_type::has_fixed_length_limit
                                                                || parsed_options_type::has_fixed_bit_length_limit;

                    static_assert((!parsed_options_type::has_var_length_limits) || (!var_length_incompatible),
                                  "var_length option is incompatible with fixed_length and fixed_bit_length");

                    static_assert(1U >= fields_options_compatibility_calc<
                                      parsed_options_type::has_sequence_size_field_prefix,
                                      parsed_options_type::has_sequence_ser_length_field_prefix,
                                      parsed_options_type::has_sequence_fixed_size,
                                      parsed_options_type::has_sequence_size_forcing,
                                      parsed_options_type::has_sequence_length_forcing,
                                      parsed_options_type::has_sequence_termination_field_suffix>::value,
                                  "The following options are incompatible, cannot be used together: "
                                  "sequence_size_field_prefix, sequence_ser_length_field_prefix, "
                                  "sequence_fixed_size, SequenceSizeForcingEnabled, SequenceLengthForcingEnabled, "
                                  "sequence_termination_field_suffix");

                    static_assert(1U >= fields_options_compatibility_calc<
                                      parsed_options_type::has_sequence_elem_ser_length_field_prefix,
                                      parsed_options_type::has_sequence_elem_fixed_ser_length_field_prefix,
                                      parsed_options_type::has_sequence_termination_field_suffix>::value,
                                  "The following options are incompatible, cannot be used together: "
                                  "sequence_elem_ser_length_field_prefix, sequence_elem_fixed_ser_length_field_prefix "
                                  "sequence_termination_field_suffix");

                    static_assert((!parsed_options_type::has_sequence_trailing_field_suffix)
                                      || (!parsed_options_type::has_sequence_termination_field_suffix),
                                  "The following options are incompatible, cannot be used together: "
                                  "sequence_trailing_field_suffix, sequence_termination_field_suffix");

                    static_assert((!parsed_options_type::has_fail_on_invalid)
                                      || (!parsed_options_type::has_ignore_invalid),
                                  "The following options are incompatible, cannot be used together: "
                                  "fail_on_invalid, ignore_invalid");

                    static_assert(
                        1U >= fields_options_compatibility_calc<parsed_options_type::has_custom_value_reader,
                                                                parsed_options_type::has_fixed_size_storage,
                                                                parsed_options_type::has_orig_data_view>::value,
                        "The following options are incompatible, cannot be used together: "
                        "custom_storage_type, fixed_size_storage, orig_data_view");

                    static_assert(
                        (!parsed_options_type::has_sequence_fixed_size_use_fixed_size_storage)
                            || (parsed_options_type::has_sequence_fixed_size),
                        "The option SequenceFixedSizeUseFixedSizeStorage cannot be used without sequence_fixed_size.");

                    static_assert((!parsed_options_type::has_sequence_fixed_size_use_fixed_size_storage)
                                      || (!parsed_options_type::has_fixed_size_storage),
                                  "The following options are incompatible, cannot be used together: "
                                  "SequenceFixedSizeUseFixedSizeStorage, fixed_size_storage");

                    using invalid_by_default_adapted = adapt_field_invalid_by_default_type<TBasic, parsed_options_type>;
                    using version_storage_adapted
                        = adapt_field_version_storage_type<invalid_by_default_adapted, parsed_options_type>;
                    using custom_reader_adapted
                        = adapt_field_custom_value_reader_type<version_storage_adapted, parsed_options_type>;
                    using ser_offset_adapted = adapt_field_ser_offset_type<custom_reader_adapted, parsed_options_type>;
                    using versions_range_adapted
                        = adapt_field_versions_range_type<ser_offset_adapted, parsed_options_type>;
                    using fixed_length_adapted
                        = adapt_field_fixed_length_type<versions_range_adapted, parsed_options_type>;
                    using fixed_bit_length_adapted
                        = adapt_field_fixed_bit_length_type<fixed_length_adapted, parsed_options_type>;
                    using var_length_adapted
                        = adapt_field_var_length_type<fixed_bit_length_adapted, parsed_options_type>;
                    using sequence_elem_length_forcing_adapted
                        = adapt_field_sequence_elem_length_forcing_type<var_length_adapted, parsed_options_type>;
                    using sequence_elem_ser_length_field_prefix_adapted
                        = adapt_field_sequence_elem_ser_length_field_prefix_type<sequence_elem_length_forcing_adapted,
                                                                                 parsed_options_type>;
                    using sequence_elem_fixed_ser_length_field_prefix_adapted
                        = adapt_field_sequence_elem_fixed_ser_length_field_prefix_type<
                            sequence_elem_ser_length_field_prefix_adapted,
                            parsed_options_type>;
                    using sequence_size_forcing_adapted
                        = adapt_field_sequence_size_forcing_type<sequence_elem_fixed_ser_length_field_prefix_adapted,
                                                                 parsed_options_type>;
                    using sequence_length_forcing_adapted
                        = adapt_field_sequence_length_forcing_type<sequence_size_forcing_adapted, parsed_options_type>;
                    using sequence_fixed_size_adapted
                        = adapt_field_sequence_fixed_size_type<sequence_length_forcing_adapted, parsed_options_type>;
                    using sequence_size_field_prefix_adapted
                        = adapt_field_sequence_size_field_prefix_type<sequence_fixed_size_adapted, parsed_options_type>;
                    using sequence_ser_length_field_prefix_adapted
                        = adapt_field_sequence_ser_length_field_prefix_type<sequence_size_field_prefix_adapted,
                                                                            parsed_options_type>;
                    using sequence_trailing_field_suffix_adapted
                        = adapt_field_sequence_trailing_field_suffix_type<sequence_ser_length_field_prefix_adapted,
                                                                          parsed_options_type>;
                    using sequence_termination_field_suffix_adapted
                        = adapt_field_sequence_termination_field_suffix_type<sequence_trailing_field_suffix_adapted,
                                                                             parsed_options_type>;
                    using default_value_initialiser_adapted
                        = adapt_field_default_value_initialiser_type<sequence_termination_field_suffix_adapted,
                                                                     parsed_options_type>;
                    using num_value_multi_range_validator_adapted
                        = adapt_field_num_value_multi_range_validator_type<default_value_initialiser_adapted,
                                                                           parsed_options_type>;
                    using custom_validator_adapted
                        = adapt_field_custom_validator_type<num_value_multi_range_validator_adapted,
                                                            parsed_options_type>;
                    using custom_refresher_adapted
                        = adapt_field_custom_refresher_type<custom_validator_adapted, parsed_options_type>;
                    using fail_on_invalid_adapted
                        = adapt_field_fail_on_invalid_type<custom_refresher_adapted, parsed_options_type>;
                    using ignore_invalid_adapted
                        = adapt_field_ignore_invalid_type<fail_on_invalid_adapted, parsed_options_type>;
                    using empty_serialization_adapted
                        = adapt_field_empty_serialization_type<ignore_invalid_adapted, parsed_options_type>;

                public:
                    using type = empty_serialization_adapted;
                };

                template<typename TBasic, typename... TOptions>
                using adapt_basic_field_type = typename adapt_basic_field<TBasic, TOptions...>::type;

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_ADAPT_BASIC_FIELD_HPP
