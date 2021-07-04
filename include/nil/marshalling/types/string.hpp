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

#ifndef MARSHALLING_STRING_HPP
#define MARSHALLING_STRING_HPP

#include <vector>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/types/string/behaviour.hpp>
#include <nil/marshalling/types/detail/options_parser.hpp>

#include <nil/marshalling/types/tag.hpp>

namespace nil {
    namespace marshalling {
        namespace types {

            /// @brief field_type that represents a string.
            /// @details By default uses
            ///     <a href="http://en.cppreference.com/w/cpp/string/basic_string">std::string</a>,
            ///     for internal storage, unless nil::marshalling::option::fixed_size_storage option is used,
            ///     which forces usage of nil::marshalling::container::static_string instead.
            /// @tparam TFieldBase Base class for this field, expected to be a variant of
            ///     nil::marshalling::field_type.
            /// @tparam TOptions Zero or more options that modify/refine default behaviour
            ///     of the field.@n
            ///     Supported options are:
            ///     @li @ref nil::marshalling::option::fixed_size_storage
            ///     @li @ref nil::marshalling::option::custom_storage_type
            ///     @li @ref nil::marshalling::option::sequence_size_field_prefix_type
            ///     @li @ref nil::marshalling::option::sequence_ser_length_field_prefix_type
            ///     @li @ref nil::marshalling::option::SequenceSizeForcingEnabled
            ///     @li @ref nil::marshalling::option::SequenceLengthForcingEnabled
            ///     @li @ref nil::marshalling::option::sequence_fixed_size
            ///     @li @ref nil::marshalling::option::sequence_termination_field_suffix
            ///     @li @ref nil::marshalling::option::sequence_trailing_field_suffix
            ///     @li @ref nil::marshalling::option::default_value_initializer
            ///     @li @ref nil::marshalling::option::contents_validator
            ///     @li @ref nil::marshalling::option::contents_refresher
            ///     @li @ref nil::marshalling::option::has_custom_read
            ///     @li @ref nil::marshalling::option::has_custom_refresh
            ///     @li @ref nil::marshalling::option::fail_on_invalid
            ///     @li @ref nil::marshalling::option::ignore_invalid
            ///     @li @ref nil::marshalling::option::OrigDataView
            ///     @li @ref nil::marshalling::option::empty_serialization
            ///     @li @ref nil::marshalling::option::invalid_by_default
            ///     @li @ref nil::marshalling::option::version_storage
            /// @extends nil::marshalling::field_type
            /// @headerfile nil/marshalling/types/string.hpp
            template<typename TFieldBase, typename... TOptions>
            class string : private detail::string_base_type<TFieldBase, TOptions...> {
                using base_impl_type = detail::string_base_type<TFieldBase, TOptions...>;

            public:
                /// @brief endian_type used for serialization.
                using endian_type = typename base_impl_type::endian_type;

                /// @brief Version type
                using version_type = typename base_impl_type::version_type;

                /// @brief All the options provided to this class bundled into struct.
                using parsed_options_type = detail::options_parser<TOptions...>;

                /// @brief Tag indicating type of the field
                using tag = tag::string;

                /// @brief Type of underlying value.
                /// @details If nil::marshalling::option::fixed_size_storage option is NOT used, the
                ///     value_type is std::string, otherwise it becomes
                ///     nil::marshalling::container::static_string<TSize>, where TSize is a size
                ///     provided to nil::marshalling::option::fixed_size_storage option.
                using value_type = typename base_impl_type::value_type;

                /// @brief Default constructor
                string() = default;

                /// @brief Constructor
                explicit string(const value_type &val) : base_impl_type(val) {
                }

                /// @brief Constructor
                explicit string(value_type &&val) : base_impl_type(std::move(val)) {
                }

                /// @brief Constructor
                explicit string(const char *str) {
                    base_impl_type::value() = str;
                }

                /// @brief Copy constructor
                string(const string &) = default;

                /// @brief Move constructor
                string(string &&) = default;

                /// @brief Destructor
                ~string() noexcept = default;

                /// @brief Copy assignment
                string &operator=(const string &) = default;

                /// @brief Move assignment
                string &operator=(string &&) = default;

                /// @brief Read field value from input data sequence
                /// @details By default, the read operation will try to consume all the
                ///     data available, unless size limiting option (such as
                ///     nil::marshalling::option::sequence_size_field_prefix_type,
                ///     nil::marshalling::option::sequence_fixed_size,
                ///     nil::marshalling::option::SequenceSizeForcingEnabled,
                ///     nil::marshalling::option::SequenceLengthForcingEnabled) is used.
                /// @param[in, out] iter Iterator to read the data.
                /// @param[in] len Number of bytes available for reading.
                /// @return Status of read operation.
                /// @post Iterator is advanced.
                template<typename TIter>
                status_type read(TIter &iter, std::size_t len) {
                    status_type es = base_impl_type::read(iter, len);
                    using TagTmp = typename std::conditional<parsed_options_type::has_sequence_fixed_size,
                                                             adjustment_needed_tag,
                                                             no_adjustment_tag>::type;

                    adjust_value(TagTmp());
                    return es;
                }

                /// @brief Read field value from input data sequence without error check and status report.
                /// @details Similar to @ref read(), but doesn't perform any correctness
                ///     checks and doesn't report any failures.
                /// @param[in, out] iter Iterator to read the data.
                /// @post Iterator is advanced.
                template<typename TIter>
                void read_no_status(TIter &iter) {
                    base_impl_type::read_no_status(iter);
                    using TagTmp = typename std::conditional<parsed_options_type::has_sequence_fixed_size,
                                                             adjustment_needed_tag,
                                                             no_adjustment_tag>::type;

                    adjust_value(TagTmp());
                }

                /// @brief Get access to the value storage.
                value_type &value() {
                    return base_impl_type::value();
                }

                /// @brief Get access to the value storage.
                const value_type &value() const {
                    return base_impl_type::value();
                }

                /// @brief Get length of serialized data
                std::size_t length() const {
                    return base_impl_type::length();
                }

                /// @brief Check validity of the field value.
                bool valid() const {
                    return base_impl_type::valid();
                }

                /// @brief Refresh the field's value
                /// @return @b true if the value has been updated, @b false otherwise
                bool refresh() {
                    return base_impl_type::refresh();
                }

                /// @brief Write current field value to output data sequence
                /// @details By default, the write operation will write all the
                ///     characters the field contains. If nil::marshalling::option::sequence_fixed_size option
                ///     is used, the number of characters, that is going to be written, is
                ///     exactly as the option specifies. If underlying string storage
                ///     doesn't contain enough data, the '\0' characters will
                ///     be appended to the written sequence until the required amount of
                ///     elements is reached.
                /// @param[in, out] iter Iterator to write the data.
                /// @param[in] len Maximal number of bytes that can be written.
                /// @return Status of write operation.
                /// @post Iterator is advanced.
                template<typename TIter>
                status_type write(TIter &iter, std::size_t len) const {
                    return base_impl_type::write(iter, len);
                }

                /// @brief Write current field value to output data sequence  without error check and status report.
                /// @details Similar to @ref write(), but doesn't perform any correctness
                ///     checks and doesn't report any failures.
                /// @param[in, out] iter Iterator to write the data.
                /// @post Iterator is advanced.
                template<typename TIter>
                void write_no_status(TIter &iter) const {
                    base_impl_type::write_no_status(iter);
                }

                /// @brief Get minimal length that is required to serialise field of this type.
                static constexpr std::size_t min_length() {
                    return base_impl_type::min_length();
                }

                /// @brief Get maximal length that is required to serialise field of this type.
                static constexpr std::size_t max_length() {
                    return base_impl_type::max_length();
                }

                /// @brief Force number of characters that must be read in the next read()
                ///     invocation.
                /// @details Exists only if nil::marshalling::option::SequenceSizeForcingEnabled option has been
                ///     used.
                /// @param[in] count Number of elements to read during following read operation.
                void force_read_elem_count(std::size_t count) {
                    base_impl_type::force_read_elem_count(count);
                }

                /// @brief Clear forcing of the number of characters that must be read in
                ///     the next read() invocation.
                /// @details Exists only if nil::marshalling::option::SequenceSizeForcingEnabled option has been
                ///     used.
                void clear_read_elem_count() {
                    base_impl_type::clear_read_elem_count();
                }

                /// @brief Force available length for the next read() invocation.
                /// @details Exists only if @ref nil::marshalling::option::SequenceLengthForcingEnabled option has been
                ///     used.
                /// @param[in] count Number of elements to read during following read operation.
                void force_read_length(std::size_t count) {
                    return base_impl_type::force_read_length(count);
                }

                /// @brief Clear forcing of the available length in the next read()
                ///     invocation.
                /// @details Exists only if @ref nil::marshalling::option::SequenceLengthForcingEnabled option has been
                ///     used.
                void clear_read_length_forcing() {
                    return base_impl_type::clear_read_length_forcing();
                }

                /// @brief Compile time check if this class is version dependent
                static constexpr bool is_version_dependent() {
                    return parsed_options_type::has_custom_version_update || base_impl_type::is_version_dependent();
                }

                /// @brief Get version of the field.
                /// @details Exists only if @ref nil::marshalling::option::version_storage option has been provided.
                version_type get_version() const {
                    return base_impl_type::get_version();
                }

                /// @brief Default implementation of version update.
                /// @return @b true in case the field contents have changed, @b false otherwise
                bool set_version(version_type version) {
                    return base_impl_type::set_version(version);
                }

            protected:
                using base_impl_type::read_data;
                using base_impl_type::write_data;

            private:
                struct no_adjustment_tag { };
                struct adjustment_needed_tag { };
                struct has_resize_tag { };
                struct has_remove_suffix_tag { };

                void adjust_value(no_adjustment_tag) {
                }

                void adjust_value(adjustment_needed_tag) {
                    std::size_t count = 0;
                    for (auto iter = base_impl_type::value().begin(); iter != base_impl_type::value().end(); ++iter) {
                        if (*iter == 0) {
                            break;
                        }
                        ++count;
                    }

                    eval_resize(count);
                }

                void eval_resize(std::size_t count) {
                    using TagTmp = typename std::conditional<
                        has_member_function_resize<value_type>::value,
                        has_resize_tag,
                        typename std::conditional<has_member_function_remove_suffix<value_type>::value,
                                                  has_remove_suffix_tag,
                                                  void>::type>::type;

                    static_assert(!std::is_void<tag>::value,
                                  "The string storage value type must have either resize() or remove_suffix() "
                                  "member functions");
                    eval_resize(count, TagTmp());
                }

                void eval_resize(std::size_t count, has_resize_tag) {
                    base_impl_type::value().resize(count);
                }

                void eval_resize(std::size_t count, has_remove_suffix_tag) {
                    base_impl_type::value().remove_suffix(base_impl_type::value().size() - count);
                }

                static_assert(
                    !parsed_options_type::has_ser_offset,
                    "nil::marshalling::option::num_value_ser_offset option is not applicable to string field");
                static_assert(!parsed_options_type::has_fixed_length_limit,
                              "nil::marshalling::option::fixed_length option is not applicable to string field");
                static_assert(!parsed_options_type::has_fixed_bit_length_limit,
                              "nil::marshalling::option::fixed_bit_length option is not applicable to string field");
                static_assert(!parsed_options_type::has_var_length_limits,
                              "nil::marshalling::option::var_length option is not applicable to string field");
                static_assert(!parsed_options_type::has_scaling_ratio,
                              "nil::marshalling::option::scaling_ratio_type option is not applicable to string field");
                static_assert(!parsed_options_type::has_units,
                              "nil::marshalling::option::Units option is not applicable to string field");
                static_assert(!parsed_options_type::has_multi_range_validation,
                              "nil::marshalling::option::valid_num_value_range (or similar) option is not applicable "
                              "to string field");
                static_assert(!parsed_options_type::has_sequence_elem_ser_length_field_prefix,
                              "nil::marshalling::option::sequence_elem_ser_length_field_prefix option is not "
                              "applicable to string field");
                static_assert(!parsed_options_type::has_sequence_elem_fixed_ser_length_field_prefix,
                              "nil::marshalling::option::SequenceElemSerLengthFixedFieldPrefix option is not "
                              "applicable to string field");
                static_assert(!parsed_options_type::has_versions_range,
                              "nil::marshalling::option::exists_between_versions (or similar) option is not applicable "
                              "to string field");
            };

            /// @brief Equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are equal, false otherwise.
            /// @related string
            template<typename TFieldBase, typename... TOptions>
            bool operator==(const string<TFieldBase, TOptions...> &field1,
                            const string<TFieldBase, TOptions...> &field2) {
                return field1.value() == field2.value();
            }

            /// @brief Non-equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are NOT equal, false otherwise.
            /// @related string
            template<typename TFieldBase, typename... TOptions>
            bool operator!=(const string<TFieldBase, TOptions...> &field1,
                            const string<TFieldBase, TOptions...> &field2) {
                return field1.value() != field2.value();
            }

            /// @brief Equivalence comparison operator.
            /// @details Performs lexicographical compare of two string values.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case first field is less than second field.
            /// @related string
            template<typename TFieldBase, typename... TOptions>
            bool operator<(const string<TFieldBase, TOptions...> &field1,
                           const string<TFieldBase, TOptions...> &field2) {
                return field1.value() < field2.value();
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::string type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::string
            template<typename TFieldBase, typename... TOptions>
            inline string<TFieldBase, TOptions...> &to_field_base(string<TFieldBase, TOptions...> &field) {
                return field;
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::string type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::string
            template<typename TFieldBase, typename... TOptions>
            inline const string<TFieldBase, TOptions...> &to_field_base(const string<TFieldBase, TOptions...> &field) {
                return field;
            }

        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_STRING_HPP
