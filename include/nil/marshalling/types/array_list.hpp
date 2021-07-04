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

#ifndef MARSHALLING_ARRAY_LIST_HPP
#define MARSHALLING_ARRAY_LIST_HPP

#include <vector>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/types/array_list/behaviour.hpp>
#include <nil/marshalling/types/detail/options_parser.hpp>

#include <nil/marshalling/types/tag.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            /// @brief field_type that represents a sequential collection of fields.
            /// @details By default uses
            ///     <a href="http://en.cppreference.com/w/cpp/container/vector">std::vector</a>,
            ///     for internal storage, unless nil::marshalling::option::fixed_size_storage option is used,
            ///     which forces usage of nil::marshalling::container::static_vector instead.
            /// @tparam TFieldBase Base class for this field, expected to be a variant of
            ///     nil::marshalling::field_type.
            /// @tparam TElement Element of the collection, can be either basic integral value
            ///     (such as std::uint8_t) or any other field from nil::marshalling::types namespace.@n
            ///     For example:
            ///     @code
            ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///     using RawDataSeqField =
            ///         nil::marshalling::types::array_list<
            ///             MyFieldBase,
            ///             std::uint8_t
            ///         >;
            ///     using CollectionOfBundlesField =
            ///         nil::marshalling::types::array_list<
            ///             MyFieldBase,
            ///             std::types::bundle<
            ///                 MyFieldBase,
            ///                 std::tuple<
            ///                     nil::marshalling::types::integral<MyFieldBase, std::uint16_t>
            ///                     nil::marshalling::types::integral<MyFieldBase, std::uint8_t>
            ///                     nil::marshalling::types::integral<MyFieldBase, std::uint8_t>
            ///                 >
            ///             >
            ///         >;
            ///     @endcode
            /// @tparam TOptions Zero or more options that modify/refine default behaviour
            ///     of the field.@n
            ///     Supported options are:
            ///     @li @ref nil::marshalling::option::fixed_size_storage
            ///     @li @ref nil::marshalling::option::custom_storage_type
            ///     @li @ref nil::marshalling::option::sequence_size_field_prefix_type
            ///     @li @ref nil::marshalling::option::sequence_ser_length_field_prefix_type
            ///     @li @ref nil::marshalling::option::sequence_elem_ser_length_field_prefix_type
            ///     @li @ref nil::marshalling::option::sequence_elem_fixed_ser_length_field_prefix_type
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
            ///     @li @ref nil::marshalling::option::OrigDataView (valid only if TElement is integral type
            ///         of 1 byte size.
            ///     @li @ref nil::marshalling::option::empty_serialization
            ///     @li @ref nil::marshalling::option::version_storage
            /// @extends nil::marshalling::field_type
            /// @headerfile nil/marshalling/types/array_list.hpp
            template<typename TFieldBase, typename TElement, typename... TOptions>
            class array_list : private detail::array_list_base_type<TFieldBase, TElement, TOptions...> {
                using base_impl_type = detail::array_list_base_type<TFieldBase, TElement, TOptions...>;

            public:
                /// @brief endian_type used for serialization.
                using endian_type = typename base_impl_type::endian_type;

                /// @brief Version type
                using version_type = typename base_impl_type::version_type;

                /// @brief All the options provided to this class bundled into struct.
                using parsed_options_type = detail::options_parser<TOptions...>;

                /// @brief Tag indicating type of the field
                using tag = typename std::conditional<std::is_integral<TElement>::value, tag::raw_array_list,
                                                      tag::array_list>::type;

                /// @brief Type of underlying value.
                /// @details If nil::marshalling::option::fixed_size_storage option is NOT used, the
                ///     value_type is std::vector<TElement>, otherwise it becomes
                ///     nil::marshalling::container::static_vector<TElement, TSize>, where TSize is a size
                ///     provided to nil::marshalling::option::fixed_size_storage option.
                using value_type = typename base_impl_type::value_type;

                /// @brief Type of the element.
                using element_type = typename base_impl_type::element_type;

                /// @brief Default constructor
                array_list() = default;

                /// @brief Value constructor
                explicit array_list(const value_type &val) : base_impl_type(val) {
                }

                /// @brief Value constructor
                explicit array_list(value_type &&val) : base_impl_type(std::move(val)) {
                }

                /// @brief Copy constructor
                array_list(const array_list &) = default;

                /// @brief Move constructor
                array_list(array_list &&) = default;

                /// @brief Destructor
                ~array_list() noexcept = default;

                /// @brief Copy assignment
                array_list &operator=(const array_list &) = default;

                /// @brief Move assignment
                array_list &operator=(array_list &&) = default;

                /// @brief Get access to the value storage.
                value_type &value() {
                    return base_impl_type::value();
                }

                /// @brief Get access to the value storage.
                const value_type &value() const {
                    return base_impl_type::value();
                }

                /// @brief Get length of serialized data
                constexpr std::size_t length() const {
                    return base_impl_type::length();
                }

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
                    return base_impl_type::read(iter, len);
                }

                /// @brief Read field value from input data sequence without error check and status report.
                /// @details Similar to @ref read(), but doesn't perform any correctness
                ///     checks and doesn't report any failures.
                /// @param[in, out] iter Iterator to read the data.
                /// @post Iterator is advanced.
                template<typename TIter>
                void read_no_status(TIter &iter) {
                    base_impl_type::read_no_status(iter);
                }

                /// @brief Write current field value to output data sequence
                /// @details By default, the write operation will write all the
                ///     elements the field contains. If nil::marshalling::option::sequence_fixed_size option
                ///     is used, the number of elements, that is going to be written, is
                ///     exactly as the option specifies. If underlying vector storage
                ///     doesn't contain enough data, the default constructed elements will
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

                /// @brief Check validity of the field value.
                /// @details The collection is valid if all the elements are valid. In case
                ///     nil::marshalling::option::contents_validator option is used, the validator,
                ///     it provides, is invoked IN ADDITION to the validation of the elements.
                /// @return true in case the field's value is valid, false otherwise.
                bool valid() const {
                    return base_impl_type::valid();
                }

                /// @brief Refresh the field.
                /// @details Calls refresh() on all the elements (if they are fields and not raw bytes).
                /// @brief Returns true if any of the elements has been updated, false otherwise.
                bool refresh() {
                    return base_impl_type::refresh();
                }

                /// @brief Get minimal length that is required to serialise field of this type.
                static constexpr std::size_t min_length() {
                    return base_impl_type::min_length();
                }

                /// @brief Get maximal length that is required to serialise field of this type.
                static constexpr std::size_t max_length() {
                    return base_impl_type::max_length();
                }

                /// @brief Force number of elements that must be read in the next read()
                ///     invocation.
                /// @details Exists only if nil::marshalling::option::SequenceSizeForcingEnabled option has been
                ///     used.
                /// @param[in] count Number of elements to read during following read operation.
                void force_read_elem_count(std::size_t count) {
                    return base_impl_type::force_read_elem_count(count);
                }

                /// @brief Clear forcing of the number of elements that must be read in the next read()
                ///     invocation.
                /// @details Exists only if nil::marshalling::option::SequenceSizeForcingEnabled option has been
                ///     used.
                void clear_read_elem_count() {
                    return base_impl_type::clear_read_elem_count();
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

                /// @brief Force serialization length of a single element.
                /// @details The function can be used to force a serialization length of a
                ///     single element within the array_list.
                ///     Exists only if @ref nil::marshalling::option::SequenceElemLengthForcingEnabled option has been
                ///     used.
                /// @param[in] count Number of elements to read during following read operation.
                void force_read_elem_length(std::size_t count) {
                    return base_impl_type::force_read_elem_length(count);
                }

                /// @brief Clear forcing the serialization length of the single element.
                /// @details Exists only if nil::marshalling::option::SequenceElemLengthForcingEnabled option has been
                ///     used.
                void clear_read_elem_length_forcing() {
                    return base_impl_type::clear_read_elem_length_forcing();
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
                static_assert(
                    !parsed_options_type::has_ser_offset,
                    "nil::marshalling::option::num_value_ser_offset option is not applicable to array_list field");
                static_assert(!parsed_options_type::has_fixed_length_limit,
                              "nil::marshalling::option::fixed_length option is not applicable to array_list field");
                static_assert(
                    !parsed_options_type::has_fixed_bit_length_limit,
                    "nil::marshalling::option::fixed_bit_length option is not applicable to array_list field");
                static_assert(!parsed_options_type::has_var_length_limits,
                              "nil::marshalling::option::var_length option is not applicable to array_list field");
                static_assert(
                    !parsed_options_type::has_scaling_ratio,
                    "nil::marshalling::option::scaling_ratio_type option is not applicable to array_list field");
                static_assert(!parsed_options_type::has_units,
                              "nil::marshalling::option::Units option is not applicable to array_list field");
                static_assert(!parsed_options_type::has_multi_range_validation,
                              "nil::marshalling::option::valid_num_value_range (or similar) option is not applicable "
                              "to array_list field");
                static_assert(
                    (!parsed_options_type::has_orig_data_view)
                        || (std::is_integral<TElement>::value && (sizeof(TElement) == sizeof(std::uint8_t))),
                    "Usage of nil::marshalling::option::orig_data_view option is allowed only for raw binary data "
                    "(std::uint8_t) types.");
                static_assert(
                    !parsed_options_type::has_versions_range,
                    "nil::marshalling::option::exists_between_versions (or similar) option is not applicable to "
                    "array_list field");
                static_assert(
                    !parsed_options_type::has_invalid_by_default,
                    "nil::marshalling::option::invalid_by_default option is not applicable to array_list field");
            };

            /// @brief Equivalence comparison operator.
            /// @details Performs lexicographical compare of two array fields.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case first field is less than second field.
            /// @related array_list
            template<typename TFieldBase, typename TElement, typename... TOptions>
            bool operator<(const array_list<TFieldBase, TElement, TOptions...> &field1,
                           const array_list<TFieldBase, TElement, TOptions...> &field2) {
                return std::lexicographical_compare(field1.value().begin(), field1.value().end(),
                                                    field2.value().begin(), field2.value().end());
            }

            /// @brief Non-equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are NOT equal, false otherwise.
            /// @related array_list
            template<typename TFieldBase, typename TElement, typename... TOptions>
            bool operator!=(const array_list<TFieldBase, TElement, TOptions...> &field1,
                            const array_list<TFieldBase, TElement, TOptions...> &field2) {
                return (field1 < field2) || (field2 < field1);
            }

            /// @brief Equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are equal, false otherwise.
            /// @related array_list
            template<typename TFieldBase, typename TElement, typename... TOptions>
            bool operator==(const array_list<TFieldBase, TElement, TOptions...> &field1,
                            const array_list<TFieldBase, TElement, TOptions...> &field2) {
                return !(field1 != field2);
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::array_list type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::array_list
            template<typename TFieldBase, typename TElement, typename... TOptions>
            inline array_list<TFieldBase, TElement, TOptions...> &
                to_field_base(array_list<TFieldBase, TElement, TOptions...> &field) {
                return field;
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::array_list type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::array_list
            template<typename TFieldBase, typename TElement, typename... TOptions>
            inline const array_list<TFieldBase, TElement, TOptions...> &
                to_field_base(const array_list<TFieldBase, TElement, TOptions...> &field) {
                return field;
            }

        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_ARRAY_LIST_HPP
