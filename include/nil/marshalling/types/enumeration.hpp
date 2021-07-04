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

/// @file
/// Contains definition of nil::marshalling::types::enumeration

#ifndef MARSHALLING_ENUM_VALUE_HPP
#define MARSHALLING_ENUM_VALUE_HPP

#include <type_traits>

#include <nil/marshalling/options.hpp>
#include <nil/marshalling/types/detail/options_parser.hpp>
#include <nil/marshalling/types/enumeration/basic_type.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/types/tag.hpp>

namespace nil {
    namespace marshalling {
        namespace types {

            /// @brief Enumerator value field.
            /// @details Sometimes dealing with enum values is much more convenient that
            ///     using integral values. nil::marshalling::types::enumeration is very similar to
            ///     nil::marshalling::types::integral, but receives underlying enum type in its
            ///     template parameters instead of integral one.
            /// @tparam TFieldBase Base class for this field, expected to be a variant of
            ///     nil::marshalling::field_type.
            /// @tparam TEnum Enderlying enum type, can be either unscoped or scoped (enum class).
            /// @tparam TOptions Zero or more options that modify/refine default behaviour
            ///     of the field. If no option is provided, the field's value is serialized as is,
            ///     where the length of the field is equal to the length of the underlying
            ///     enum type. For example:
            ///     @code
            ///         enum class MyEnum : std::uint16_t
            ///         {
            ///             Value1,
            ///             Value2,
            ///             Value3
            ///         }
            ///         using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///         using MyField =nil::marshalling::types::enumeration<MyFieldBase, MyEnum>;
            ///     @endcode
            ///     The serialized value of the field in the example above will consume
            ///     2 bytes, because the underlying type of MyEnum is
            ///     defined to be std::uint16_t. The value is serialized using big endian
            ///     notation because base field class receives nil::marshalling::option::BigEndian option.@n
            ///     Supported options are:
            ///     @li @ref nil::marshalling::option::fixed_length
            ///     @li @ref nil::marshalling::option::fixed_bit_length
            ///     @li @ref nil::marshalling::option::var_length
            ///     @li @ref nil::marshalling::num_value_ser_offset
            ///     @li @ref nil::marshalling::option::default_value_initializer or
            ///     nil::marshalling::option::default_num_value.
            ///     @li @ref nil::marshalling::option::ContentsValidator
            ///     @li @ref nil::marshalling::option::valid_num_value_range, @ref nil::marshalling::option::ValidNumValue,
            ///         @ref nil::marshalling::option::ValidBigUnsignedNumValueRange, @ref
            ///         nil::marshalling::option::ValidBigUnsignedNumValue
            ///     @li @ref nil::marshalling::option::valid_ranges_clear
            ///     @li @ref nil::marshalling::option::contents_refresher
            ///     @li @ref nil::marshalling::option::has_custom_read
            ///     @li @ref nil::marshalling::option::has_custom_refresh
            ///     @li @ref nil::marshalling::option::fail_on_invalid
            ///     @li @ref nil::marshalling::option::ignore_invalid
            ///     @li @ref nil::marshalling::option::empty_serialization
            ///     @li @ref nil::marshalling::option::invalid_by_default
            ///     @li @ref nil::marshalling::option::version_storage
            /// @extends nil::marshalling::field_type
            /// @headerfile nil/marshalling/types/enumeration.hpp
            template<typename TFieldBase, typename TEnum, typename... TOptions>
            class enumeration
                : private detail::adapt_basic_field_type<detail::basic_enumeration<TFieldBase, TEnum>, TOptions...> {
                using base_impl_type
                    = detail::adapt_basic_field_type<detail::basic_enumeration<TFieldBase, TEnum>, TOptions...>;
                static_assert(std::is_enum<TEnum>::value, "TEnum must be enum type");

            public:
                /// @brief endian_type used for serialization.
                using endian_type = typename base_impl_type::endian_type;

                /// @brief Version type
                using version_type = typename base_impl_type::version_type;

                /// @brief All the options provided to this class bundled into struct.
                using parsed_options_type = detail::options_parser<TOptions...>;

                /// @brief Tag indicating type of the field
                using tag = tag::enumeration;

                /// @brief Type of underlying enum value.
                /// @details Same as template parameter TEnum to this class.
                using value_type = typename base_impl_type::value_type;

                /// @brief Default constructor.
                enumeration() = default;

                /// @brief Constructor
                explicit enumeration(const value_type &val) : base_impl_type(val) {
                }

                /// @brief Copy constructor
                enumeration(const enumeration &) = default;

                /// @brief Destructor
                ~enumeration() noexcept = default;

                /// @brief Copy assignment
                enumeration &operator=(const enumeration &) = default;

                /// @brief Get access to enum value storage.
                const value_type &value() const {
                    return base_impl_type::value();
                }

                /// @brief Get access to enum value storage.
                value_type &value() {
                    return base_impl_type::value();
                }

                /// @brief Get length required to serialise the current field value.
                /// @return Number of bytes it will take to serialise the field value.
                constexpr std::size_t length() const {
                    return base_impl_type::length();
                }

                /// @brief Get minimal length that is required to serialise field of this type.
                /// @return Minimal number of bytes required serialise the field value.
                static constexpr std::size_t min_length() {
                    return base_impl_type::min_length();
                }

                /// @brief Get maximal length that is required to serialise field of this type.
                /// @return Maximal number of bytes required serialise the field value.
                static constexpr std::size_t max_length() {
                    return base_impl_type::max_length();
                }

                /// @brief Read field value from input data sequence
                /// @param[in, out] iter Iterator to read the data.
                /// @param[in] size Number of bytes available for reading.
                /// @return Status of read operation.
                /// @post Iterator is advanced.
                template<typename TIter>
                status_type read(TIter &iter, std::size_t size) {
                    return base_impl_type::read(iter, size);
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
                /// @param[in, out] iter Iterator to write the data.
                /// @param[in] size Maximal number of bytes that can be written.
                /// @return Status of write operation.
                /// @post Iterator is advanced.
                template<typename TIter>
                status_type write(TIter &iter, std::size_t size) const {
                    return base_impl_type::write(iter, size);
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
                bool valid() const {
                    return base_impl_type::valid();
                }

                /// @brief Refresh the field's value
                /// @return @b true if the value has been updated, @b false otherwise
                bool refresh() {
                    return base_impl_type::refresh();
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
                static_assert(!parsed_options_type::has_sequence_elem_length_forcing,
                              "nil::marshalling::option::SequenceElemLengthForcingEnabled option is not applicable to "
                              "enumeration field");
                static_assert(!parsed_options_type::has_sequence_size_forcing,
                              "nil::marshalling::option::SequenceSizeForcingEnabled option is not applicable to "
                              "enumeration field");
                static_assert(!parsed_options_type::has_sequence_length_forcing,
                              "nil::marshalling::option::SequenceLengthForcingEnabled option is not applicable to "
                              "enumeration field");
                static_assert(
                    !parsed_options_type::has_sequence_fixed_size,
                    "nil::marshalling::option::sequence_fixed_size option is not applicable to enumeration field");
                static_assert(
                    !parsed_options_type::has_sequence_fixed_size_use_fixed_size_storage,
                    "nil::marshalling::option::SequenceFixedSizeUseFixedSizeStorage option is not applicable to "
                    "enumeration field");
                static_assert(!parsed_options_type::has_sequence_size_field_prefix,
                              "nil::marshalling::option::sequence_size_field_prefix option is not applicable to "
                              "enumeration field");
                static_assert(!parsed_options_type::has_sequence_ser_length_field_prefix,
                              "nil::marshalling::option::sequence_ser_length_field_prefix option is not applicable to "
                              "enumeration field");
                static_assert(
                    !parsed_options_type::has_sequence_elem_ser_length_field_prefix,
                    "nil::marshalling::option::sequence_elem_ser_length_field_prefix option is not applicable to "
                    "enumeration field");
                static_assert(
                    !parsed_options_type::has_sequence_elem_fixed_ser_length_field_prefix,
                    "nil::marshalling::option::SequenceElemSerLengthFixedFieldPrefix option is not applicable to "
                    "enumeration field");
                static_assert(!parsed_options_type::has_sequence_trailing_field_suffix,
                              "nil::marshalling::option::sequence_trailing_field_suffix option is not applicable to "
                              "enumeration field");
                static_assert(!parsed_options_type::has_sequence_termination_field_suffix,
                              "nil::marshalling::option::sequence_termination_field_suffix option is not applicable to "
                              "enumeration field");
                static_assert(
                    !parsed_options_type::has_fixed_size_storage,
                    "nil::marshalling::option::fixed_size_storage option is not applicable to enumeration field");
                static_assert(
                    !parsed_options_type::has_custom_storage_type,
                    "nil::marshalling::option::custom_storage_type option is not applicable to enumeration field");
                static_assert(
                    !parsed_options_type::has_scaling_ratio,
                    "nil::marshalling::option::scaling_ratio_type option is not applicable to enumeration field");
                static_assert(!parsed_options_type::has_units,
                              "nil::marshalling::option::Units option is not applicable to enumeration field");
                static_assert(!parsed_options_type::has_orig_data_view,
                              "nil::marshalling::option::orig_data_view option is not applicable to enumeration field");
                static_assert(
                    !parsed_options_type::has_versions_range,
                    "nil::marshalling::option::exists_between_versions (or similar) option is not applicable to "
                    "enumeration field");
            };

            // Implementation

            /// @brief Equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are equal, false otherwise.
            /// @related enumeration
            template<typename TFieldBase, typename TEnum, typename... TOptions>
            bool operator==(const enumeration<TFieldBase, TEnum, TOptions...> &field1,
                            const enumeration<TFieldBase, TEnum, TOptions...> &field2) {
                return field1.value() == field2.value();
            }

            /// @brief Non-equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are NOT equal, false otherwise.
            /// @related enumeration
            template<typename TFieldBase, typename TEnum, typename... TOptions>
            bool operator!=(const enumeration<TFieldBase, TEnum, TOptions...> &field1,
                            const enumeration<TFieldBase, TEnum, TOptions...> &field2) {
                return field1.value() != field2.value();
            }

            /// @brief Equivalence comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case value of the first field is lower than than the value of the second.
            /// @related enumeration
            template<typename TFieldBase, typename TEnum, typename... TOptions>
            bool operator<(const enumeration<TFieldBase, TEnum, TOptions...> &field1,
                           const enumeration<TFieldBase, TEnum, TOptions...> &field2) {
                return field1.value() < field2.value();
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::enumeration type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::enumeration
            template<typename TFieldBase, typename TEnum, typename... TOptions>
            inline enumeration<TFieldBase, TEnum, TOptions...> &
                to_field_base(enumeration<TFieldBase, TEnum, TOptions...> &field) {
                return field;
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::enumeration type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::enumeration
            template<typename TFieldBase, typename TEnum, typename... TOptions>
            inline const enumeration<TFieldBase, TEnum, TOptions...> &
                to_field_base(const enumeration<TFieldBase, TEnum, TOptions...> &field) {
                return field;
            }

        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_ENUM_VALUE_HPP
