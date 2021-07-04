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

#ifndef MARSHALLING_FLOAT_VALUE_HPP
#define MARSHALLING_FLOAT_VALUE_HPP

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/types/float_value/basic_type.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>

#include <nil/marshalling/types/tag.hpp>

namespace nil {
    namespace marshalling {
        namespace types {

            /// @brief field_type that represent floating point value.
            /// @details Represents IEEE 754 floating point value, which means the value is
            ///     serialized as is (consumes 4 bytes for float, and 8 bytes for double),
            ///     using big or little endian.
            /// @tparam TFieldBase Base class for this field, expected to be a variant of
            ///     nil::marshalling::field_type.
            /// @tparam T Basic underlying floating point type, must be either float or double.
            /// @tparam TOptions Zero or more options that modify/refine default behaviour
            ///     of the field. If no option is provided The field's value is serialized as is.
            ///     @code
            ///         using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///         using MyField =nil::marshalling::types::float_value<MyFieldBase, float>;
            ///     @endcode
            ///     In the example above it will
            ///     consume 4 bytes (because sizeof(float) == 4) and will
            ///     be serialized using big endian notation.@n
            ///     Supported options are:
            ///     @li @ref nil::marshalling::option::default_value_initializer or @ref
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
            ///     @li @b nil::marshalling::option::Units* - all variants of value units, see
            ///         @ref sec_field_tutorial_integral_units for details.
            ///     @li @ref nil::marshalling::option::empty_serialization
            ///     @li @ref nil::marshalling::option::invalid_by_default
            ///     @li @ref nil::marshalling::option::version_storage
            /// @extends nil::marshalling::field_type
            /// @headerfile nil/marshalling/types/float_value.hpp
            template<typename TFieldBase, typename T, typename... TOptions>
            class float_value : private detail::adapt_basic_field_type<detail::basic_float_value<TFieldBase, T>, TOptions...> {
                using base_impl_type = detail::adapt_basic_field_type<detail::basic_float_value<TFieldBase, T>, TOptions...>;

            public:
                /// @brief endian_type used for serialization.
                using endian_type = typename base_impl_type::endian_type;

                /// @brief Version type
                using version_type = typename base_impl_type::version_type;

                /// @brief All the options provided to this class bundled into struct.
                using parsed_options_type = detail::options_parser<TOptions...>;

                /// @brief Tag indicating type of the field
                using tag = tag::floating_point;

                /// @brief Type of underlying floating point value.
                /// @details Same as template parameter T to this class.
                using value_type = typename base_impl_type::value_type;

                /// @brief Default constructor
                /// @details Initialises internal value to 0.
                float_value() = default;

                /// @brief Constructor
                explicit float_value(const value_type &val) : base_impl_type(val) {
                }

                /// @brief Get access to floating point value storage.
                const value_type &value() const {
                    return base_impl_type::value();
                }

                /// @brief Get access to floating point value storage.
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

                /// @brief Check validity of the field value.
                bool valid() const {
                    return base_impl_type::valid();
                }

                /// @brief Refresh the field's value
                /// @return @b true if the value has been updated, @b false otherwise
                bool refresh() {
                    return base_impl_type::refresh();
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
                static_assert(!parsed_options_type::has_var_length_limits,
                              "nil::marshalling::option::var_length option is not applicable to float_value field");
                static_assert(!parsed_options_type::has_sequence_elem_length_forcing,
                              "nil::marshalling::option::SequenceElemLengthForcingEnabled option is not applicable to "
                              "float_value field");
                static_assert(!parsed_options_type::has_sequence_size_forcing,
                              "nil::marshalling::option::SequenceSizeForcingEnabled option is not applicable to "
                              "float_value field");
                static_assert(!parsed_options_type::has_sequence_length_forcing,
                              "nil::marshalling::option::SequenceLengthForcingEnabled option is not applicable to "
                              "float_value field");
                static_assert(
                    !parsed_options_type::has_sequence_fixed_size,
                    "nil::marshalling::option::sequence_fixed_size option is not applicable to float_value field");
                static_assert(
                    !parsed_options_type::has_sequence_fixed_size_use_fixed_size_storage,
                    "nil::marshalling::option::SequenceFixedSizeUseFixedSizeStorage option is not applicable to "
                    "float_value field");
                static_assert(!parsed_options_type::has_sequence_size_field_prefix,
                              "nil::marshalling::option::sequence_size_field_prefix option is not applicable to "
                              "float_value field");
                static_assert(!parsed_options_type::has_sequence_ser_length_field_prefix,
                              "nil::marshalling::option::sequence_ser_length_field_prefix option is not applicable to "
                              "float_value field");
                static_assert(
                    !parsed_options_type::has_sequence_elem_ser_length_field_prefix,
                    "nil::marshalling::option::sequence_elem_ser_length_field_prefix option is not applicable to "
                    "float_value field");
                static_assert(
                    !parsed_options_type::has_sequence_elem_fixed_ser_length_field_prefix,
                    "nil::marshalling::option::SequenceElemSerLengthFixedFieldPrefix option is not applicable to "
                    "float_value field");
                static_assert(!parsed_options_type::has_sequence_trailing_field_suffix,
                              "nil::marshalling::option::sequence_trailing_field_suffix option is not applicable to "
                              "float_value field");
                static_assert(!parsed_options_type::has_sequence_termination_field_suffix,
                              "nil::marshalling::option::sequence_termination_field_suffix option is not applicable to "
                              "float_value field");
                static_assert(
                    !parsed_options_type::has_fixed_size_storage,
                    "nil::marshalling::option::fixed_size_storage option is not applicable to float_value field");
                static_assert(
                    !parsed_options_type::has_custom_storage_type,
                    "nil::marshalling::option::custom_storage_type option is not applicable to float_value field");
                static_assert(!parsed_options_type::has_orig_data_view,
                              "nil::marshalling::option::orig_data_view option is not applicable to float_value field");
                static_assert(
                    !parsed_options_type::has_versions_range,
                    "nil::marshalling::option::exists_between_versions (or similar) option is not applicable to "
                    "float_value field");
            };

            /// @brief Equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are equal, false otherwise.
            /// @related float_value
            template<typename TFieldBase, typename T, typename... TOptions>
            bool operator==(const float_value<TFieldBase, T, TOptions...> &field1,
                            const float_value<TFieldBase, T, TOptions...> &field2) {
                return field1.value() == field2.value();
            }

            /// @brief Non-equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are NOT equal, false otherwise.
            /// @related float_value
            template<typename TFieldBase, typename T, typename... TOptions>
            bool operator!=(const float_value<TFieldBase, T, TOptions...> &field1,
                            const float_value<TFieldBase, T, TOptions...> &field2) {
                return field1.value() != field2.value();
            }

            /// @brief Equivalence comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case value of the first field is lower than than the value of the second.
            /// @related float_value
            template<typename TFieldBase, typename T, typename... TOptions>
            bool operator<(const float_value<TFieldBase, T, TOptions...> &field1,
                           const float_value<TFieldBase, T, TOptions...> &field2) {
                return field1.value() < field2.value();
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::float_value type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::float_value
            template<typename TFieldBase, typename T, typename... TOptions>
            inline float_value<TFieldBase, T, TOptions...> &
                to_field_base(float_value<TFieldBase, T, TOptions...> &field) {
                return field;
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::float_value type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::float_value
            template<typename TFieldBase, typename T, typename... TOptions>
            inline const float_value<TFieldBase, T, TOptions...> &
                to_field_base(const float_value<TFieldBase, T, TOptions...> &field) {
                return field;
            }

        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_FLOAT_VALUE_HPP
