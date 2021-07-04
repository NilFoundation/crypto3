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

#ifndef MARSHALLING_BITFIELD_HPP
#define MARSHALLING_BITFIELD_HPP

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/types/bitfield/basic_type.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>

#include <nil/marshalling/types/tag.hpp>

namespace nil {
    namespace marshalling {
        namespace types {

            /// @brief bitfield field.
            /// @details Sometimes one or several bytes can be logically split into two
            ///     or more independent values, which are packed together to save some
            ///     space. For example, one enum type that has only 4 possible values, i.e
            ///     only two bits are needed to encode such value. It would be a waste to
            ///     allocate full byte for it. Instead, it is packed with some other, say
            ///     unsigned counter that requires up to 6 bits to encode its valid
            ///     range of values. The following code defines such field:
            ///     @code
            ///         enum class MyEnumType : std::uint8_t
            ///         {
            ///             Value1,
            ///             Value2,
            ///             Value3,
            ///             Value4
            ///         };
            ///
            ///         using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///         using MyField =
            ///             nil::marshalling::types::bitfield<
            ///                 MyFieldBase,
            ///                 std::tuple<
            ///                     nil::marshalling::types::enumeration<
            ///                         MyFieldBase,
            ///                         MyEnumType,
            ///                         nil::marshalling::option::fixed_bit_length<2>
            ///                     >,
            ///                     nil::marshalling::types::integral<
            ///                         MyFieldBase,
            ///                         std::uint8_t,
            ///                         nil::marshalling::option::fixed_bit_length<6>
            ///                     >
            ///                 >
            ///             >;
            ///     @endcode
            ///     Note, that bitfield members fields specify their length in bits using
            ///     nil::marshalling::option::fixed_bit_length option.
            ///     Also note, that all bitfield member's lengths in bits combined create
            ///     a round number of bytes, i.e all the bits must sum up to 8, 16, 24, 32, ...
            ///     bits.
            ///
            ///     Refer to @ref sec_field_tutorial_bitfield for tutorial and usage examples.
            /// @tparam TFieldBase Base class for this field, expected to be a variant of
            ///     nil::marshalling::field_type.
            /// @tparam TMembers All member fields bundled together in
            ///     <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>.
            /// @tparam TOptions Zero or more options that modify/refine default behaviour
            ///     of the field.@n
            ///     Supported options are:
            ///     @li @ref nil::marshalling::option::contents_validator - All field members may specify
            ///         their independent validators. The bitfield field considered to
            ///         be valid if all the field members are valid. This option though,
            ///         provides an ability to add extra validation logic that can
            ///         observe value of more than one bitfield member. For example,
            ///         protocol specifies that if one specific member has value X, than
            ///         other member is NOT allowed to have value Y.
            ///     @li @ref nil::marshalling::option::contents_refresher - The default refreshing
            ///         behaviour is to call the @b refresh() member function of every
            ///         member field. This option provides an ability to set a custom
            ///         "refreshing" logic.
            ///     @li @ref nil::marshalling::option::has_custom_read
            ///     @li @ref nil::marshalling::option::has_custom_refresh
            ///     @li @ref nil::marshalling::option::empty_serialization
            ///     @li @ref nil::marshalling::option::version_storage
            /// @pre TMember is a variant of std::tuple, that contains other fields.
            /// @pre Every field member specifies its length in bits using
            ///     nil::marshalling::option::fixed_bit_length option.
            /// @extends nil::marshalling::field_type
            /// @headerfile nil/marshalling/types/bitfield.hpp
            /// @see @ref MARSHALLING_FIELD_MEMBERS_ACCESS()
            /// @see @ref MARSHALLING_FIELD_MEMBERS_ACCESS_NOTEMPLATE()
            template<typename TFieldBase, typename TMembers, typename... TOptions>
            class bitfield
                : private detail::adapt_basic_field_type<detail::basic_bitfield<TFieldBase, TMembers>, TOptions...> {
                using base_impl_type
                    = detail::adapt_basic_field_type<detail::basic_bitfield<TFieldBase, TMembers>, TOptions...>;

            public:
                /// @brief endian_type used for serialization.
                using endian_type = typename base_impl_type::endian_type;

                /// @brief Version type
                using version_type = typename base_impl_type::version_type;

                /// @brief All the options provided to this class bundled into struct.
                using parsed_options_type = detail::options_parser<TOptions...>;

                /// @brief Tag indicating type of the field
                using tag = tag::bitfield;

                /// @brief Value type.
                /// @details Same as TMemebers template argument, i.e. it is std::tuple
                ///     of all the member fields.
                using value_type = typename base_impl_type::value_type;

                /// @brief Default constructor
                /// @details All field members are initialised using their default constructors.
                bitfield() = default;

                /// @brief Constructor
                /// @param[in] val Value of the field to initialise it with.
                explicit bitfield(const value_type &val) : base_impl_type(val) {
                }

                /// @brief Constructor
                /// @param[in] val Value of the field to initialise it with.
                explicit bitfield(value_type &&val) : base_impl_type(std::move(val)) {
                }

                /// @brief Retrieve number of bits specified member field consumes.
                /// @tparam TIdx Index of the member field.
                /// @return Number of bits, specified with nil::marshalling::option::fixed_bit_length option
                ///     used with the requested member.
                template<std::size_t TIdx>
                static constexpr std::size_t member_bit_length() {
                    return base_impl_type::template member_bit_length<TIdx>();
                }

                /// @brief Get access to the stored tuple of fields.
                /// @return Const reference to the underlying stored value.
                const value_type &value() const {
                    return base_impl_type::value();
                }

                /// @brief Get access to the stored tuple of fields.
                /// @return Reference to the underlying stored value.
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

                /// @brief Refresh the field's contents
                /// @details Calls refresh() member function on every member field, will
                ///     return @b true if any of the calls returns @b true.
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
                static_assert(
                    !parsed_options_type::has_ser_offset,
                    "nil::marshalling::option::num_value_ser_offset option is not applicable to bitfield field");
                static_assert(!parsed_options_type::has_fixed_length_limit,
                              "nil::marshalling::option::fixed_length option is not applicable to bitfield field");
                static_assert(!parsed_options_type::has_fixed_bit_length_limit,
                              "nil::marshalling::option::fixed_bit_length option is not applicable to bitfield field");
                static_assert(!parsed_options_type::has_var_length_limits,
                              "nil::marshalling::option::var_length option is not applicable to bitfield field");
                static_assert(!parsed_options_type::has_sequence_elem_length_forcing,
                              "nil::marshalling::option::SequenceElemLengthForcingEnabled option is not applicable to "
                              "bitfield field");
                static_assert(
                    !parsed_options_type::has_sequence_size_forcing,
                    "nil::marshalling::option::SequenceSizeForcingEnabled option is not applicable to bitfield field");
                static_assert(
                    !parsed_options_type::has_sequence_length_forcing,
                    "nil::marshalling::option::SequenceLengthorcingEnabled option is not applicable to bitfield field");
                static_assert(
                    !parsed_options_type::has_sequence_fixed_size,
                    "nil::marshalling::option::sequence_fixed_size option is not applicable to bitfield field");
                static_assert(!parsed_options_type::has_sequence_fixed_size_use_fixed_size_storage,
                              "nil::marshalling::option::SequenceFixedSizeUseFixedSizeStorage option is not applicable "
                              "to bitfield field");
                static_assert(
                    !parsed_options_type::has_sequence_size_field_prefix,
                    "nil::marshalling::option::sequence_size_field_prefix option is not applicable to bitfield field");
                static_assert(!parsed_options_type::has_sequence_ser_length_field_prefix,
                              "nil::marshalling::option::sequence_ser_length_field_prefix option is not applicable to "
                              "bitfield field");
                static_assert(
                    !parsed_options_type::has_sequence_elem_ser_length_field_prefix,
                    "nil::marshalling::option::sequence_elem_ser_length_field_prefix option is not applicable to "
                    "bitfield field");
                static_assert(
                    !parsed_options_type::has_sequence_elem_fixed_ser_length_field_prefix,
                    "nil::marshalling::option::SequenceElemSerLengthFixedFieldPrefix option is not applicable to "
                    "bitfield field");
                static_assert(!parsed_options_type::has_sequence_trailing_field_suffix,
                              "nil::marshalling::option::sequence_trailing_field_suffix option is not applicable to "
                              "bitfield field");
                static_assert(!parsed_options_type::has_sequence_termination_field_suffix,
                              "nil::marshalling::option::sequence_termination_field_suffix option is not applicable to "
                              "bitfield field");
                static_assert(
                    !parsed_options_type::has_fixed_size_storage,
                    "nil::marshalling::option::fixed_size_storage option is not applicable to bitfield field");
                static_assert(
                    !parsed_options_type::has_custom_storage_type,
                    "nil::marshalling::option::custom_storage_type option is not applicable to bitfield field");
                static_assert(
                    !parsed_options_type::has_scaling_ratio,
                    "nil::marshalling::option::scaling_ratio_type option is not applicable to bitfield field");
                static_assert(!parsed_options_type::has_units,
                              "nil::marshalling::option::Units option is not applicable to bitfield field");
                static_assert(!parsed_options_type::has_orig_data_view,
                              "nil::marshalling::option::orig_data_view option is not applicable to bitfield field");
                static_assert(!parsed_options_type::has_multi_range_validation,
                              "nil::marshalling::option::valid_num_value_range (or similar) option is not applicable "
                              "to bitfield field");
                static_assert(!parsed_options_type::has_versions_range,
                              "nil::marshalling::option::exists_between_versions (or similar) option is not applicable "
                              "to bitfield field");
                static_assert(
                    !parsed_options_type::has_invalid_by_default,
                    "nil::marshalling::option::invalid_by_default option is not applicable to bitfield field");
            };

            /// @brief Equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are equal, false otherwise.
            /// @related bitfield
            template<typename TFieldBase, typename TMembers, typename... TOptions>
            bool operator==(const bitfield<TFieldBase, TMembers, TOptions...> &field1,
                            const bitfield<TFieldBase, TMembers, TOptions...> &field2) {
                return field1.value() == field2.value();
            }

            /// @brief Non-equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are NOT equal, false otherwise.
            /// @related bitfield
            template<typename TFieldBase, typename TMembers, typename... TOptions>
            bool operator!=(const bitfield<TFieldBase, TMembers, TOptions...> &field1,
                            const bitfield<TFieldBase, TMembers, TOptions...> &field2) {
                return field1.value() != field2.value();
            }

            /// @brief Equivalence comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case value of the first field is lower than than the value of the second.
            /// @related bitfield
            template<typename TFieldBase, typename TMembers, typename... TOptions>
            bool operator<(const bitfield<TFieldBase, TMembers, TOptions...> &field1,
                           const bitfield<TFieldBase, TMembers, TOptions...> &field2) {
                return field1.value() < field2.value();
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::bitfield type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::bitfield
            template<typename TFieldBase, typename TMembers, typename... TOptions>
            inline bitfield<TFieldBase, TMembers, TOptions...> &
                to_field_base(bitfield<TFieldBase, TMembers, TOptions...> &field) {
                return field;
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::bitfield type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::bitfield
            template<typename TFieldBase, typename TMembers, typename... TOptions>
            inline const bitfield<TFieldBase, TMembers, TOptions...> &
                to_field_base(const bitfield<TFieldBase, TMembers, TOptions...> &field) {
                return field;
            }

        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BITFIELD_HPP
