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
/// Contains definition of all the options used by the @b Marshalling library

#ifndef MARSHALLING_OPTIONS_HPP
#define MARSHALLING_OPTIONS_HPP

#include <tuple>
#include <type_traits>
#include <limits>
#include <ratio>
#include <cstdint>
#include <cstddef>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/units_types.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/types/optional_mode.hpp>

namespace nil {
    namespace marshalling {
        namespace option {
            namespace detail {

                template<typename T>
                struct is_ratio_t {
                    static const bool value = false;
                };

                template<std::intmax_t TNum, std::intmax_t TDen>
                struct is_ratio_t<std::ratio<TNum, TDen>> {
                    static const bool value = true;
                };

                template<typename T>
                constexpr bool is_ratio() {
                    return is_ratio_t<T>::value;
                }

            }    // namespace detail

            // message/field_t common options

            /// @brief options to specify endian.
            /// @tparam TEndian endian_type type. Must be either nil::marshalling::endian::big_endian or
            ///     nil::marshalling::endian::little_endian.
            /// @headerfile nil/marshalling/options.hpp
            template<typename TEndian>
            struct endian { };

            /// @brief Alias option to endian_type specifying big endian.
            /// @headerfile nil/marshalling/options.hpp
            using big_endian = endian<nil::marshalling::endian::big_endian>;

            /// @brief Alias option to endian_type specifying little endian.
            /// @headerfile nil/marshalling/options.hpp
            using little_endian = endian<nil::marshalling::endian::little_endian>;

            /// @brief No-op option, doesn't have any effect.
            /// @headerfile nil/marshalling/options.hpp
            struct empty_option { };

            /// @brief Option used to specify type of the ID.
            /// @tparam T Type of the message ID.
            /// @headerfile nil/marshalling/options.hpp
            template<typename T>
            struct msg_id_type { };

            /// @brief Option used to specify type of iterator used for reading.
            /// @tparam TIter Type of the iterator.
            /// @headerfile nil/marshalling/options.hpp
            template<typename TIter>
            struct read_iterator { };

            /// @brief Option used to specify type of iterator used for writing.
            /// @tparam TIter Type of the iterator.
            /// @headerfile nil/marshalling/options.hpp
            template<typename TIter>
            struct write_iterator { };

            /// @brief Option used to add @b get_id() function into message interface.
            /// @headerfile nil/marshalling/options.hpp
            struct id_info_interface { };

            /// @brief Option used to add @b valid() function into message interface.
            /// @headerfile nil/marshalling/options.hpp
            struct valid_check_interface { };

            /// @brief Option used to add @b length() function into message interface.
            /// @headerfile nil/marshalling/options.hpp
            struct length_info_interface { };

            /// @brief Option used to add @b refresh() function into message interface.
            /// @headerfile nil/marshalling/options.hpp
            struct refresh_interface { };

            /// @brief Option used to add @b name() function into message interface.
            /// @headerfile nil/marshalling/options.hpp
            struct name_interface { };

            /// @brief Option used to specify type of the message handler.
            /// @tparam T Type of the handler.
            /// @headerfile nil/marshalling/options.hpp
            template<typename T>
            struct handler { };

            /// @brief Option used to specify numeric ID of the message.
            /// @tparam TId Numeric ID value.
            /// @headerfile nil/marshalling/options.hpp
            template<std::intmax_t TId>
            struct static_num_id_impl { };

            /// @brief Option used to specify that message doesn't have valid ID.
            /// @headerfile nil/marshalling/options.hpp
            struct no_id_impl { };

            /// @brief Option used to specify actual type of the message.
            /// @headerfile nil/marshalling/options.hpp
            template<typename TMsg>
            struct msg_type { };

            /// @brief Option used to inhibit default implementation of @b dispatch_impl()
            ///     in nil::marshalling::message_base.
            /// @headerfile nil/marshalling/options.hpp
            struct no_dispatch_impl { };

            /// @brief Option used to specify some extra fields from transport framing.
            /// @details Some fields from transport framing may influence the way on how
            ///     message fields get read or written. It may also have an influence on
            ///     how message is handled. This option is intended to provide a list
            ///     of such fields, bundled in @b std::tuple, to @ref nil::marshalling::message interface
            ///     class.
            /// @tparam TFields The fields of the message bundled in std::tuple.
            /// @headerfile nil/marshalling/options.hpp
            template<typename TFields>
            struct extra_transport_fields { };

            /// @brief Option used to specify index of the version field inside
            ///     extra transport fields tuple provided with @ref
            ///     nil::marshalling::option::extra_transport_fields_type option.
            /// @tparam TIdx Index of the field inside the tuple.
            /// @headerfile nil/marshalling/options.hpp
            template<std::size_t TIdx>
            struct version_in_extra_transport_fields { };

            /// @brief Option used to specify fields of the message and force implementation
            ///     of default read, write, validity check, and length retrieval information
            ///     of the message.
            /// @tparam TFields The fields of the message bundled in std::tuple.
            /// @headerfile nil/marshalling/options.hpp
            template<typename TFields>
            struct fields_impl;

            /// @cond SKIP_DOC
            template<typename... TFields>
            struct fields_impl<std::tuple<TFields...>> { };
            /// @endcond

            /// @brief Alias to FieldsImpl<std::tuple<> >
            /// @headerfile nil/marshalling/options.hpp
            using zero_fields_impl = fields_impl<std::tuple<>>;

            /// @brief Option that inhibits implementation of nil::marshalling::message_base::read_impl()
            ///     regardless of other availability conditions.
            /// @headerfile nil/marshalling/options.hpp
            struct no_read_impl { };

            /// @brief Option that inhibits implementation of nil::marshalling::message_base::write_impl()
            ///     regardless of other availability conditions.
            /// @headerfile nil/marshalling/options.hpp
            struct no_write_impl { };

            /// @brief Option that inhibits implementation of nil::marshalling::message_base::valid_impl()
            ///     regardless of other availability conditions.
            /// @headerfile nil/marshalling/options.hpp
            struct no_valid_impl { };

            /// @brief Option that inhibits implementation of nil::marshalling::message_base::length_impl()
            ///     regardless of other availability conditions.
            /// @headerfile nil/marshalling/options.hpp
            struct no_length_impl { };

            /// @brief Option that inhibits implementation of nil::marshalling::message_base::refresh_impl()
            ///     regardless of other availability conditions.
            /// @headerfile nil/marshalling/options.hpp
            struct no_refresh_impl { };

            /// @brief Option that notifies nil::marshalling::message_base about existence of
            ///     @b eval_get_id() member function in derived class.
            /// @headerfile nil/marshalling/options.hpp
            struct has_do_get_id { };

            /// @brief Option that notifies nil::marshalling::message_base about existence of
            ///     access to fields.
            /// @details Can be useful when there is a chain of inheritances from
            ///     nil::marshalling::message_base.
            /// @headerfile nil/marshalling/options.hpp
            struct assume_fields_existence { };

            /// @brief Option that forces "in place" allocation with placement "new" for
            ///     initialisation, instead of usage of dynamic memory allocation.
            /// @headerfile nil/marshalling/options.hpp
            struct in_place_allocation { };

            /// @brief Option used to allow @ref nil::marshalling::generic_message generation inside
            ///  @ref nil::marshalling::msg_factory and/or @ref nil::marshalling::protocol::MsgIdLayer classes.
            /// @tparam TGenericMessage Type of message, expected to be a variant of
            ///     @ref nil::marshalling::generic_message.
            template<typename TGenericMessage>
            struct support_generic_message { };

            /// @brief Option used to specify number of bytes that is used for field serialization.
            /// @details Applicable only to numeric fields, such as nil::marshalling::types::integral or
            ///     nil::marshalling::types::enumeration.
            ///
            ///     For example, protocol specifies that some field is serialized using
            ///     only 3 bytes. There is no basic integral type that takes 3 bytes
            ///     of space exactly. The closest alternative is std::int32_t or
            ///     std::uint32_t. Such field may be defined as:
            ///     @code
            ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///     using MyField =
            ///         nil::marshalling::types::integral<
            ///             MyFieldBase,
            ///             std::uint32_t,
            ///             nil::marshalling::option::fixed_length<3>
            ///         >;
            ///     @endcode
            /// @tparam TLen length of the serialized value.
            /// @tparam TSignExtend Perform sign extension, relevant only to signed types.
            /// @headerfile nil/marshalling/options.hpp
            template<std::size_t TLen, bool TSignExtend = true>
            struct fixed_length { };

            /// @brief Option used to specify number of bits that is used for field serialization
            ///     when a field is a member of nil::marshalling::types::bitfield.
            /// @details For example, the protocol specifies that two independent integer
            ///     values of 6 and 10 bits respectively packed into two bytes to save space.
            ///     Such combined field may be defined as:
            ///     @code
            ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///     using MyField =
            ///         nil::marshalling::types::bitfield<
            ///             MyFieldBase,
            ///             std::tuple<
            ///                 nil::marshalling::types::integral<
            ///                     MyFieldBase,
            ///                     std::uint8_t,
            ///                     nil::marshalling::option::fixed_bit_length<6>
            ///                 >,
            ///                 nil::marshalling::types::integral<
            ///                     MyFieldBase,
            ///                     std::uint16_t,
            ///                     nil::marshalling::option::fixed_bit_length<10>
            ///                 >
            ///             >
            ///         >;
            ///     @endcode
            /// @tparam TLen length of the serialized value in bits.
            /// @headerfile nil/marshalling/options.hpp
            template<std::size_t TLen>
            struct fixed_bit_length { };

            /// @brief Option used to specify that field may have variable serialization length
            /// @details Applicable only to numeric fields, such as nil::marshalling::types::integral
            ///     or nil::marshalling::types::enumeration.
            ///     Use this option to specify that serialized value has
            ///     <a href="https://en.wikipedia.org/wiki/Variable-length_quantity">Base-128</a>
            ///     encoding, i.e. the most significant bit in the byte indicates whether
            ///     the encoding of the value is complete or the next byte in
            ///     sequence still encodes the current integer value. For example field
            ///     which value can be serialized using between 1 and 4 bytes can be
            ///     defined as:
            ///     @code
            ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///     using MyField =
            ///         nil::marshalling::types::integral<
            ///             MyFieldBase,
            ///             std::uint32_t,
            ///             nil::marshalling::option::var_length<1, 4>
            ///         >;
            ///         @endcode
            /// @tparam TMin Minimal length the field may consume.
            /// @tparam TMax Maximal length the field may consume.
            /// @pre TMin <= TMax
            /// @headerfile nil/marshalling/options.hpp
            template<std::size_t TMin, std::size_t TMax>
            struct var_length {
                static_assert(TMin <= TMax, "TMin must not be greater that TMax.");
            };

            /// @brief Option to specify numeric value serialization offset.
            /// @details Applicable only to numeric fields such as nil::marshalling::types::integral or
            ///     nil::marshalling::types::enumeration.
            ///     The provided value will be added to the field's value and the
            ///     result will be written to the buffer when serialising. Good example
            ///     for such option would be serialising a "current year" value. Most protocols
            ///     now specify it as an offset from year 2000 or later and written as a
            ///     single byte, i.e. to specify year 2015 is to write value 15.
            ///     However it may be inconvenient to manually adjust serialized/deserialized
            ///     value by predefined offset 2000. To help with such case option
            ///     nil::marshalling::option::num_value_ser_offset can be used. For example:
            ///     @code
            ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///     using MyField =
            ///         nil::marshalling::types::integral<
            ///             MyFieldBase,
            ///             std::uint16_t,
            ///             nil::marshalling::option::fixed_length<1>,
            ///             nil::marshalling::option::num_value_ser_offset<-2000>
            ///         >;
            ///     @endcode
            ///     Note that in the example above the field value (accessible by @b value() member
            ///     function of the field) will have type std::uint16_t and will be equal to
            ///     say 2015, while when serialized it consumes only 1 byte (thanks to
            ///     nil::marshalling::option::fixed_length option) and reduced value of 15 is written.
            /// @tparam TOffset Offset value to be added when serialising field.
            /// @headerfile nil/marshalling/options.hpp
            template<std::intmax_t TOffset>
            struct num_value_ser_offset { };

            /// @brief Option that forces usage of embedded uninitialised data area instead
            ///     of dynamic memory allocation.
            /// @details Applicable to fields that represent collection of raw data or other
            ///     fields, such as nil::marshalling::types::array_list or nil::marshalling::types::string. By
            ///     default, these fields will use
            ///     <a href="http://en.cppreference.com/w/cpp/container/vector">std::vector</a> or
            ///     <a href="http://en.cppreference.com/w/cpp/string/basic_string">std::string</a>
            ///     for their internal data storage. If this option is used, it will force
            ///     such fields to use @ref nil::marshalling::container::static_vector or @ref
            ///     nil::marshalling::container::static_string with the capacity provided by this option.
            /// @tparam TSize Size of the storage area in number of elements, for strings it does @b NOT include
            ///     the '\0' terminating character.
            /// @headerfile nil/marshalling/options.hpp
            template<std::size_t TSize>
            struct fixed_size_storage { };

            /// @brief Set custom storage type for fields like nil::marshalling::types::string or
            ///     nil::marshalling::types::array_list.
            /// @details By default nil::marshalling::types::string uses
            ///     <a href="http://en.cppreference.com/w/cpp/string/basic_string">std::string</a>
            ///     and nil::marshalling::types::array_list uses
            ///     <a href="http://en.cppreference.com/w/cpp/container/vector">std::vector</a> as
            ///     their internal storage types. The @ref fixed_size_storage option forces
            ///     them to use nil::marshalling::container::static_string and
            ///     nil::marshalling::container::static_vector instead. This option can be used to provide any other
            ///     third party type. Such type must define the same public interface as @b std::string (when used with
            ///     nil::marshalling::types::string) or @b std::vector (when used with
            ///     nil::marshalling::types::array_list).
            /// @tparam TType Custom storage type
            /// @headerfile nil/marshalling/options.hpp
            template<typename TType>
            struct custom_storage_type { };

            /// @brief Option to specify scaling ratio.
            /// @details Applicable only to nil::marshalling::types::integral.
            ///     Sometimes the protocol specifies values being transmitted in
            ///     one units while when handling the message they are better to be handled
            ///     in another. For example, some distance information is transmitted as
            ///     integer value of millimetres, but while processing it should be handled as floating
            ///     point value of meters. Such field is defined as:
            ///     @code
            ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///     using MyField =
            ///         nil::marshalling::types::integral<
            ///             MyFieldBase,
            ///             std::int32_t,
            ///             nil::marshalling::option::scaling_ratio<1, 100>
            ///         >;
            ///     @endcode
            ///     Then, to accessed the scaled value of the field use @b scale_as() or
            ///     @b set_scaled() methods of nil::marshalling::types::integral field:
            ///     @code
            ///     void processField(const MyField& field)
            ///     {
            ///         auto distInMillimetres = field.value();
            ///         auto distInMeters = field.scale_as<double>();
            ///     }
            ///     @endcode
            /// @tparam TNum Numerator of the scaling ratio.
            /// @tparam TDenom Denominator of the scaling ratio.
            /// @headerfile nil/marshalling/options.hpp
            template<std::intmax_t TNum, std::intmax_t TDenom>
            struct scaling_ratio {
                static_assert(TNum != 0, "Wrong scaling ratio");
                static_assert(TDenom != 0, "Wrong scaling ratio");
            };

            /// @brief Option that modifies the default behaviour of collection fields to
            ///     prepend the serialized data with number of @b elements information.
            /// @details Quite often when collection of fields is serialized it must be
            ///     prepended with one or more bytes indicating number of elements that will
            ///     follow.
            ///     Applicable to fields that represent collection of raw data or other
            ///     fields, such as nil::marshalling::types::array_list or nil::marshalling::types::string.@n
            ///     For example sequence of raw bytes must be prefixed with 2 bytes stating
            ///     the size of the sequence:
            ///     @code
            ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///     using MyField =
            ///         nil::marshalling::types::array_list<
            ///             MyFieldBase,
            ///             std::uint8_t,
            ///             nil::marshalling::option::sequence_size_field_prefix_type<
            ///                 nil::marshalling::types::integral<MyFieldBase, std::uint16_t>
            ///             >
            ///         >;
            ///     @endcode
            /// @tparam TField Type of the field that represents size
            /// @headerfile nil/marshalling/options.hpp
            template<typename TField>
            struct sequence_size_field_prefix { };

            /// @brief Option that modifies the default behaviour of collection fields to
            ///     prepend the serialized data with number of @b bytes information.
            /// @details Similar to @ref sequence_size_field_prefix_type, but instead of
            ///     number of @b elements to follow, the prefix field contains number of
            ///     @b bytes that will follow.
            ///     @code
            ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///     using MyField =
            ///         nil::marshalling::types::array_list<
            ///             MyFieldBase,
            ///             nil::marshalling::types::bundle<
            ///                 std::tuple<
            ///                     nil::marshalling::types::integral<MyFieldBase, std::uint32_t>,
            ///                     nil::marshalling::types::string<MyFieldBase>
            ///                 >
            ///             >,
            ///             nil::marshalling::option::sequence_ser_length_field_prefix_type<
            ///                 nil::marshalling::types::integral<MyFieldBase, std::uint16_t>
            ///             >
            ///         >;
            ///     @endcode
            /// @tparam TField Type of the field that represents serialization length
            /// @tparam TReadErrorStatus Error status to return in case read operation fails when should not
            /// @headerfile nil/marshalling/options.hpp
            template<typename TField,
                     status_type TReadErrorStatus = status_type::invalid_msg_data>
            struct sequence_ser_length_field_prefix { };

            /// @brief Option that forces <b>every element</b> of @ref nil::marshalling::types::array_list to
            ///     be prefixed with its serialization length.
            /// @details Similar to @ref sequence_ser_length_field_prefix_type but instead of the whole
            ///     list, every element is prepended with its serialization length.
            /// @tparam TField Type of the field that represents serialization length
            /// @tparam TReadErrorStatus Error status to return in case read operation fails when should not
            /// @headerfile nil/marshalling/options.hpp
            template<typename TField,
                     status_type TReadErrorStatus = status_type::invalid_msg_data>
            struct sequence_elem_ser_length_field_prefix { };

            /// @brief Option that forces @b first element only of @ref nil::marshalling::types::array_list to
            ///     be prefixed with its serialization length.
            /// @details Similar to @ref sequence_elem_ser_length_field_prefix_type, but
            ///     applicable only to the lists where elements are of the same
            ///     fixed size, where there is no need to prefix @b every element
            ///     with its size.
            /// @tparam TField Type of the field that represents serialization length
            /// @tparam TReadErrorStatus Error status to return in case read operation fails when should not
            /// @headerfile nil/marshalling/options.hpp
            template<typename TField,
                     status_type TReadErrorStatus = status_type::invalid_msg_data>
            struct sequence_elem_fixed_ser_length_field_prefix { };

            /// @brief Option that forces termination of the sequence when predefined value
            ///     is encountered.
            /// @details Sometimes protocols use zero-termination for strings instead of
            ///     prefixing them with their size. Below is an example of how to achieve
            ///     such termination using sequence_termination_field_suffix option.
            ///     @code
            ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///     using MyField =
            ///         nil::marshalling::types::string<
            ///             MyFieldBase,
            ///             nil::marshalling::option::sequence_termination_field_suffix<
            ///                 nil::marshalling::types::integral<MyFieldBase, char,
            ///                 nil::marshalling::option::default_num_value<0> >
            ///             >
            ///         >;
            ///     @endcode
            /// @tparam TField Type of the field that represents suffix
            /// @headerfile nil/marshalling/options.hpp
            template<typename TField>
            struct sequence_termination_field_suffix { };

            /// @brief Option that forces collection fields to append provides suffix every
            ///     time it is serialized.
            /// @details It is a bit looser version than sequence_termination_field_suffix.
            ///     Encountering the expected termination value doesn't terminate the
            ///     read operation on the sequence. The size of the sequence should
            ///     be defined by other means. For example, zero termination string that
            ///     occupies exactly 6 bytes when serialized (padded with zeroes at the end)
            ///     will be defined like this:
            ///     @code
            ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///     using MyField =
            ///         nil::marshalling::types::string<
            ///             MyFieldBase,
            ///             nil::marshalling::option::sequence_fixed_size<5>,
            ///             nil::marshalling::option::sequence_trailing_field_suffix<
            ///                 nil::marshalling::types::integral<MyFieldBase, char,
            ///                 nil::marshalling::option::default_num_value<0> >
            ///             >
            ///         >;
            ///     @endcode
            /// @tparam TField Type of the field that represents suffix
            /// @headerfile nil/marshalling/options.hpp
            template<typename TField>
            struct sequence_trailing_field_suffix { };

            /// @brief Option to enable external forcing of the collection's elements count.
            /// @details Sometimes the size information is detached from the data sequence
            ///     itself, i.e. there may be one or more independent fields between the
            ///     size field and the first byte of the collection. In such case it becomes
            ///     impossible to use @ref sequence_size_field_prefix_type option. Instead, the size
            ///     information must be provided by external calls. Usage of this option
            ///     enables @b force_read_elem_count() and @b clear_read_elem_count() functions in
            ///     the collection fields, such as nil::marshalling::types::array_list or
            ///     nil::marshalling::types::string which can be used to specify the size information after it was read
            ///     independently.
            /// @headerfile nil/marshalling/options.hpp
            struct sequence_size_forcing_enabled { };

            /// @brief Option to enable external forcing of the collection's serialization length
            ///     duting "read" operation.
            /// @details Sometimes the length information is detached from the data sequence
            ///     itself, i.e. there may be one or more independent fields between the
            ///     length field and the first byte of the collection. In such case it becomes
            ///     impossible to use @ref sequence_ser_length_field_prefix_type option. Instead, the length
            ///     information must be provided by external calls. Usage of this option
            ///     enables @b force_read_length() and @b clear_read_length_forcing() functions in
            ///     the collection fields, such as nil::marshalling::types::array_list or
            ///     nil::marshalling::types::string which can be used to specify the size information after it was read
            ///     independently.
            /// @headerfile nil/marshalling/options.hpp
            struct sequence_length_forcing_enabled { };

            /// @brief Option to enable external forcing of the collection element
            ///     serialization length.
            /// @details Some protocols may prefix the variable length lists with serialization
            ///     length of a <b>single element</b> in addition to the number of elements
            ///     in the list. Usage of this option
            ///     enables @b force_read_elem_length() and @b clear_read_elem_length_forcing() functions in
            ///     the nil::marshalling::types::array_list
            ///     which can be used to specify the element serialization length after it was read
            ///     independently. @n
            /// @headerfile nil/marshalling/options.hpp
            struct sequence_elem_length_forcing_enabled { };

            /// @brief Option used to define exact number of elements in the collection field.
            /// @details Protocol specification may define that there is exact number of
            ///     elements in the sequence. Use sequence_fixed_size option to convey
            ///     this information to the field definition, which will force @b read() and
            ///     @b write() member functions of the collection field to behave as expected.
            /// @headerfile nil/marshalling/options.hpp
            template<std::size_t TSize>
            struct sequence_fixed_size { };

            /// @brief Option that forces usage of fixed size storage for sequences with fixed
            ///     size.
            /// @details Equivalent to @ref fixed_size_storage option, but applicable only
            ///     to sequence types @ref nil::marshalling::types::array_list or @ref nil::marshalling::types::string,
            ///     that alrady use @ref sequence_fixed_size option. Usage of this option do not require knowledge of
            ///     the storage area size.
            /// @headerfile nil/marshalling/options.hpp
            struct sequence_fixed_size_use_fixed_size_storage { };

            /// @brief Option that specifies default initialisation class.
            /// @details Use this option when default constructor of the field must assign
            ///     some special value. The initialiser class provided as template argument
            ///     must define the following member function:
            ///     @code
            ///     struct MyInitialiser
            ///     {
            ///         template <typename TField>
            ///         void operator()(TField& field) {...}
            ///     };
            ///     @endcode
            ///     For example, we want string field that will have "hello" as its default
            ///     value. The provided initialiser class with the option will be instantiated
            ///     and its operator() is invoked which is responsible to assign proper
            ///     value to the field.
            ///     @code
            ///     struct MyStringInitialiser
            ///     {
            ///         template <typename TField>
            ///         void operator()(TField& field) const
            ///         {
            ///             field.value() = hello;
            ///         }
            ///     };
            ///
            ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///     using MyField =
            ///         nil::marshalling::types::string<
            ///             MyFieldBase,
            ///             nil::marshalling::option::default_value_initializer<MyStringInitialiser>
            ///         >;
            ///     @endcode
            /// @tparam T Type of the initialiser class.
            /// @headerfile nil/marshalling/options.hpp
            template<typename T>
            struct default_value_initialiser { };

            /// @brief Option that specifies custom validation class.
            /// @details By default, value of every field is considered to be valid
            ///     (@b valid() member function of the field returns @b true). If there is a need
            ///     to validate the value of the function, use this option to define
            ///     custom validation logic for the field. The validation class provided as
            ///     a template argument to this option must define the following member function:
            ///     @code
            ///     struct MyValidator
            ///     {
            ///         template <typename TField>
            ///         bool operator()(const TField& field) {...}
            ///     };
            ///     @endcode
            ///     For example, value of the string field considered to be valid if it's
            ///     not empty and starts with '$' character.
            ///     The provided validator class with the option will be instantiated
            ///     and its operator() will be invoked.
            ///     @code
            ///     struct MyStringValidator
            ///     {
            ///         template <typename TField>
            ///         bool operator()(TField& field) const
            ///         {
            ///             auto& str = field.value();
            ///             return (!str.empty()) && (str[0] == '$');
            ///         }
            ///     };
            ///
            ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///     using MyField =
            ///         nil::marshalling::types::string<
            ///             MyFieldBase,
            ///             nil::marshalling::option::contents_validator<MyStringValidator>
            ///         >;
            ///     @endcode
            ///     Note that in the example above the default constructed MyField will
            ///     have invalid value. To fix that you must also use
            ///     nil::marshalling::option::default_value_initializer option to specify proper default
            ///     value.
            /// @tparam T Type of the validator class.
            /// @headerfile nil/marshalling/options.hpp
            template<typename T>
            struct contents_validator { };

            /// @brief Option that specifies custom refreshing class.
            /// @details The "refreshing" functionality is there to allow bringing field's
            ///     contents into a consistent state if it's not. The default "refreshing"
            ///     functionality does nothing and returns @b false (meaning nothing has
            ///     been changed). If there is a need to provide custom refreshing functionality
            ///     use this option and provide custom refresher class. It must
            ///     define the following member function:
            ///     @code
            ///     struct MyRefresher
            ///     {
            ///         template <typename TField>
            ///         bool operator()(TField& field) {
            ///             ... // return true if field's contents changed
            ///         }
            ///     };
            ///     @endcode
            /// @tparam T Type of the refresher class.
            /// @headerfile nil/marshalling/options.hpp
            template<typename T>
            struct contents_refresher { };

            /// @brief Option that specifies custom value reader class.
            /// @details It may be useful to override default reading functionality for complex
            ///     fields, such as nil::marshalling::types::bundle, where the way members are read is
            ///     defined by the values of other members. For example, bundle of two integer
            ///     fields, the first one is normal, and the second one is optional.
            ///     The optional mode of the latter is determined by
            ///     the value of the first field. If its value is 0, than the second
            ///     member exists, otherwise it's missing.
            ///     @code
            ///     typedef nil::marshalling::types::bundle<
            ///         nil::marshalling::field_type<BigEndianOpt>,
            ///         std::tuple<
            ///             nil::marshalling::types::integral<
            ///                 nil::marshalling::field_type<BigEndianOpt>,
            ///                 std::uint8_t
            ///             >,
            ///             nil::marshalling::types::optional<
            ///                 nil::marshalling::types::integral<
            ///                     nil::marshalling::field_type<BigEndianOpt>,
            ///                     std::uint16_t
            ///                 >
            ///             >
            ///         >,
            ///         nil::marshalling::option::custom_value_reader<MyCustomReader>
            ///     > field_type;
            ///     @endcode
            ///     The @b MyCustomReader custom reading class may implement required
            ///     functionality of reading the first member, analysing its value, setting
            ///     appropriate mode for the second one and read the second member.
            ///
            ///     The custom value reader class provided as template argument
            ///     must define the following member function:
            ///     @code
            ///     struct MyCustomReader
            ///     {
            ///         template <typename TField, typename TIter>
            ///         nil::marshalling::ErrorStatus operator()(TField& field, TIter& iter, std::size_t len) {...}
            ///     };
            ///     @endcode
            ///
            ///     The custom reader for the example above may be implemented as:
            ///     @code
            ///     struct MyCustomReader
            ///     {
            ///         template <typename TField, typename TIter>
            ///         nil::marshalling::ErrorStatus operator()(TField& field, TIter& iter, std::size_t len) const
            ///         {
            ///             auto& members = field.value();
            ///             auto& first = std::get<0>(members);
            ///             auto& second = std::get<1>(members);
            ///
            ///             auto es = first.read(iter, len);
            ///             if (es != nil::marshalling::ErrorStatus::Success) {
            ///                 return es;
            ///             }
            ///
            ///             if (first.value() != 0) {
            ///                 second.set_mode(nil::marshalling::types::optional_mode::missing);
            ///             }
            ///             else {
            ///                 second.set_mode(nil::marshalling::types::optional_mode::exists);
            ///             }
            ///
            ///             return second.read(iter, len - first.length());
            ///         }
            ///     };
            ///     @endcode
            /// @tparam T Type of the custom reader class.
            /// @headerfile nil/marshalling/options.hpp
            template<typename T>
            struct custom_value_reader { };

            /// @brief Option that forces field's read operation to fail if invalid value
            ///     is received.
            /// @details Sometimes protocol is very strict about what field's values are
            ///     allowed and forces to abandon a message if invalid value is received.
            ///     If nil::marshalling::option::fail_on_invalid is provided as an option to a field,
            ///     the validity is going to checked automatically after the read. If invalid
            ///     value is identified, error will be returned from the @b read() operation.
            /// @tparam TStatus Error status to return when the content of the read field is invalid.
            /// @headerfile nil/marshalling/options.hpp
            template<status_type TStatus = status_type::invalid_msg_data>
            struct fail_on_invalid { };

            /// @brief Option that forces field's read operation to ignore read data if invalid value
            ///     is received.
            /// @details If this option is provided to the field, the read operation will
            ///     check the validity of the read value. If it is identified as invalid,
            ///     the read value is not assigned to the field, i.e. the field's value
            ///     remains unchanged, although no error is reported.
            /// @headerfile nil/marshalling/options.hpp
            struct ignore_invalid { };

            /// @brief Force the destructor of nil::marshalling::message class to be @b non-virtual,
            ///     even if there are other virtual functions defined.
            /// @headerfile nil/marshalling/options.hpp
            struct no_virtual_destructor { };

            /// @brief options to specify units of the field.
            /// @tparam TType Type of the unints, can be any type from nil::marshalling::traits::units
            ///     namespace.
            /// @tparam TRatio Ratio within the units type, must be a variant of
            ///     @b std::ratio type.
            /// @headerfile nil/marshalling/options.hpp
            template<typename TType, typename TRatio>
            struct units {
                static_assert(detail::is_ratio_t<TRatio>(), "TRatio parameter must be a variant of std::ratio");

                static_assert(TRatio::num != 0, "Wrong ratio value");
                static_assert(TRatio::den != 0, "Wrong ratio value");
            };

            /// @brief Alias option, specifying field value units are "nanoseconds".
            /// @headerfile nil/marshalling/options.hpp
            using units_nanoseconds
                = units<nil::marshalling::traits::units::Time, nil::marshalling::traits::units::nanoseconds_ratio>;

            /// @brief Alias option, specifying field value units are "microseconds".
            /// @headerfile nil/marshalling/options.hpp
            using units_microseconds
                = units<nil::marshalling::traits::units::Time, nil::marshalling::traits::units::microseconds_ratio>;

            /// @brief Alias option, specifying field value units are "milliseconds".
            /// @headerfile nil/marshalling/options.hpp
            using units_milliseconds
                = units<nil::marshalling::traits::units::Time, nil::marshalling::traits::units::milliseconds_ratio>;

            /// @brief Alias option, specifying field value units are "seconds".
            /// @headerfile nil/marshalling/options.hpp
            using units_seconds
                = units<nil::marshalling::traits::units::Time, nil::marshalling::traits::units::seconds_ratio>;

            /// @brief Alias option, specifying field value units are "minutes".
            /// @headerfile nil/marshalling/options.hpp
            using units_minutes
                = units<nil::marshalling::traits::units::Time, nil::marshalling::traits::units::minutes_ratio>;

            /// @brief Alias option, specifying field value units are "hours".
            /// @headerfile nil/marshalling/options.hpp
            using units_hours
                = units<nil::marshalling::traits::units::Time, nil::marshalling::traits::units::hours_ratio>;

            /// @brief Alias option, specifying field value units are "days".
            /// @headerfile nil/marshalling/options.hpp
            using units_days
                = units<nil::marshalling::traits::units::Time, nil::marshalling::traits::units::days_ratio>;

            /// @brief Alias option, specifying field value units are "weeks".
            /// @headerfile nil/marshalling/options.hpp
            using units_weeks
                = units<nil::marshalling::traits::units::Time, nil::marshalling::traits::units::weeks_ratio>;

            /// @brief Alias option, specifying field value units are "nanometers".
            /// @headerfile nil/marshalling/options.hpp
            using units_nanometers
                = units<nil::marshalling::traits::units::distance, nil::marshalling::traits::units::nanometers_ratio>;

            /// @brief Alias option, specifying field value units are "micrometers".
            /// @headerfile nil/marshalling/options.hpp
            using units_micrometers
                = units<nil::marshalling::traits::units::distance, nil::marshalling::traits::units::micrometers_ratio>;

            /// @brief Alias option, specifying field value units are "millimeters".
            /// @headerfile nil/marshalling/options.hpp
            using units_millimeters
                = units<nil::marshalling::traits::units::distance, nil::marshalling::traits::units::millimeters_ratio>;

            /// @brief Alias option, specifying field value units are "centimeters".
            /// @headerfile nil/marshalling/options.hpp
            using units_centimeters
                = units<nil::marshalling::traits::units::distance, nil::marshalling::traits::units::centimeters_ratio>;

            /// @brief Alias option, specifying field value units are "meters".
            /// @headerfile nil/marshalling/options.hpp
            using units_meters
                = units<nil::marshalling::traits::units::distance, nil::marshalling::traits::units::meters_ratio>;

            /// @brief Alias option, specifying field value units are "kilometers".
            /// @headerfile nil/marshalling/options.hpp
            using units_kilometers
                = units<nil::marshalling::traits::units::distance, nil::marshalling::traits::units::kilometers_ratio>;

            /// @brief Alias option, specifying field value units are "nanometers per second".
            /// @headerfile nil/marshalling/options.hpp
            using units_nanometers_per_second = units<nil::marshalling::traits::units::speed,
                                                      nil::marshalling::traits::units::nanometers_per_second_ratio>;

            /// @brief Alias option, specifying field value units are "micrometers per second".
            /// @headerfile nil/marshalling/options.hpp
            using units_micrometers_per_second = units<nil::marshalling::traits::units::speed,
                                                       nil::marshalling::traits::units::micrometers_per_second_ratio>;

            /// @brief Alias option, specifying field value units are "millimeters per second".
            /// @headerfile nil/marshalling/options.hpp
            using units_millimeters_per_second = units<nil::marshalling::traits::units::speed,
                                                       nil::marshalling::traits::units::millimeters_per_second_ratio>;

            /// @brief Alias option, specifying field value units are "centimeters per second".
            /// @headerfile nil/marshalling/options.hpp
            using units_centimeters_per_second = units<nil::marshalling::traits::units::speed,
                                                       nil::marshalling::traits::units::centimeters_per_second_ratio>;

            /// @brief Alias option, specifying field value units are "meters per second".
            /// @headerfile nil/marshalling/options.hpp
            using units_meters_per_second = units<nil::marshalling::traits::units::speed,
                                                  nil::marshalling::traits::units::meters_per_second_ratio>;

            /// @brief Alias option, specifying field value units are "kilometers per second".
            /// @headerfile nil/marshalling/options.hpp
            using units_kilometers_per_second = units<nil::marshalling::traits::units::speed,
                                                      nil::marshalling::traits::units::kilometers_per_second_ratio>;

            /// @brief Alias option, specifying field value units are "kilometers per hour".
            /// @headerfile nil/marshalling/options.hpp
            using units_kilometers_per_hour = units<nil::marshalling::traits::units::speed,
                                                    nil::marshalling::traits::units::kilometers_per_hour_ratio>;

            /// @brief Alias option, specifying field value units are "hertz".
            /// @headerfile nil/marshalling/options.hpp
            using units_hertz
                = units<nil::marshalling::traits::units::frequency, nil::marshalling::traits::units::hz_ratio>;

            /// @brief Alias option, specifying field value units are "kilohertz".
            /// @headerfile nil/marshalling/options.hpp
            using units_kilohertz
                = units<nil::marshalling::traits::units::frequency, nil::marshalling::traits::units::kilo_hz_ratio>;

            /// @brief Alias option, specifying field value units are "megahertz".
            /// @headerfile nil/marshalling/options.hpp
            using units_megahertz
                = units<nil::marshalling::traits::units::frequency, nil::marshalling::traits::units::mega_hz_ratio>;

            /// @brief Alias option, specifying field value units are "gigahertz".
            /// @headerfile nil/marshalling/options.hpp
            using units_gigahertz
                = units<nil::marshalling::traits::units::frequency, nil::marshalling::traits::units::giga_hz_ratio>;

            /// @brief Alias option, specifying field value units are "degrees".
            /// @headerfile nil/marshalling/options.hpp
            using units_degrees
                = units<nil::marshalling::traits::units::angle, nil::marshalling::traits::units::degrees_ratio>;

            /// @brief Alias option, specifying field value units are "radians".
            /// @headerfile nil/marshalling/options.hpp
            using units_radians
                = units<nil::marshalling::traits::units::angle, nil::marshalling::traits::units::radians_ratio>;

            /// @brief Alias option, specifying field value units are "nanoamps".
            /// @headerfile nil/marshalling/options.hpp
            using units_nanoamps
                = units<nil::marshalling::traits::units::current, nil::marshalling::traits::units::nanoamps_ratio>;

            /// @brief Alias option, specifying field value units are "microamps".
            /// @headerfile nil/marshalling/options.hpp
            using units_microamps
                = units<nil::marshalling::traits::units::current, nil::marshalling::traits::units::microamps_ratio>;

            /// @brief Alias option, specifying field value units are "milliamps".
            /// @headerfile nil/marshalling/options.hpp
            using units_milliamps
                = units<nil::marshalling::traits::units::current, nil::marshalling::traits::units::milliamps_ratio>;

            /// @brief Alias option, specifying field value units are "amps".
            /// @headerfile nil/marshalling/options.hpp
            using units_amps
                = units<nil::marshalling::traits::units::current, nil::marshalling::traits::units::amps_ratio>;

            /// @brief Alias option, specifying field value units are "kiloamps".
            /// @headerfile nil/marshalling/options.hpp
            using units_kiloamps
                = units<nil::marshalling::traits::units::current, nil::marshalling::traits::units::kiloamps_ratio>;

            /// @brief Alias option, specifying field value units are "nanovolts".
            /// @headerfile nil/marshalling/options.hpp
            using units_nanovolts
                = units<nil::marshalling::traits::units::voltage, nil::marshalling::traits::units::nanovolts_ratio>;

            /// @brief Alias option, specifying field value units are "microvolts".
            /// @headerfile nil/marshalling/options.hpp
            using units_microvolts
                = units<nil::marshalling::traits::units::voltage, nil::marshalling::traits::units::microvolts_ratio>;

            /// @brief Alias option, specifying field value units are "millivolts".
            /// @headerfile nil/marshalling/options.hpp
            using units_millivolts
                = units<nil::marshalling::traits::units::voltage, nil::marshalling::traits::units::millivolts_ratio>;

            /// @brief Alias option, specifying field value units are "volts".
            /// @headerfile nil/marshalling/options.hpp
            using units_volts
                = units<nil::marshalling::traits::units::voltage, nil::marshalling::traits::units::volts_ratio>;

            /// @brief Alias option, specifying field value units are "kilovolts".
            /// @headerfile nil/marshalling/options.hpp
            using units_kilovolts
                = units<nil::marshalling::traits::units::voltage, nil::marshalling::traits::units::kilovolts_ratio>;

            namespace detail {

                template<typename T, T TVal>
                struct default_num_value_initialiser {
                    template<typename TField>
                    void operator()(TField &&field) {
                        using field_type = typename std::decay<TField>::type;
                        using value_type = typename field_type::value_type;
                        field.value() = static_cast<value_type>(TVal);
                    }
                };

                template<std::intmax_t TMinValue, std::intmax_t TMaxValue>
                struct num_value_range_validator {
                    static_assert(TMinValue <= TMaxValue, "Min value must be not greater than Max value");

                    template<typename TField>
                    constexpr bool operator()(const TField &field) const {
                        using MinTag =
                            typename std::conditional<(std::numeric_limits<decltype(MinValue)>::min() < MinValue),
                                                      compare_tag, return_true_tag>::type;

                        using MaxTag =
                            typename std::conditional<(MaxValue < std::numeric_limits<decltype(MaxValue)>::max()),
                                                      compare_tag, return_true_tag>::type;

                        return above_min(field.value(), MinTag()) && below_max(field.value(), MaxTag());
                    }

                private:
                    struct return_true_tag { };
                    struct compare_tag { };

                    template<typename TValue>
                    static constexpr bool above_min(const TValue &value, compare_tag) {
                        using value_type = typename std::decay<decltype(value)>::type;
                        return (static_cast<value_type>(MinValue) <= static_cast<value_type>(value));
                    }

                    template<typename TValue>
                    static constexpr bool above_min(const TValue &, return_true_tag) {
                        return true;
                    }

                    template<typename TValue>
                    static constexpr bool below_max(const TValue &value, compare_tag) {
                        using value_type = typename std::decay<decltype(value)>::type;
                        return (value <= static_cast<value_type>(MaxValue));
                    }

                    template<typename TValue>
                    static constexpr bool below_max(const TValue &, return_true_tag) {
                        return true;
                    }

                    static const auto MinValue = TMinValue;
                    static const auto MaxValue = TMaxValue;
                };

                template<std::uintmax_t TMask, std::uintmax_t TValue>
                struct bitmask_reserved_bits_validator {
                    template<typename TField>
                    constexpr bool operator()(TField &&field) const {
                        using field_type = typename std::decay<TField>::type;
                        using value_type = typename field_type::value_type;

                        return (field.value() & static_cast<value_type>(TMask)) == static_cast<value_type>(TValue);
                    }
                };

                template<nil::marshalling::types::optional_mode TVal>
                struct default_opt_mode_initialiser {
                    template<typename TField>
                    void operator()(TField &field) const {
                        field.set_mode(TVal);
                    }
                };

                template<std::size_t TIdx>
                struct default_variant_index_initialiser {
                    template<typename TField>
                    void operator()(TField &field) {
                        field.template init_field<TIdx>();
                    }
                };

            }    // namespace detail

            /// @brief Alias to default_value_initializer, it defines initialiser class that
            ///     assigns numeric value provided as the template argument to this option.
            /// @details If the required numeric value is too big (doesn't fit into @b
            ///     std::intmax_t type), please use @ref DefaultBigUnsignedNumValue option
            ///     class instead.
            /// @tparam TVal Numeric value is to be assigned to the field in default constructor.
            /// @see @ref DefaultBigUnsignedNumValue
            /// @headerfile nil/marshalling/options.hpp
            template<std::intmax_t TVal>
            using default_num_value
                = default_value_initialiser<detail::default_num_value_initialiser<std::intmax_t, TVal>>;

            /// @brief Alias to default_value_initializer, it defines initialiser class that
            ///     assigns big unsigned numeric value provided as the template argument to this option.
            /// @details If the required numeric value is small enough to fit into @b
            ///     std::intmax_t type, it is recommended to use @ref default_num_value option
            ///     class instead.
            /// @tparam TVal Numeric value is to be assigned to the field in default constructor.
            /// @see @ref DefaultBigUnsignedNumValue
            /// @headerfile nil/marshalling/options.hpp
            template<std::uintmax_t TVal>
            using default_big_unsigned_num_value
                = default_value_initialiser<detail::default_num_value_initialiser<std::uintmax_t, TVal>>;

            /// @brief Provide range of valid numeric values.
            /// @details Quite often numeric fields such as nil::marshalling::types::integral or
            ///     nil::marshalling::types::enumeration have limited number of valid values ranges.
            ///     This option can be used multiple times to provide several valid ranges.@n
            ///     If values are too big to fit into @b std::intmax_t type, please use
            ///     @ref ValidBigUnsignedNumValueRange option instead.
            /// @tparam TMinValue Minimal valid numeric value
            /// @tparam TMaxValue Maximal valid numeric value
            /// @note The intersection of the provided multiple ranges is @b NOT checked.
            /// @warning Some older compilers (@b gcc-4.7) fail to compile valid C++11 code
            ///     that allows usage of multiple @ref valid_num_value_range options. If this is
            ///     the case, please don't pass more than one @ref valid_num_value_range option.
            /// @see @ref ValidNumValue
            /// @see @ref ValidBigUnsignedNumValueRange
            /// @headerfile nil/marshalling/options.hpp
            template<std::intmax_t TMinValue, std::intmax_t TMaxValue>
            struct valid_num_value_range {
                static_assert(TMinValue <= TMaxValue, "Invalid range");
            };

            /// @brief Clear accumulated ranges of valid values.
            struct valid_ranges_clear { };

            /// @brief Similar to @ref valid_num_value_range, but overrides (nullifies)
            ///     all previously set valid values ranges.
            /// @see @ref ValidNumValueOverride
            /// @see @ref ValidBigUnsignedNumValueRangeOverride
            /// @deprecated Use @ref valid_ranges_clear instead.
            template<std::intmax_t TMinValue, std::intmax_t TMaxValue>
            using valid_num_value_range_override
                = std::tuple<valid_num_value_range<TMinValue, TMaxValue>, valid_ranges_clear>;

            /// @brief Alias to @ref valid_num_value_range.
            /// @details Equivalent to @b valid_num_value_range<TValue, TValue>
            template<std::intmax_t TValue>
            using valid_num_value = valid_num_value_range<TValue, TValue>;

            /// @brief Alias to @ref valid_num_value_rangeOverride.
            /// @details Equivalent to @b valid_num_value_rangeOverride<TValue, TValue>
            /// @deprecated Use @ref valid_ranges_clear instead.
            template<std::intmax_t TValue>
            using valid_num_value_override = valid_num_value_range_override<TValue, TValue>;

            /// @brief Provide range of valid unsigned numeric values.
            /// @details Similar to @ref valid_num_value_range, but dedicated to
            ///     big unsigned numbers, which don't fit into @b std::intmax_t type.
            /// @tparam TMinValue Minimal valid numeric value
            /// @tparam TMaxValue Maximal valid numeric value
            /// @note The intersection of the provided multiple ranges is @b NOT checked.
            /// @warning Some older compilers (@b gcc-4.7) fail to compile valid C++11 code
            ///     that allows usage of multiple @ref valid_num_value_range options. If this is
            ///     the case, please don't pass more than one
            ///     @ref valid_num_value_range or @ref ValidBigUnsignedNumValueRange option.
            /// @see @ref valid_num_value_range
            /// @see @ref ValidBigUnsignedNumValue
            /// @headerfile nil/marshalling/options.hpp
            template<std::uintmax_t TMinValue, std::uintmax_t TMaxValue>
            struct valid_big_unsigned_num_value_range {
                static_assert(TMinValue <= TMaxValue, "Invalid range");
            };

            /// @brief Similar to @ref ValidBigUnsignedNumValueRange, but overrides (nullifies)
            ///     all previously set valid values ranges.
            /// @see @ref ValidNumValueOverride
            /// @see @ref ValidBigUnsignedNumValueOverride
            /// @deprecated Use @ref valid_ranges_clear instead.
            template<std::uintmax_t TMinValue, std::uintmax_t TMaxValue>
            using valid_big_unsigned_num_value_range_override
                = std::tuple<valid_big_unsigned_num_value_range<TMinValue, TMaxValue>, valid_ranges_clear>;

            /// @brief Alias to @ref ValidBigUnsignedNumValueRange.
            /// @details Equivalent to @b ValidBigUnsignedNumValueRange<TValue, TValue>
            template<std::uintmax_t TValue>
            using valid_big_unsigned_num_value = valid_big_unsigned_num_value_range<TValue, TValue>;

            /// @brief Alias to @ref ValidBigUnsignedNumValueRangeOverride.
            /// @details Equivalent to @b ValidBigUnsignedNumValueRangeOverride<TValue, TValue>
            /// @deprecated Use @ref valid_ranges_clear instead.
            template<std::uintmax_t TValue>
            using valid_big_unsigned_num_value_override = valid_big_unsigned_num_value_range_override<TValue, TValue>;

            /// @brief Alias to contents_validator, it defines validator class that checks
            ///     that reserved bits of the field have expected values.
            /// @details It is usually used with nil::marshalling::types::BitmaskValue field to
            ///     specify values of the unused/reserved bits.
            ///     The custom validator will return true if
            ///     @code
            ///     (field.value() & TMask) == TValue
            ///     @endcode
            /// @tparam TMask Mask that specifies reserved bits.
            /// @tparam TValue Expected value of the reserved bits. Defaults to 0.
            /// @headerfile nil/marshalling/options.hpp
            template<std::uintmax_t TMask, std::uintmax_t TValue = 0U>
            using bitmask_reserved_bits = contents_validator<detail::bitmask_reserved_bits_validator<TMask, TValue>>;

            /// @brief Alias to default_value_initializer, it sets default mode
            ///     to types::optional field.
            /// @tparam TVal optional mode value is to be assigned to the field in default constructor.
            /// @see @ref MissingByDefault
            /// @see @ref ExistsByDefault
            /// @headerfile nil/marshalling/options.hpp
            template<nil::marshalling::types::optional_mode TVal>
            using default_optional_mode = default_value_initialiser<detail::default_opt_mode_initialiser<TVal>>;

            /// @brief Alias to @ref DefaultOptionalMode.
            /// @details Equivalent to
            ///     @code
            ///     DefaultOptionalMode<nil::marshalling::types::optional_mode::missing>
            ///     @endcode
            using missing_by_default = default_optional_mode<nil::marshalling::types::optional_mode::missing>;

            /// @brief Alias to @ref DefaultOptionalMode.
            /// @details Equivalent to
            ///     @code
            ///     DefaultOptionalMode<nil::marshalling::types::optional_mode::exists>
            ///     @endcode
            using exists_by_default = default_optional_mode<nil::marshalling::types::optional_mode::exists>;

            /// @brief Alias to DefaultOptionalMode<nil::marshalling::types::OptinalMode::missing>
            using optional_missing_by_default = missing_by_default;

            /// @brief Alias to DefaultOptionalMode<nil::marshalling::types::OptinalMode::exists>
            using optional_exists_by_default = exists_by_default;

            /// @brief Alias to default_value_initializer, it initalises nil::marshalling::types::variant field
            ///     to contain valid default value of the specified member.
            /// @tparam TIdx Index of the default member.
            /// @headerfile nil/marshalling/options.hpp
            template<std::size_t TIdx>
            using default_variant_index = default_value_initialiser<detail::default_variant_index_initialiser<TIdx>>;

            /// @brief Force nil::marshalling::protocol::ChecksumLayer and
            ///     nil::marshalling::protocol::ChecksumPrefixLayer, to verify checksum prior to
            ///     forwarding read to the wrapped layer(s).
            /// @headerfile nil/marshalling/options.hpp
            struct checksum_layer_verify_before_read { };

            /// @brief Use "view" on original raw data instead of copying it.
            /// @details Can be used with @ref nil::marshalling::types::string and raw data @ref
            /// nil::marshalling::types::array_list,
            ///     will force usage of @ref nil::marshalling::container::string_view and
            ///     nil::marshalling::container::array_view respectively as data storage type.
            /// @note The original data must be preserved until destruction of the field
            ///     that uses the "view".
            /// @note Incompatible with other options that contol data storage type,
            ///     such as @ref nil::marshalling::option::custom_storage_type or @ref
            ///     nil::marshalling::option::fixed_size_storage
            /// @headerfile nil/marshalling/options.hpp
            struct orig_data_view { };

            /// @brief Force field not to be serialized during read/write operations
            /// @details Some protocols may define some constant values that are predefined
            ///     and are not present on I/O link when serialized. Sometimes it is convenient
            ///     to have such values abstracted away as fields, which are not actually
            ///     serialized. Using this option will have such effect: read/write operaitons
            ///     will not change the value of iterators and will report immediate success.
            ///     The serialization length is always reported as 0.
            /// @headerfile nil/marshalling/options.hpp
            struct empty_serialization { };

            /// @brief Option to force @ref nil::marshalling::protocol::ProtocolLayerBase class to
            ///     split read operation "until" and "from" data (payload) layer.
            /// @details Can be used by some layers which require its read operation to be
            ///     fully complete before read is forwared to data layer, i.e. until message
            ///     contents being read.
            /// @headerfile nil/marshalling/options.hpp
            struct protocol_layer_force_read_until_data_split { };

            /// @brief Disallow usage of @ref ProtocolLayerForceReadUntilDataSplit option in
            ///     earlier (outer wrapping) layers.
            /// @details Some layers, such as @ref nil::marshalling::protocol::ChecksumLayer cannot
            ///     split their "read" operation to "until" and "from" data layer. They can
            ///     use this option to prevent outer layers from using
            ///     @ref ProtocolLayerForceReadUntilDataSplit one.
            /// @headerfile nil/marshalling/options.hpp
            struct protocol_layer_disallow_read_until_data_split { };

            /// @brief Mark this class to have custom
            ///     implementation of @b read functionality.
            /// @headerfile nil/marshalling/options.hpp
            struct has_custom_read { };

            /// @brief Mark this class to have custom
            ///     implementation of @b refresh functionality.
            /// @headerfile nil/marshalling/options.hpp
            struct has_custom_refresh { };

            /// @brief Mark this class as providing its name information
            /// @headerfile nil/marshalling/options.hpp
            struct has_name { };

            /// @brief Option that notifies nil::marshalling::message_base about existence of
            ///     custom refresh functionality in derived class.
            /// @details Alias to @ref has_custom_refresh for backward compatibility.
            /// @deprecated Use @ref has_custom_refresh instead.
            /// @headerfile nil/marshalling/options.hpp
            using has_do_refresh = has_custom_refresh;

            /// @brief Option for @ref nil::marshalling::protocol::TransportValueLayer to
            ///     mark that the handled field is a "pseudo" one, i.e. is not serialized.
            struct pseudo_value { };

            /// @brief Provide type to be used for versioning
            /// @tparam T Type of the version value. Expected to be unsigned integral one.
            template<typename T>
            struct version_type {
                static_assert(std::is_integral<T>::value, "Only unsigned integral types are supported for versions");
                static_assert(std::is_unsigned<T>::value, "Only unsigned integral types are supported for versions");
            };

            /// @brief Mark this class to have custom
            ///     implementation of version update functionality.
            /// @headerfile nil/marshalling/options.hpp
            struct has_custom_version_update { };

            /// @brief Mark an @ref nil::marshalling::types::optional field as existing
            ///     between specified versions.
            /// @tparam TFrom First version when field has been added
            /// @tparam TUntil Last version when field still hasn't been removed.
            /// @pre @b TFrom <= @b TUntil
            template<std::uintmax_t TFrom, std::uintmax_t TUntil>
            struct exists_between_versions {
                static_assert(TFrom <= TUntil, "Invalid version parameters");
            };

            /// @brief Mark an @ref nil::marshalling::types::optional field as existing
            ///     starting from specified version.
            /// @details Alias to @ref ExistsBetweenVersions
            /// @tparam TVer First version when field has been added
            template<std::uintmax_t TVer>
            using exists_since_version = exists_between_versions<TVer, std::numeric_limits<std::uintmax_t>::max()>;

            /// @brief Mark an @ref nil::marshalling::types::optional field as existing
            ///     only until specified version.
            /// @details Alias to @ref ExistsBetweenVersions
            /// @tparam TVer Last version when field still hasn't been removed.
            template<std::uintmax_t TVer>
            using exists_until_version = exists_between_versions<0, TVer>;

            /// @brief Make the field's contents to be invalid by default.
            struct invalid_by_default { };

            /// @brief Add storage of version information inside private data members.
            /// @details The version information can be accessed using @b get_version() member function.
            struct version_storage { };

        }    // namespace option
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_OPTIONS_HPP
