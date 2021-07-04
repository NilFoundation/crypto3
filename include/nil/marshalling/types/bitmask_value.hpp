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

#ifndef MARSHALLING_BITMASK_VALUE_HPP
#define MARSHALLING_BITMASK_VALUE_HPP

#include <limits>

#include <nil/marshalling/types/detail/options_parser.hpp>
#include <nil/marshalling/detail/gen_enum.hpp>
#include <nil/marshalling/detail/bits_access.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/tag.hpp>
#include <nil/marshalling/types/bitmask_value/behaviour.hpp>

namespace nil {
    namespace marshalling {
        namespace types {

            /// @brief Bitmask value field.
            /// @details Quite often communication protocols specify bitmask values, where
            ///     any bit has a specific meaning. Although such masks are can be handled
            ///     as unsigned integer values using nil::marshalling::types::integral field type,
            ///     using nil::marshalling::types::Bitmask may be a bit more convenient.
            /// @tparam TFieldBase Base class for this field, expected to be a variant of
            ///     nil::marshalling::field_type.
            /// @tparam TOptions Zero or more options that modify/refine default behaviour
            ///     of the field. If no option is provided, the underlying type is assumed
            ///     to be "unsigned", which is usually 4 bytes long. To redefined the length
            ///     of the bitmask field, use nil::marshalling::option::fixed_length option.
            ///     For example:
            ///     @code
            ///         using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///         using MyField =nil::marshalling::types::enumeration<MyFieldBase>;
            ///     @endcode
            ///     The serialized value of the field in the example above will consume
            ///     sizeof(unsigned) bytes, because the underlying type chosen to be "unsigned"
            ///     by default. Example below specifies simple bitmask value field with
            ///     2 bytes serialization length:
            ///     @code
            ///         using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
            ///         using MyField =nil::marshalling::types::enumeration<MyFieldBase,
            ///         nil::marshalling::option::fixed_length<2> >;
            ///     @endcode
            ///     Supported options are:
            ///     @li @ref nil::marshalling::option::fixed_length
            ///     @li @ref nil::marshalling::option::fixed_bit_length
            ///     @li @ref nil::marshalling::option::default_value_initializer or
            ///     nil::marshalling::option::default_num_value.
            ///     @li @ref nil::marshalling::option::contents_validator or
            ///     nil::marshalling::option::BitmaskReservedBits.
            ///     @li @ref nil::marshalling::option::contents_refresher
            ///     @li @ref nil::marshalling::option::has_custom_read
            ///     @li @ref nil::marshalling::option::has_custom_refresh
            ///     @li @ref nil::marshalling::option::fail_on_invalid
            ///     @li @ref nil::marshalling::option::ignore_invalid
            ///     @li @ref nil::marshalling::option::empty_serialization
            ///     @li @ref nil::marshalling::option::version_storage
            /// @extends nil::marshalling::field_type
            /// @headerfile nil/marshalling/types/bitmask_value.hpp
            /// @see MARSHALLING_BITMASK_BITS()
            /// @see MARSHALLING_BITMASK_BITS_ACCESS()
            /// @see MARSHALLING_BITMASK_BITS_ACCESS_NOTEMPLATE()
            /// @see MARSHALLING_BITMASK_BITS_SEQ()
            /// @see MARSHALLING_BITMASK_BITS_SEQ_NOTEMPLATE()
            template<typename TFieldBase, typename... TOptions>
            class bitmask_value : public TFieldBase {
                using base_impl_type = TFieldBase;
            public:
                /// @brief endian_type used for serialization.
                using endian_type = typename base_impl_type::endian_type;

                /// @brief Version type
                using version_type = typename base_impl_type::version_type;

                /// @brief All the options provided to this class bundled into struct.
                using parsed_options_type = detail::options_parser<TOptions...>;

            private:
                
                using bitmask_behaviour_type = 
                    detail::bitmask_undertlying_type_type<parsed_options_type>;

                using integral_type = 
                    integral<TFieldBase, bitmask_behaviour_type, TOptions...>;

            public:

                /// @brief Tag indicating type of the field
                using tag = tag::bitmask;

                /// @brief Type of underlying integral value.
                /// @details Unsigned integral type, which depends on the length of the
                ///     mask determined by the nil::marshalling::option::fixed_length option.
                using value_type = typename integral_type::value_type;

                /// @brief Default constructor.
                /// @brief Initial bitmask has all bits cleared (equals 0)
                bitmask_value() = default;

                /// @brief Constructor
                /// @param[in] val Value of the field to initialise it with.
                explicit bitmask_value(const value_type &val) : intValue_(val) {
                }

                /// @brief Copy constructor
                bitmask_value(const bitmask_value &) = default;

                /// @brief Destructor
                ~bitmask_value() noexcept = default;

                /// @brief Copy assignment
                bitmask_value &operator=(const bitmask_value &) = default;

                /// @brief Get access to underlying mask value storage.
                /// @return Const reference to the underlying stored value.
                const value_type &value() const {
                    return intValue_.value();
                }

                /// @brief Get access to underlying mask value storage.
                /// @return Reference to the underlying stored value.
                value_type &value() {
                    return intValue_.value();
                }

                /// @brief Get length required to serialise the current field value.
                /// @return Number of bytes it will take to serialise the field value.
                constexpr std::size_t length() const {
                    return intValue_.length();
                }

                /// @brief Get maximal length that is required to serialise field of this type.
                /// @return Maximal number of bytes required serialise the field value.
                static constexpr std::size_t max_length() {
                    return integral_type::max_length();
                }

                /// @brief Get minimal length that is required to serialise field of this type.
                /// @return Minimal number of bytes required serialise the field value.
                static constexpr std::size_t min_length() {
                    return integral_type::min_length();
                }

                /// @brief Read field value from input data sequence
                /// @param[in, out] iter Iterator to read the data.
                /// @param[in] size Number of bytes available for reading.
                /// @return Status of read operation.
                /// @post Iterator is advanced.
                template<typename TIter>
                status_type read(TIter &iter, std::size_t size) {
                    return intValue_.read(iter, size);
                }

                /// @brief Read field value from input data sequence without error check and status report.
                /// @details Similar to @ref read(), but doesn't perform any correctness
                ///     checks and doesn't report any failures.
                /// @param[in, out] iter Iterator to read the data.
                /// @post Iterator is advanced.
                template<typename TIter>
                void read_no_status(TIter &iter) {
                    intValue_.read_no_status(iter);
                }

                /// @brief Write current field value to output data sequence
                /// @param[in, out] iter Iterator to write the data.
                /// @param[in] size Maximal number of bytes that can be written.
                /// @return Status of write operation.
                /// @post Iterator is advanced.
                template<typename TIter>
                status_type write(TIter &iter, std::size_t size) const {
                    return intValue_.write(iter, size);
                }

                /// @brief Write current field value to output data sequence  without error check and status report.
                /// @details Similar to @ref write(), but doesn't perform any correctness
                ///     checks and doesn't report any failures.
                /// @param[in, out] iter Iterator to write the data.
                /// @post Iterator is advanced.
                template<typename TIter>
                void write_no_status(TIter &iter) const {
                    intValue_.write_no_status(iter);
                }

                /// @brief Check validity of the field value.
                constexpr bool valid() const {
                    return intValue_.valid();
                }

                /// @brief Refresh contents of the field
                /// @return @b true in case the field's value has been updated, @b false otherwise
                bool refresh() {
                    return intValue_.refresh();
                }

                /// @brief Check whether all bits from provided mask are set.
                /// @param[in] mask Mask to check against
                /// @return true in case all the bits are set, false otherwise
                bool has_all_bits_set(value_type mask) const {
                    return (value() & mask) == mask;
                }

                /// @brief Check whether any bits from provided mask are set.
                /// @param[in] mask Mask to check against
                /// @return true in case at least one of the bits is set, false otherwise.
                bool has_any_bits_set(value_type mask) const {
                    return (value() & mask) != 0;
                }

                /// @brief Set all the provided bits.
                /// @details Equivalent to @code value() |= mask; @endcode
                /// @param[in] mask Mask of bits to set.
                void set_bits(value_type mask) {
                    value() |= mask;
                }

                /// @brief Set all the provided bits.
                /// @details Equivalent to @code value() &= (~mask); @endcode
                /// @param[in] mask Mask of bits to clear.
                void clear_bits(value_type mask) {
                    value() &= (~mask);
                }

                /// @brief Get bit value
                bool get_bit_value(unsigned bitNum) const {
                    return has_all_bits_set(static_cast<value_type>(1U) << bitNum);
                }

                /// @brief Set bit value
                void set_bit_value(unsigned bitNum, bool val) {
                    auto mask = static_cast<value_type>(1U) << bitNum;
                    if (val) {
                        set_bits(mask);
                    } else {
                        clear_bits(mask);
                    }
                }

                /// @brief Compile time check if this class is version dependent
                static constexpr bool is_version_dependent() {
                    return integral_type::is_version_dependent();
                }

                /// @brief Get version of the field.
                /// @details Exists only if @ref nil::marshalling::option::version_storage option has been provided.
                version_type get_version() const {
                    return intValue_.get_version();
                }

                /// @brief Default implementation of version update.
                /// @return @b true in case the field contents have changed, @b false otherwise
                bool set_version(version_type version) {
                    return intValue_.set_version(version);
                }

            protected:
                using base_impl_type::read_data;
                using base_impl_type::write_data;

            private:
                static_assert(
                    !parsed_options_type::has_ser_offset,
                    "nil::marshalling::option::num_value_ser_offset option is not applicable to bitmask_value field");
                static_assert(!parsed_options_type::has_var_length_limits,
                              "nil::marshalling::option::var_length option is not applicable to bitmask_value field");
                static_assert(!parsed_options_type::has_sequence_elem_length_forcing,
                              "nil::marshalling::option::SequenceElemLengthForcingEnabled option is not applicable to "
                              "bitmask_value field");
                static_assert(!parsed_options_type::has_sequence_size_forcing,
                              "nil::marshalling::option::SequenceSizeForcingEnabled option is not applicable to "
                              "bitmask_value field");
                static_assert(!parsed_options_type::has_sequence_length_forcing,
                              "nil::marshalling::option::SequenceLengthForcingEnabled option is not applicable to "
                              "bitmask_value field");
                static_assert(
                    !parsed_options_type::has_sequence_fixed_size,
                    "nil::marshalling::option::sequence_fixed_size option is not applicable to bitmask_value field");
                static_assert(
                    !parsed_options_type::has_sequence_fixed_size_use_fixed_size_storage,
                    "nil::marshalling::option::SequenceFixedSizeUseFixedSizeStorage option is not applicable to "
                    "bitmask_value field");
                static_assert(!parsed_options_type::has_sequence_size_field_prefix,
                              "nil::marshalling::option::sequence_size_field_prefix option is not applicable to "
                              "bitmask_value field");
                static_assert(!parsed_options_type::has_sequence_ser_length_field_prefix,
                              "nil::marshalling::option::sequence_ser_length_field_prefix option is not applicable to "
                              "bitmask_value field");
                static_assert(
                    !parsed_options_type::has_sequence_elem_ser_length_field_prefix,
                    "nil::marshalling::option::sequence_elem_ser_length_field_prefix option is not applicable to "
                    "bitmask_value field");
                static_assert(
                    !parsed_options_type::has_sequence_elem_fixed_ser_length_field_prefix,
                    "nil::marshalling::option::SequenceElemSerLengthFixedFieldPrefix option is not applicable to "
                    "bitmask_value field");
                static_assert(!parsed_options_type::has_sequence_trailing_field_suffix,
                              "nil::marshalling::option::sequence_trailing_field_suffix option is not applicable to "
                              "bitmask_value field");
                static_assert(!parsed_options_type::has_sequence_termination_field_suffix,
                              "nil::marshalling::option::sequence_termination_field_suffix option is not applicable to "
                              "bitmask_value field");
                static_assert(
                    !parsed_options_type::has_fixed_size_storage,
                    "nil::marshalling::option::fixed_size_storage option is not applicable to bitmask_value field");
                static_assert(
                    !parsed_options_type::has_custom_storage_type,
                    "nil::marshalling::option::custom_storage_type option is not applicable to bitmask_value field");
                static_assert(
                    !parsed_options_type::has_scaling_ratio,
                    "nil::marshalling::option::scaling_ratio_type option is not applicable to bitmask_value field");
                static_assert(!parsed_options_type::has_units,
                              "nil::marshalling::option::Units option is not applicable to bitmask_value field");
                static_assert(
                    !parsed_options_type::has_orig_data_view,
                    "nil::marshalling::option::orig_data_view option is not applicable to bitmask_value field");
                static_assert(
                    !parsed_options_type::has_multi_range_validation,
                    "nil::marshalling::option::valid_num_value_range (or similar) option is not applicable to "
                    "bitmask_value field");
                static_assert(
                    !parsed_options_type::has_versions_range,
                    "nil::marshalling::option::exists_between_versions (or similar) option is not applicable to "
                    "bitmask_value field");
                static_assert(
                    !parsed_options_type::has_invalid_by_default,
                    "nil::marshalling::option::invalid_by_default option is not applicable to bitmask_value field");

                integral_type intValue_;
            };

            // Implementation

            /// @brief Equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are equal, false otherwise.
            /// @related bitmask_value
            template<typename TFieldBase, typename... TOptions>
            bool operator==(const bitmask_value<TFieldBase, TOptions...> &field1,
                            const bitmask_value<TFieldBase, TOptions...> &field2) {
                return field1.value() == field2.value();
            }

            /// @brief Non-equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are NOT equal, false otherwise.
            /// @related bitmask_value
            template<typename TFieldBase, typename... TOptions>
            bool operator!=(const bitmask_value<TFieldBase, TOptions...> &field1,
                            const bitmask_value<TFieldBase, TOptions...> &field2) {
                return field1.value() != field2.value();
            }

            /// @brief Equivalence comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case value of the first field is lower than than the value of the second.
            /// @related bitmask_value
            template<typename TFieldBase, typename... TOptions>
            bool operator<(const bitmask_value<TFieldBase, TOptions...> &field1,
                           const bitmask_value<TFieldBase, TOptions...> &field2) {
                return field1.value() < field2.value();
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::bitmask_value type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::bitmask_value
            template<typename TFieldBase, typename... TOptions>
            inline bitmask_value<TFieldBase, TOptions...> &
                to_field_base(bitmask_value<TFieldBase, TOptions...> &field) {
                return field;
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::bitmask_value type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::bitmask_value
            template<typename TFieldBase, typename... TOptions>
            inline const bitmask_value<TFieldBase, TOptions...> &
                to_field_base(const bitmask_value<TFieldBase, TOptions...> &field) {
                return field;
            }

/// @brief Provide names for bits in nil::marshalling::types::bitmask_value field.
/// @details Defines BitIdx enum with all the provided values prefixed with
///     "BitIdx_". For example usage of
///     @code
///     MARSHALLING_BITMASK_BITS(first, second, third, fourth);
///     @endcode
///     will generate the following enum type:
///     @code
///     enum BitIdx
///     {
///         BitIdx_first,
///         BitIdx_second,
///         BitIdx_third,
///         BitIdx_fourth,
///         BitIdx_numOfValues
///     };
///     @endcode
///     @b NOTE, that provided names @b first, @b second, @b third, and @b fourth have
///     found their way to the enum @b BitIdx. @n
///     Also note, that there is automatically added @b BitIdx_nameOfValues
///     value to the end of @b BitIdx enum.
///
///     It is possible to assign values to the provided names. It could be useful
///     when skipping some unused bits. For example
///     @code
///     MARSHALLING_BITMASK_BITS(first=1, third=3, fourth);
///     @endcode
///     will generate the following enum type:
///     @code
///     enum BitIdx
///     {
///         BitIdx_first=1,
///         BitIdx_third=3,
///         BitIdx_fourth,
///         BitIdx_numOfValues
///     };
///     @endcode
///
///     The macro MARSHALLING_BITMASK_BITS() should be used inside definition of the
///     bitmask field to provide names for the bits for external use:
///     @code
///     struct MyField : public nil::marshalling::types::bitmask_value<...>
///     {
///         MARSHALLING_BITMASK_BITS(first, second, third, fourth);
///     }
///     @endcode
/// @related nil::marshalling::types::bitmask_value
#define MARSHALLING_BITMASK_BITS(...) MARSHALLING_DEFINE_ENUM(BitIdx, __VA_ARGS__)

/// @brief Generate access functions for bits in nil::marshalling::types::bitmask_value field.
/// @details The @ref MARSHALLING_BITMASK_BITS() macro defines @b BitIdx enum to
///     be able to access internal bits. However, an ability to provide
///     values to the enumeration values using @b =val suffixes doesn't
///     allow generation of convenience access functions to the bits. That's
///     why MARSHALLING_BITMASK_BITS_ACCESS() macro was introduced. For every name
///     listed in the parameters list, @b getBitValue_*() and @b set_bit_value_*()
///     functions will be generated. For example, having the following definition
///     @code
///     struct MyField : public nil::marshalling::types::bitmask_value<...>
///     {
///         ...
///         MARSHALLING_BITMASK_BITS_ACCESS(first, third, fourth);
///     }
///     @endcode
///     is equivalent to having following functions defined:
///     @code
///     struct MyField : public nil::marshalling::types::bitmask_value<...>
///     {
///         ...
///         bool getBitValue_first() const {
///             return get_bit_value(BitIdx_first);
///         }
///
///         void set_bit_value_first(bool value) {
///             set_bit_value(BitIdx_first, value);
///         }
///
///         bool getBitValue_third() const {
///             return get_bit_value(BitIdx_third);
///         }
///
///         void set_bit_value_third(bool value) {
///             set_bit_value(BitIdx_third, value);
///         }
///
///         bool getBitValue_fourth() const {
///             return get_bit_value(BitIdx_fourth);
///         }
///
///         void set_bit_value_fourth(bool value) {
///             set_bit_value(BitIdx_fourth, value);
///         }
///     }
///     @endcode
///     @b NOTE, that generated @b getBitValue_*() and @b set_bit_value_*()
///     functions use @b BitIdx_* enum values generated by
///     @ref MARSHALLING_BITMASK_BITS(). It means that MARSHALLING_BITMASK_BITS_ACCESS()
///     macro can NOT be used without @ref MARSHALLING_BITMASK_BITS().
///     @code
///     struct MyField : public nil::marshalling::types::bitmask_value<...>
///     {
///         MARSHALLING_BITMASK_BITS(first, third=2, fourth);
///         MARSHALLING_BITMASK_BITS_ACCESS(first, third, fourth);
///     }
///     @endcode
/// @pre Must be used together with @ref MARSHALLING_BITMASK_BITS()
/// @related nil::marshalling::types::bitmask_value
/// @warning Some compilers, such as @b clang or early versions of @b g++
///     may have problems compiling code generated by this macro even
///     though it uses valid C++11 constructs in attempt to automatically identify the
///     type of the base class. If the compilation fails,
///     and this macro resides inside a @b NON-template class, please use
///     @ref MARSHALLING_BITMASK_BITS_ACCESS_NOTEMPLATE() macro instead. In
///     case this macro needs to reside inside a @b template class, then
///     there is a need to define inner @b Base type, which specifies
///     exact type of the @ref nil::marshalling::types::bitmask_value class. For example:
///     @code
///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
///     template <typename... TExtraOptions>
///     class MyField : public
///         nil::marshalling::types::bitmask_value<
///             MyFieldBase,
///             nil::marshalling::types::fixed_length<1>,
///             nil::marshalling::types::BitmaskReservedBits<0xf2, 0>,
///             TExtraOptions...
///         >
///     {
///         // Duplicate definition of the base class
///         using Base =
///             nil::marshalling::types::bitmask_value<
///                 MyFieldBase,
///                 nil::marshalling::types::fixed_length<1>,
///                 smarshalling::types::BitmaskReservedBits<0xf2, 0>,
///                 TExtraOptions...
///             >;
///     public:
///         MARSHALLING_BITMASK_BITS(first, third=2, fourth);
///         MARSHALLING_BITMASK_BITS_ACCESS(first, third, fourth);
///     }
///     @endcode
#define MARSHALLING_BITMASK_BITS_ACCESS(...)                  \
    MARSHALLING_AS_BITMASK_FUNC {                             \
        return nil::marshalling::types::to_field_base(*this); \
    }                                                         \
    MARSHALLING_AS_BITMASK_CONST_FUNC {                       \
        return nil::marshalling::types::to_field_base(*this); \
    }                                                         \
    MARSHALLING_DO_BIT_ACC_FUNC(asBitmask(), __VA_ARGS__)

/// @brief Similar to @ref MARSHALLING_BITMASK_BITS_ACCESS(), but dedicated for
///     non-template classes.
/// @details The @ref MARSHALLING_BITMASK_BITS_ACCESS() macro is a generic one,
///     which can be used in any class (template, or non-template). However,
///     some compilers (such as <b>g++-4.9</b> and below, @b clang-4.0 and below) may fail
///     to compile it even though it uses valid C++11 constructs. If the
///     compilation fails and the class it is being used in is @b NOT a
///     template one, please use @ref MARSHALLING_BITMASK_BITS_ACCESS_NOTEMPLATE()
///     instead.
/// @related nil::marshalling::types::bitmask_value
#define MARSHALLING_BITMASK_BITS_ACCESS_NOTEMPLATE(...) MARSHALLING_DO_BIT_ACC_FUNC((*this), __VA_ARGS__)

/// @brief Combine usage of @ref MARSHALLING_BITMASK_BITS() and @ref MARSHALLING_BITMASK_BITS_ACCESS().
/// @details When assigned bit names start at bit 0 and go sequentially without
///     any gaps in the middle, i.e. don't have any @b =val suffixes, then use
///     MARSHALLING_BITMASK_BITS_SEQ() macro to name the bits. It is defined to use
///     @ref MARSHALLING_BITMASK_BITS() and @ref MARSHALLING_BITMASK_BITS_ACCESS() with the
///     same bit names. For example
///     @code
///     struct MyField : public nil::marshalling::types::bitmask_value<...>
///     {
///         MARSHALLING_BITMASK_BITS_SEQ(first, second, third, fourth);
///     }
///     @endcode
///     is equivalent to having
///     @code
///     struct MyField : public nil::marshalling::types::bitmask_value<...>
///     {
///         enum BitIdx
///         {
///             BitIdx_first,
///             BitIdx_second,
///             BitIdx_third,
///             BitIdx_fourth,
///             BitIdx_numOfValues
///         }
///
///         bool getBitValue_first() const {...}
///         void set_bit_value_first(bool value) {...}
///         bool getBitValue_second() const {...}
///         void set_bit_value_second(bool value) {...}
///         bool getBitValue_third() const {...}
///         void set_bit_value_third(bool value) {...}
///         bool getBitValue_fourth() const {...}
///         void set_bit_value_fourth(bool value) {...}
///     };
///     @endcode
/// @related nil::marshalling::types::bitmask_value
/// @warning Some compilers, such as @b clang or early versions of @b g++
///     may have problems compiling code generated by this macro even
///     though it uses valid C++11 constructs in attempt to automatically identify the
///     type of the base class. If the compilation fails,
///     and this macro resides inside a @b NON-template class, please use
///     @ref MARSHALLING_BITMASK_BITS_SEQ_NOTEMPLATE() macro instead. In
///     case this macro needs to reside inside a @b template class, then
///     there is a need to define inner @b Base type, which specifies
///     exact type of the @ref nil::marshalling::types::bitmask_value class. For example:
///     @code
///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
///     template <typename... TExtraOptions>
///     class MyField : public
///         nil::marshalling::types::bitmask_value<
///             MyFieldBase,
///             nil::marshalling::types::fixed_length<1>,
///             nil::marshalling::types::BitmaskReservedBits<0xf0, 0>,
///             TExtraOptions...
///         >
///     {
///         // Duplicate definition of the base class
///         using Base =
///             nil::marshalling::types::bitmask_value<
///                 MyFieldBase,
///                 nil::marshalling::types::fixed_length<1>,
///                 scomms::types::BitmaskReservedBits<0xf0, 0>,
///                 TExtraOptions...
///             >;
///     public:
///         MARSHALLING_BITMASK_BITS_SEQ(first, second, third, fourth);
///     }
///     @endcode
#define MARSHALLING_BITMASK_BITS_SEQ(...) \
    MARSHALLING_BITMASK_BITS(__VA_ARGS__) \
    MARSHALLING_BITMASK_BITS_ACCESS(__VA_ARGS__)

/// @brief Similar to @ref MARSHALLING_BITMASK_BITS_SEQ(), but dedicated for
///     non-template classes.
/// @details The @ref MARSHALLING_BITMASK_BITS_SEQ() macro is a generic one,
///     which can be used in any class (template, or non-template). However,
///     some compilers (such as <b>g++-4.9</b> and below, @b clang-4.0 and below) may fail
///     to compile it even though it uses valid C++11 constructs. If the
///     compilation fails and the class it is being used in is @b NOT a
///     template one, please use @ref MARSHALLING_BITMASK_BITS_SEQ_NOTEMPLATE()
///     instead.
/// @related nil::marshalling::types::bitmask_value
#define MARSHALLING_BITMASK_BITS_SEQ_NOTEMPLATE(...) \
    MARSHALLING_BITMASK_BITS(__VA_ARGS__)            \
    MARSHALLING_BITMASK_BITS_ACCESS_NOTEMPLATE(__VA_ARGS__)

        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BITMASK_VALUE_HPP
