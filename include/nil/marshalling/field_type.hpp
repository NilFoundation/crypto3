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
/// @brief Contains definition of @ref nil::marshalling::field_type class.

#ifndef MARSHALLING_FIELD_TYPE_HPP
#define MARSHALLING_FIELD_TYPE_HPP

#include <type_traits>

#include <nil/marshalling/processing/access.hpp>
#include <nil/marshalling/detail/field_base.hpp>
#include <nil/marshalling/detail/macro_common.hpp>
#include <nil/marshalling/detail/fields_access.hpp>

namespace nil {
    namespace marshalling {

        /// @brief Base class to all the field classes.
        /// @details Every custom "field" class should inherit from this one.
        /// @tparam TOptions Zero or more options. The supported options are:
        ///     @li nil::marshalling::option::BigEndian or nil::marshalling::option::LittleEndian - Option to
        ///         specify serialization endian. If none is provided big endian is
        ///         assumed.
        /// @headerfile nil/marshalling/field_type.hpp
        template<typename... TOptions>
        class field_type : public detail::field_base<TOptions...> {
            using base_impl_type = detail::field_base<TOptions...>;

        public:
            /// @brief endian_type type
            /// @details Equal to either @ref nil::marshalling::endian::big_endian or
            ///     @ref nil::marshalling::endian::little_endian
            using endian_type = typename base_impl_type::endian_type;

            /// @brief Version type
            using version_type = typename base_impl_type::version_type;

            /// @brief Default validity check
            /// @details Always returns true, can be overriden by the derived class
            /// @return Always @b true
            static constexpr bool valid() {
                return true;
            }

            /// @brief Default refresh functionality
            /// @details Does nothing and returns false, can be overriden by the
            ///     derived class
            /// @return Always @b false
            static constexpr bool refresh() {
                return false;
            }

            /// @brief Default check of whether the field is version dependent.
            /// @return Always @b false.
            static constexpr bool is_version_dependent() {
                return false;
            }

            /// @brief Default version update functionality
            /// @details Does nothing and returns false, can be overriden by the
            ///     derived class
            /// @return Always @b false
            static constexpr bool set_version(version_type) {
                return false;
            }

        protected:
            /// @brief Write data into the output buffer.
            /// @details Use this function to write data to the the buffer
            ///          maintained by the caller. The endianness of the data will be
            ///          as specified in the options provided to the class.
            /// @tparam T Type of the value to write. Must be integral.
            /// @tparam Type of output iterator
            /// @param[in] value Integral type value to be written.
            /// @param[in, out] iter Output iterator.
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least sizeof(T) times.
            /// @post The iterator is advanced.
            /// @note Thread safety: Safe for distinct buffers, unsafe otherwise.
            template<typename T, typename TIter>
            static void write_data(T value, TIter &iter) {
                write_data<sizeof(T), T>(value, iter);
            }

            /// @brief Write partial data into the output buffer.
            /// @details Use this function to write partial data to the buffer maintained
            ///          by the caller. The endianness of the data will be as specified
            ///          the class options.
            /// @tparam TSize length of the value in bytes known in compile time.
            /// @tparam T Type of the value to write. Must be integral.
            /// @tparam TIter Type of output iterator
            /// @param[in] value Integral type value to be written.
            /// @param[in, out] iter Output iterator.
            /// @pre TSize <= sizeof(T)
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least TSize times.
            /// @post The iterator is advanced.
            /// @note Thread safety: Safe for distinct buffers, unsafe otherwise.
            template<std::size_t TSize, typename T, typename TIter>
            static void write_data(T value, TIter &iter) {
                static_assert(TSize <= sizeof(T), "Cannot put more bytes than type contains");
                return processing::write_data<TSize, T>(value, iter, endian_type());
            }

            /// @brief Read data from input buffer.
            /// @details Use this function to read data from the intput buffer maintained
            ///     by the caller. The endianness of the data will be as specified in
            ///     options of the class.
            /// @tparam T Return type
            /// @tparam TIter Type of input iterator
            /// @param[in, out] iter Input iterator.
            /// @return The integral type value.
            /// @pre TSize <= sizeof(T)
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least sizeof(T) times.
            /// @post The iterator is advanced.
            /// @note Thread safety: Safe for distinct stream buffers, unsafe otherwise.
            template<typename T, typename TIter>
            static T read_data(TIter &iter) {
                return read_data<T, sizeof(T)>(iter);
            }

            /// @brief Read partial data from input buffer.
            /// @details Use this function to read data from the intput buffer maintained
            ///     by the caller. The endianness of the data will be as specified in
            ///     options of the class.
            /// @tparam T Return type
            /// @tparam TSize number of bytes to read
            /// @tparam TIter Type of input iterator
            /// @param[in, out] iter Input iterator.
            /// @return The integral type value.
            /// @pre TSize <= sizeof(T)
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least TSize times.
            /// @post The internal pointer of the stream buffer is advanced.
            /// @note Thread safety: Safe for distinct stream buffers, unsafe otherwise.
            template<typename T, std::size_t TSize, typename TIter>
            static T read_data(TIter &iter) {
                static_assert(TSize <= sizeof(T), "Cannot get more bytes than type contains");
                return processing::read_data<T, TSize>(iter, endian_type());
            }
        };

/// @brief Add convenience access enum and functions to the members of
///     bundle fields, such as nil::marshalling::types::bundle or nil::marshalling::types::bitfield.
/// @details The fields of "bundle" types, such as nil::marshalling::types::bundle or
///     nil::marshalling::types::bitfield keep their members bundled in
///     <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>
///     and provide access to them via @b value() member functions.
///     The access to the specific member field can be obtained using
///     <a href="http://en.cppreference.com/w/cpp/utility/tuple/get">std::get</a>
///     later on:
///     @code
///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
///     using ... Field1;
///     using ... Field2;
///     using ... Field3;
///     using MyField =
///         nil::marshalling::types::bitfield<
///             MyFieldBase,
///             std::tuple<Field1, Field2, Field3>
///         >;
///
///     MyField field;
///     auto& members = field.value();
///     auto& firstMember = std::get<0>(members);
///     auto& secondMember = std::get<1>(members);
///     auto& thirdMember = std::get<2>(members);
///     @endcode
///     However, it would be convenient to provide names and easier access to
///     the member fields. The MARSHALLING_FIELD_MEMBERS_ACCESS() macro does exactly
///     that when used inside the field class definition. Just inherit from
///     the "bundle" field and use the macro inside with the names for the
///     member fields:
///     @code
///     class MyField : public nil::marshalling::types::bitfield<...>
///     {
///     public:
///         MARSHALLING_FIELD_MEMBERS_ACCESS(member1, member2, member3);
///     }
///     @endcode
///     It would be equivalent to having the following types and functions
///     definitions:
///     @code
///     class MyField : public nil::marshalling::types::bitfield<...>
///     {
///     public:
///         // Access indices for member fields
///         enum FieldIdx {
///             FieldIdx_member1,
///             FieldIdx_member2,
///             FieldIdx_member3,
///             FieldIdx_numOfValues
///         };
///
///         // Accessor to "member1" member field.
///         auto field_member1() -> decltype(std::get<FieldIdx_member1>(value()))
///         {
///             return std::get<FieldIdx_member1>(value());
///         }
///
///         // Accessor to const "member1" member field.
///         auto field_member1() const -> decltype(std::get<FieldIdx_member1>(value()))
///         {
///             return std::get<FieldIdx_member1>(value());
///         }
///
///         // Accessor to "member2" member field.
///         auto field_member2() -> decltype(std::get<FieldIdx_member2>(value()))
///         {
///             return std::get<FieldIdx_member2>(value());
///         }
///
///         // Accessor to const "member2" member field.
///         auto field_member2() const -> decltype(std::get<FieldIdx_member2>(value()))
///         {
///             return std::get<FieldIdx_member2>(value());
///         }
///
///         // Accessor to "member3" member field.
///         auto field_member3() -> decltype(std::get<FieldIdx_member2>(value()))
///         {
///             return std::get<FieldIdx_member3>(value());
///         }
///
///         // Accessor to const "member3" member field.
///         auto field_member2() const -> decltype(std::get<FieldIdx_member3>(value()))
///         {
///             return std::get<FieldIdx_member3>(value());
///         }
///     };
///     @endcode
///     @b NOTE, that provided names @b member1, @b member2, and @b member3, have
///         found their way to the following definitions:
///     @li @b FieldIdx enum. The names are prefixed with @b FieldIdx_. The
///         @b FieldIdx_nameOfValues value is automatically added at the end.
///     @li Accessor functions prefixed with @b field_
///
///     See @ref sec_field_tutorial_bitfield for more examples and details
/// @param[in] ... List of member fields' names.
/// @related nil::marshalling::types::bitfield
/// @warning Some compilers, such as @b clang or early versions of @b g++
///     may have problems compiling code generated by this macro even
///     though it uses valid C++11 constructs in attempt to automatically identify the
///     type of the base class. If the compilation fails,
///     and this macro resides inside a @b NON-template class, please use
///     @ref MARSHALLING_FIELD_MEMBERS_ACCESS_NOTEMPLATE() macro instead. In
///     case this macro needs to reside inside a @b template class, then
///     there is a need to define inner @b Base type, which specifies
///     exact type of the @ref nil::marshalling::types::bitfield class. For example:
///     @code
///     template <typename... TExtraOptions>
///     class MyField : public
///         nil::marshalling::types::bitfield<
///             MyFieldBase,
///             std::tuple<Field1, Field2, Field3>,
///             TExtraOptions...
///         >
///     {
///         // Define type of the base class
///         using Base =
///             nil::marshalling::types::bitfield<
///                 MyFieldBase,
///                 std::tuple<Field1, Field2, Field3>,
///                 TExtraOptions...
///             >;
///     public:
///         MARSHALLING_FIELD_MEMBERS_ACCESS(member1, member2, member3);
///     };
///     @endcode
#define MARSHALLING_FIELD_MEMBERS_ACCESS(...)                                         \
    MARSHALLING_EXPAND(MARSHALLING_DEFINE_FIELD_ENUM(__VA_ARGS__))                    \
    MARSHALLING_FIELD_VALUE_ACCESS_FUNC {                                             \
        auto &val = types::to_field_base(*this).value();            \
        using AllFieldsTuple = typename std::decay<decltype(val)>::type;              \
        static_assert(std::tuple_size<AllFieldsTuple>::value == FieldIdx_numOfValues, \
                      "Invalid number of names for fields tuple");                    \
        return val;                                                                   \
    }                                                                                 \
    MARSHALLING_FIELD_VALUE_ACCESS_CONST_FUNC {                                       \
        auto &val = types::to_field_base(*this).value();            \
        using AllFieldsTuple = typename std::decay<decltype(val)>::type;              \
        static_assert(std::tuple_size<AllFieldsTuple>::value == FieldIdx_numOfValues, \
                      "Invalid number of names for fields tuple");                    \
        return val;                                                                   \
    }                                                                                 \
    MARSHALLING_EXPAND(MARSHALLING_DO_FIELD_ACC_FUNC(value_type, value(), __VA_ARGS__))

/// @brief Similar to @ref MARSHALLING_FIELD_MEMBERS_ACCESS(), but dedicated for
///     non-template classes.
/// @details The @ref MARSHALLING_FIELD_MEMBERS_ACCESS() macro is a generic one,
///     which can be used in any class (template, or non-template). However,
///     some compilers (such as <b>g++-4.9</b> and below, @b clang-4.0 and below) may fail
///     to compile it even though it uses valid C++11 constructs. If the
///     compilation fails and the class it is being used in is @b NOT a
///     template one, please use @ref MARSHALLING_FIELD_MEMBERS_ACCESS_NOTEMPLATE()
///     instead.
/// @related nil::marshalling::types::bitfield
#define MARSHALLING_FIELD_MEMBERS_ACCESS_NOTEMPLATE(...)           \
    MARSHALLING_EXPAND(MARSHALLING_DEFINE_FIELD_ENUM(__VA_ARGS__)) \
    MARSHALLING_EXPAND(MARSHALLING_DO_FIELD_ACC_FUNC_NOTEMPLATE(__VA_ARGS__))

#ifdef FOR_DOXYGEN_DOC_ONLY
        /// @brief Add convenience access enum and functions to the members of
        ///     bundle fields, such as nil::marshalling::types::bundle or nil::marshalling::types::bitfield.
        /// @detail The fields of "bundle" types, such as nil::marshalling::types::bundle or
        ///     nil::marshalling::types::bitfield keep their members bundled in
        ///     <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>
        ///     and provide access to them via @b value() member functions.
        ///     The access to the specific member field can be obtained using
        ///     <a href="http://en.cppreference.com/w/cpp/utility/tuple/get">std::get</a>
        ///     later on:
        ///     @code
        ///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::big_endian>;
        ///     using ... Field1;
        ///     using ... Field2;
        ///     using ... Field3;
        ///     using MyField =
        ///         nil::marshalling::types::bundle<
        ///             MyFieldBase,
        ///             std::tuple<Field1, Field2, Field3>
        ///         >;
        ///
        ///     MyField field;
        ///     auto& members = field.value();
        ///     auto& firstMember = std::get<0>(members);
        ///     auto& secondMember = std::get<1>(members);
        ///     auto& thirdMember = std::get<2>(members);
        ///     @endcode
        ///     However, it would be convenient to provide names and easier access to
        ///     the member fields. The MARSHALLING_FIELD_MEMBERS_ACCESS() macro does exaclty
        ///     that when used inside the field class definition. Just inherit from
        ///     the "bundle" field and use the macro inside with names for the
        ///     member fields:
        ///     @code
        ///     class MyField : public nil::marshalling::types::bundle<...>
        ///     {
        ///     public:
        ///         MARSHALLING_FIELD_MEMBERS_ACCESS(member1, member2, member3);
        ///     }
        ///     @endcode
        ///     It would be equivalent to having the following types and functions
        ///     definitions:
        ///     @code
        ///     class MyField : public nil::marshalling::types::bundle<...>
        ///     {
        ///     public:
        ///         // Access indices for member fields
        ///         enum FieldIdx {
        ///             FieldIdx_member1,
        ///             FieldIdx_member2,
        ///             FieldIdx_member3,
        ///             FieldIdx_numOfValues
        ///         };
        ///
        ///         // Accessor to "member1" member field.
        ///         auto field_member1() -> decltype(std::get<FieldIdx_member1>(value()))
        ///         {
        ///             return std::get<FieldIdx_member1>(value());
        ///         }
        ///
        ///         // Accessor to const "member1" member field.
        ///         auto field_member1() const -> decltype(std::get<FieldIdx_member1>(value()))
        ///         {
        ///             return std::get<FieldIdx_member1>(value());
        ///         }
        ///
        ///         // Accessor to "member2" member field.
        ///         auto field_member2() -> decltype(std::get<FieldIdx_member2>(value()))
        ///         {
        ///             return std::get<FieldIdx_member2>(value());
        ///         }
        ///
        ///         // Accessor to const "member2" member field.
        ///         auto field_member2() const -> decltype(std::get<FieldIdx_member2>(value()))
        ///         {
        ///             return std::get<FieldIdx_member2>(value());
        ///         }
        ///
        ///         // Accessor to "member3" member field.
        ///         auto field_member3() -> decltype(std::get<FieldIdx_member2>(value()))
        ///         {
        ///             return std::get<FieldIdx_member3>(value());
        ///         }
        ///
        ///         // Accessor to const "member3" member field.
        ///         auto field_member2() const -> decltype(std::get<FieldIdx_member3>(value()))
        ///         {
        ///             return std::get<FieldIdx_member3>(value());
        ///         }
        ///     };
        ///     @endcode
        ///     @b NOTE, that provided names @b member1, @b member2, and @b member3, have
        ///         found their way to the following definitions:
        ///     @li @b FieldIdx enum. The names are prefixed with @b FieldIdx_. The
        ///         @b FieldIdx_nameOfValues value is automatically added at the end.
        ///     @li Accessor functions prefixed with @b field_
        ///
        ///     See @ref sec_field_tutorial_bundle for more examples and detail
        /// @param[in] ... List of member fields' names.
        /// @related nil::marshalling::types::bundle
        /// @warning Some compilers, such as @b clang or early versions of @b g++
        ///     may have problems compiling code generated by this macro even
        ///     though it uses valid C++11 constructs in attempt to automatically identify the
        ///     type of the base class. If the compilation fails,
        ///     and this macro resides inside a @b NON-template class, please use
        ///     @ref MARSHALLING_FIELD_MEMBERS_ACCESS_NOTEMPLATE() macro instead. In
        ///     case this macro needs to reside inside a @b template class, then
        ///     there is a need to define inner @b Base type, which specifies
        ///     exact type of the @ref nil::marshalling::types::bundle class. For example:
        ///     @code
        ///     template <typename... TExtraOptions>
        ///     class MyField : public
        ///         nil::marshalling::types::bundle<
        ///             MyFieldBase,
        ///             std::tuple<Field1, Field2, Field3>,
        ///             TExtraOptions...
        ///         >
        ///     {
        ///         // Define type of the base class
        ///         using Base =
        ///             nil::marshalling::types::bundle<
        ///                 MyFieldBase,
        ///                 std::tuple<Field1, Field2, Field3>,
        ///                 TExtraOptions...
        ///             >;
        ///     public:
        ///         MARSHALLING_FIELD_MEMBERS_ACCESS(member1, member2, member3);
        ///     };
        ///     @endcode
#define MARSHALLING_FIELD_MEMBERS_ACCESS(...)

        /// @brief Similar to @ref MARSHALLING_FIELD_MEMBERS_ACCESS(), but dedicated for
        ///     non-template classes.
        /// @detail The @ref MARSHALLING_FIELD_MEMBERS_ACCESS() macro is a generic one,
        ///     which can be used in any class (template, or non-template). However,
        ///     some compilers (such as <b>g++-4.9</b> and below, @b clang-4.0 and below) may fail
        ///     to compile it even though it uses valid C++11 constructs. If the
        ///     compilation fails and the class it is being used in is @b NOT a
        ///     template one, please use @ref MARSHALLING_FIELD_MEMBERS_ACCESS_NOTEMPLATE()
        ///     instead.
        /// @related nil::marshalling::types::bundle
#define MARSHALLING_FIELD_MEMBERS_ACCESS_NOTEMPLATE(...)           \
    MARSHALLING_EXPAND(MARSHALLING_DEFINE_FIELD_ENUM(__VA_ARGS__)) \
    MARSHALLING_EXPAND(MARSHALLING_DO_FIELD_ACC_FUNC_NOTEMPLATE(__VA_ARGS__))
#endif    // #ifdef FOR_DOXYGEN_DOC_ONLY

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_FIELD_TYPE_HPP
