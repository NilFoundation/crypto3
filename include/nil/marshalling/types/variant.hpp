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

#ifndef MARSHALLING_VARIANT_HPP
#define MARSHALLING_VARIANT_HPP

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/types/variant/basic_type.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/detail/macro_common.hpp>
#include <nil/marshalling/detail/variant_access.hpp>

#include <nil/marshalling/types/tag.hpp>

namespace nil {
    namespace marshalling {
        namespace types {

            /// @brief Defines a "variant" field, that can contain any of the provided ones.
            /// @details The @b variant object contains uninitialised buffer that can
            ///     fit any of the provided field types (as second template parameter).
            ///     At any given point of time this space can be initialised and used to
            ///     contain <b>at most</b> one of the specified field types. It resembles
            ///     a classic @b union, but disallows set value of one field type and read
            ///     it as other. The @b variant field abstraction provides
            ///     expected single field API functions, such as length(), read(), write(),
            ///     valid().
            ///
            ///     Refer to @ref sec_field_tutorial_variant for tutorial and usage examples.
            /// @tparam TFieldBase Base class for this field, expected to be a variant of
            ///     nil::marshalling::field_type.
            /// @tparam TMembers All supported field types bundled together in
            ///     <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>.
            ///     This parameter is used to determine the size of the contained buffer
            ///     to be able to fit any of the specified types.
            /// @tparam TOptions Zero or more options that modify/refine default behaviour
            ///     of the field.@n
            ///     Supported options are:
            ///     @li @ref nil::marshalling::option::default_value_initializer - All wrapped fields may
            ///         specify their independent default value initialisers. It is
            ///         also possible to provide initialiser for the variant field which
            ///         will set appropriate values to the fields based on some
            ///         internal logic.
            ///     @li @ref nil::marshalling::option::contents_validator - All wrapped fields may specify
            ///         their independent validators. The bundle field considered to
            ///         be valid if all the wrapped fields are valid. This option though,
            ///         provides an ability to add extra validation logic that can
            ///         observe value of more than one wrapped fields. For example,
            ///         protocol specifies that if one specific field has value X, than
            ///         other field is NOT allowed to have value Y.
            ///     @li @ref nil::marshalling::option::contents_refresher - The default @b refresh()
            ///         behavior is to call @b refresh() member function of the contained
            ///         field (if such exists). This option allows specifying the custom
            ///         refreshing behaviour.
            ///     @li @ref nil::marshalling::option::custom_value_reader - It may be required to implement
            ///         custom reading functionality instead of default behaviour of
            ///         invoking read() member function of every member field. It is possible
            ///         to provide cusom reader functionality using nil::marshalling::option::custom_value_reader
            ///         option.
            ///     @li @ref nil::marshalling::option::DefaultVariantIndex - By default the variant field
            ///         doesn't have any valid contents. This option may be used to specify
            ///         the index of the default member field.
            ///     @li @ref nil::marshalling::option::has_custom_read
            ///     @li @ref nil::marshalling::option::has_custom_refresh
            ///     @li @ref nil::marshalling::option::empty_serialization
            ///     @li @ref nil::marshalling::option::version_storage
            /// @extends nil::marshalling::field_type
            /// @headerfile nil/marshalling/types/variant.hpp
            /// @see MARSHALLING_VARIANT_MEMBERS_ACCESS()
            /// @see MARSHALLING_VARIANT_MEMBERS_ACCESS_NOTEMPLATE()
            template<typename TFieldBase, typename TMembers, typename... TOptions>
            class variant : private detail::adapt_basic_field_type<detail::basic_variant<TFieldBase, TMembers>, TOptions...> {
                using base_impl_type
                    = detail::adapt_basic_field_type<detail::basic_variant<TFieldBase, TMembers>, TOptions...>;

                static_assert(nil::detail::is_tuple<TMembers>::value,
                              "TMembers is expected to be a tuple of std::tuple<...>");

                static_assert(1U < std::tuple_size<TMembers>::value, "Number of members is expected to be at least 2.");

            public:
                /// @brief endian_type used for serialization.
                using endian_type = typename base_impl_type::endian_type;

                /// @brief Version type
                using version_type = typename base_impl_type::version_type;

                /// @brief All the options provided to this class bundled into struct.
                using parsed_options_type = detail::options_parser<TOptions...>;

                /// @brief Tag indicating type of the field
                using tag = tag::variant;

                /// @brief Value type.
                /// @details Type of the internal buffer used to store contained field,
                ///     should not be used in normal operation.
                using value_type = typename base_impl_type::value_type;

                /// @brief All the supported types.
                /// @details Same as @b TMemebers template argument, i.e. it is @b std::tuple
                ///     of all the wrapped fields.
                using members_type = typename base_impl_type::members_type;

                /// @brief Default constructor
                /// @details Invokes default constructor of every wrapped field
                variant() = default;

                /// @brief Constructor
                explicit variant(const value_type &val) : base_impl_type(val) {
                }

                /// @brief Constructor
                explicit variant(value_type &&val) : base_impl_type(std::move(val)) {
                }

                /// @brief Get access to the internal storage buffer.
                /// @details Should not be used in normal operation.
                value_type &value() {
                    return base_impl_type::value();
                }

                /// @brief Get access to the internal storage buffer.
                /// @details Should not be used in normal operation.
                const value_type &value() const {
                    return base_impl_type::value();
                }

                /// @brief Get length required to serialise contained fields.
                /// @details If the field doesn't contain a valid instance of other
                ///     field, the reported length is 0, otherwise the length of the
                ///     contained field is reported.
                /// @return Number of bytes it will take to serialise the field value.
                std::size_t length() const {
                    return base_impl_type::length();
                }

                /// @brief Get minimal length that is required to serialise all possible contained fields.
                /// @return Always returns 0.
                static constexpr std::size_t min_length() {
                    return base_impl_type::min_length();
                }

                /// @brief Get maximal length that is required to serialise all possible contained fields.
                /// @return Maximal number of bytes required serialise the field value.
                static constexpr std::size_t max_length() {
                    return base_impl_type::max_length();
                }

                /// @brief Read field value from input data sequence
                /// @details Invokes read() member function over every possible field
                ///     in order of definition until nil::marshalling::ErrorStatus::Success is returned.
                /// @param[in, out] iter Iterator to read the data.
                /// @param[in] size Number of bytes available for reading.
                /// @return Status of read operation.
                /// @post Iterator is advanced.
                template<typename TIter>
                status_type read(TIter &iter, std::size_t size) {
                    return base_impl_type::read(iter, size);
                }

                /// @brief Read operation without error check and status report is not supported.
                template<typename TIter>
                void read_no_status(TIter &iter) = delete;

                /// @brief Write current field value to output data sequence
                /// @details Invokes write() member function of the contained field if such
                ///     exists. If the variant field doesn't contain any valid field, the
                ///     function doesn't advance the iterator, but returns nil::marshalling::ErrorStatus::Success.
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

                /// @brief Check validity of all the contained field.
                /// @details Returns @b false if doesn't contain any field.
                bool valid() const {
                    return base_impl_type::valid();
                }

                /// @brief Refresh the field's value
                /// @details Invokes refresh() member function of the current field
                ///     if such exists, otherwise returns false.
                /// @return @b true if the value has been updated, @b false otherwise
                bool refresh() {
                    return base_impl_type::refresh();
                }

                /// @brief Get index of the current field (within the @ref Members tuple).
                /// @details If the variant field doesn't contain any valid field, the
                ///     returned index is equivalent to size of the @ref Members tuple.
                std::size_t current_field() const {
                    return base_impl_type::current_field();
                }

                /// @brief Select type of the variant field.
                /// @details If the same index has been selected before, the function does
                ///     nothing, otherwise the currently selected member field is destructed,
                ///     and the new one is default constructed.@n
                ///     If provided index is equal or exceeds the size of the @ref Members
                ///     tuple, no new field is constructed.
                /// @param[in] idx Index of the type within @ref Members tuple.
                void select_field(std::size_t idx) {
                    base_impl_type::select_field(idx);
                }

                /// @brief Execute provided function object with current field as
                ///     parameter.
                /// @details The provided function object must define all the public @b operator()
                ///     member functions to handle all possible types.
                ///     @code
                ///     struct MyFunc
                ///     {
                ///         template <std::size_t TIdx>
                ///         void operator()(Type1& field) {...}
                ///
                ///         template <std::size_t TIdx>
                ///         void operator()(Type2& field) {...}
                ///         ...
                ///     }
                ///     @endcode
                ///     @b NOTE, that every @b operator() is expecting to receive
                ///     an index of the type within the holding tuple as a template
                ///     parameter. If the index information is not needed it may be
                ///     either ignored or static_assert-ed upon.
                ///
                ///     The @b operator() may also receive a member field type as a
                ///     template parameter.
                ///     @code
                ///     struct MyFunc
                ///     {
                ///         template <std::size_t TIdx, typename TField>
                ///         void operator()(TField& field)
                ///         {
                ///             ... // do somethign with the field
                ///         }
                ///     }
                ///     @endcode
                ///     The TField will be the actual type of the contained field.
                ///     If the variant field doesn't contain any valid field, the functor
                ///     will @b NOT be called.
                template<typename TFunc>
                void current_field_exec(TFunc &&func) {
                    base_impl_type::current_field_exec(std::forward<TFunc>(func));
                }

                /// @brief Execute provided function object with current field as
                ///     parameter (const variant).
                /// @details Similar to other current_field_exec() variant, but with @b const.
                ///     Note, the constness of the parameter.
                ///     @code
                ///     struct MyFunc
                ///     {
                ///         template <std::size_t TIdx, typename TField>
                ///         void operator()(const TField& field)
                ///         {
                ///             ... // do somethign with the field
                ///         }
                ///     }
                ///     @endcode
                ///     The TField will be the actual type of the contained field.
                ///     If the variant field doesn't contain any valid field, the functor
                ///     will @b NOT be called.
                template<typename TFunc>
                void current_field_exec(TFunc &&func) const {
                    base_impl_type::current_field_exec(std::forward<TFunc>(func));
                }

                /// @brief Construct and initialise specified contained field in the
                ///     internal buffer.
                /// @details If the field already contains a valid field of any other
                ///     field type, the latter will be destructed.
                /// @tparam TIdx Index of the field type witin the @ref Members tuple.
                /// @tparam TArgs Types of the agurments for the field's constructor
                /// @param[in] args Arguments for the constructed field.
                /// @return Reference to the constructed field.
                template<std::size_t TIdx, typename... TArgs>
                typename std::tuple_element<TIdx, members_type>::type &init_field(TArgs &&...args) {
                    return base_impl_type::template init_field<TIdx>(std::forward<TArgs>(args)...);
                }

                /// @brief Access already constructed field at specifed index (known at compile time).
                /// @details Use this function to get a reference to the contained field type
                /// @tparam TIdx Index of the field type witin the @ref Members tuple.
                /// @return Reference to the contained field.
                /// @pre @code current_field() == TIdx @endcode
                template<std::size_t TIdx>
                typename std::tuple_element<TIdx, members_type>::type &access_field() {
                    return base_impl_type::template access_field<TIdx>();
                }

                /// @brief Access already constructed field at specifed index (known at compile time).
                /// @details Use this function to get a const reference to the contained field type.
                /// @tparam TIdx Index of the field type witin the @ref Members tuple.
                /// @return Const reference to the contained field.
                /// @pre @code current_field() == TIdx @endcode
                template<std::size_t TIdx>
                const typename std::tuple_element<TIdx, members_type>::type &access_field() const {
                    return base_impl_type::template access_field<TIdx>();
                }

                /// @brief Check whether the field contains a valid instance of other field.
                /// @details Returns @b true if and only if current_field() returns a valid
                ///     index inside the @ref Members tuple.
                bool current_field_valid() const {
                    return base_impl_type::current_field_valid();
                }

                /// @brief Invalidate current state
                /// @details Destructs currently contained field if such exists.
                void reset() {
                    base_impl_type::reset();
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
                    "nil::marshalling::option::num_value_ser_offset option is not applicable to variant field");
                static_assert(!parsed_options_type::has_fixed_length_limit,
                              "nil::marshalling::option::fixed_length option is not applicable to variant field");
                static_assert(!parsed_options_type::has_fixed_bit_length_limit,
                              "nil::marshalling::option::fixed_bit_length option is not applicable to variant field");
                static_assert(!parsed_options_type::has_var_length_limits,
                              "nil::marshalling::option::var_length option is not applicable to variant field");
                static_assert(!parsed_options_type::has_sequence_elem_length_forcing,
                              "nil::marshalling::option::SequenceElemLengthForcingEnabled option is not applicable to "
                              "variant field");
                static_assert(
                    !parsed_options_type::has_sequence_size_forcing,
                    "nil::marshalling::option::SequenceSizeForcingEnabled option is not applicable to variant field");
                static_assert(
                    !parsed_options_type::has_sequence_length_forcing,
                    "nil::marshalling::option::SequenceLengthForcingEnabled option is not applicable to variant field");
                static_assert(
                    !parsed_options_type::has_sequence_fixed_size,
                    "nil::marshalling::option::sequence_fixed_size option is not applicable to variant field");
                static_assert(!parsed_options_type::has_sequence_fixed_size_use_fixed_size_storage,
                              "nil::marshalling::option::SequenceFixedSizeUseFixedSizeStorage option is not applicable "
                              "to variant field");
                static_assert(
                    !parsed_options_type::has_sequence_size_field_prefix,
                    "nil::marshalling::option::sequence_size_field_prefix option is not applicable to variant field");
                static_assert(!parsed_options_type::has_sequence_ser_length_field_prefix,
                              "nil::marshalling::option::sequence_ser_length_field_prefix option is not applicable to "
                              "variant field");
                static_assert(!parsed_options_type::has_sequence_elem_ser_length_field_prefix,
                              "nil::marshalling::option::sequence_elem_ser_length_field_prefix option is not "
                              "applicable to variant field");
                static_assert(
                    !parsed_options_type::has_sequence_elem_fixed_ser_length_field_prefix,
                    "nil::marshalling::option::sequence_elem_fixed_ser_length_field_prefix option is not applicable "
                    "to variant field");
                static_assert(!parsed_options_type::has_sequence_trailing_field_suffix,
                              "nil::marshalling::option::sequence_trailing_field_suffix option is not applicable to "
                              "variant field");
                static_assert(!parsed_options_type::has_sequence_termination_field_suffix,
                              "nil::marshalling::option::sequence_termination_field_suffix option is not applicable to "
                              "variant field");
                static_assert(!parsed_options_type::has_fixed_size_storage,
                              "nil::marshalling::option::fixed_size_storage option is not applicable to variant field");
                static_assert(
                    !parsed_options_type::has_custom_storage_type,
                    "nil::marshalling::option::custom_storage_type option is not applicable to variant field");
                static_assert(!parsed_options_type::has_scaling_ratio,
                              "nil::marshalling::option::scaling_ratio_type option is not applicable to variant field");
                static_assert(!parsed_options_type::has_units,
                              "nil::marshalling::option::Units option is not applicable to variant field");
                static_assert(!parsed_options_type::has_orig_data_view,
                              "nil::marshalling::option::orig_data_view option is not applicable to variant field");
                static_assert(!parsed_options_type::has_multi_range_validation,
                              "nil::marshalling::option::valid_num_value_range (or similar) option is not applicable "
                              "to variant field");
                static_assert(!parsed_options_type::has_versions_range,
                              "nil::marshalling::option::exists_between_versions (or similar) option is not applicable "
                              "to variant field");
                static_assert(!parsed_options_type::has_invalid_by_default,
                              "nil::marshalling::option::invalid_by_default option is not applicable to variant field");
            };

            namespace detail {

                template<typename TVar>
                class variant_equality_comp_helper {
                public:
                    variant_equality_comp_helper(const TVar &other, bool &result) : other_(other), result_(result) {
                    }

                    template<std::size_t TIdx, typename TField>
                    void operator()(const TField &field) {
                        result_ = (field == other_.template access_field<TIdx>());
                    }

                private:
                    const TVar &other_;
                    bool &result_;
                };

                template<typename TVar>
                variant_equality_comp_helper<TVar> make_variant_equality_comp_helper(TVar &other, bool &result) {
                    return variant_equality_comp_helper<TVar>(other, result);
                }

            }    // namespace detail

            /// @brief Equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are equal, false otherwise.
            /// @related variant
            template<typename TFieldBase, typename TMembers, typename... TOptions>
            bool operator==(const variant<TFieldBase, TMembers, TOptions...> &field1,
                            const variant<TFieldBase, TMembers, TOptions...> &field2) {
                if (&field1 == &field2) {
                    return true;
                }

                if (field1.current_field_valid() != field2.current_field_valid()) {
                    return false;
                }

                if (!field1.current_field_valid()) {
                    return true;
                }

                if (field1.current_field() != field2.current_field()) {
                    return false;
                }

                bool result = false;
                field1.current_field_exec(detail::make_variant_equality_comp_helper(field2, result));
                return result;
            }

            /// @brief Non-equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return true in case fields are NOT equal, false otherwise.
            /// @related variant
            template<typename TFieldBase, typename TMembers, typename... TOptions>
            bool operator!=(const variant<TFieldBase, TMembers, TOptions...> &field1,
                            const variant<TFieldBase, TMembers, TOptions...> &field2) {
                return field1.value() != field2.value();
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::variant type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::variant
            template<typename TFieldBase, typename TMembers, typename... TOptions>
            inline variant<TFieldBase, TMembers, TOptions...> &
                to_field_base(variant<TFieldBase, TMembers, TOptions...> &field) {
                return field;
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::variant type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::variant
            template<typename TFieldBase, typename TMembers, typename... TOptions>
            inline const variant<TFieldBase, TMembers, TOptions...> &
                to_field_base(const variant<TFieldBase, TMembers, TOptions...> &field) {
                return field;
            }

/// @brief Add convenience access enum and functions to the members of
///     @ref nil::marshalling::types::variant field.
/// @details All the possible field types the @ref nil::marshalling::types::variant field
///     can contain are bundled in
///     <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>
///     and provided as a template parameter to the definition of the
///     nil::marshalling::types::variant field.
///     @code
///     using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::BigEndian>;
///     using ... Field1;
///     using ... Field2;
///     using ... Field3;
///     using MyField =
///         nil::marshalling::types::variant<
///             MyFieldBase,
///             std::tuple<Field1, Field2, Field3>
///         >;
///
///     MyField field;
///     auto& field1 = field.init_field<0>(); // Initialise the field to contain Field1 value
///     field1.value() = ...;
///     @endcode
///     However, it would be convenient to provide names and easier access to
///     all the poisble variants. The MARSHALLING_VARIANT_MEMBERS_ACCESS() macro does exactly
///     that when used inside the field class definition. Just inherit from
///     the nil::marshalling::types::variant class and use the macro inside with the names for the
///     member fields:
///     @code
///     class MyField : public nil::marshalling::types::variant<...>
///     {
///     public:
///         MARSHALLING_FIELD_MEMBERS_ACCESS(member1, member2, member3);
///     }
///     @endcode
///     It would be equivalent to having the following types and functions
///     definitions:
///     @code
///     class MyField : public nil::marshalling::types::variant<...>
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
///         // Initialise as first member (Field1)
///         template <typename... TArgs>
///         Field1& initField_member1(TArgs&&... args)
///         {
///             rerturn init_field<FieldIdx_member1>(std::forward<TArgs>(args)...);
///         }
///
///         // Accessor to the stored field as first member (Field1)
///         Field1& accessField_member1()
///         {
///             return access_field<FieldIdx_member1>();
///         }
///
///         // Const variant of the accessor to the stored field as first member (Field1)
///         const Field1& accessField_member1() const
///         {
///             return access_field<FieldIdx_member1>();
///         }
///
///         // Initialise as second member (Field2)
///         template <typename... TArgs>
///         Field2& initField_member2(TArgs&&... args)
///         {
///             rerturn init_field<FieldIdx_member2>(std::forward<TArgs>(args)...);
///         }
///
///         // Accessor to the stored field as second member (Field2)
///         Field2& accessField_member2()
///         {
///             return access_field<FieldIdx_member2>();
///         }
///
///         // Const variant of the accessor to the stored field as second member (Field2)
///         const Field2& accessField_member2() const
///         {
///             return access_field<FieldIdx_member2>();
///         }
///
///         // Initialise as third member (Field3)
///         template <typename... TArgs>
///         Field3& initField_member3(TArgs&&... args)
///         {
///             rerturn init_field<FieldIdx_member3>(std::forward<TArgs>(args)...);
///         }
///
///         // Accessor to the stored field as third member (Field3)
///         Field3& accessField_member3()
///         {
///             return access_field<FieldIdx_member3>();
///         }
///
///         // Const variant of the accessor to the stored field as third member (Field3)
///         const Field3& accessField_member3() const
///         {
///             return access_field<FieldIdx_member3>();
///         }
///     };
///     @endcode
///     @b NOTE, that provided names @b member1, @b member2, and @b member3, have
///         found their way to the following definitions:
///     @li @b FieldIdx enum. The names are prefixed with @b FieldIdx_. The
///         @b FieldIdx_nameOfValues value is automatically added at the end.
///     @li Initialisation functions prefixed with @b initField_
///     @li Accessor functions prefixed with @b accessField_
///
///     See @ref sec_field_tutorial_variant for more examples and details
/// @param[in] ... List of member fields' names.
/// @related nil::marshalling::types::variant
/// @warning Some compilers, such as @b clang or early versions of @b g++
///     may have problems compiling code generated by this macro even
///     though it uses valid C++11 constructs in attempt to automatically identify the
///     type of the base class. If the compilation fails,
///     and this macro resides inside a @b NON-template class, please use
///     MARSHALLING_VARIANT_MEMBERS_ACCESS_NOTEMPLATE() macro instead. In
///     case this macro needs to reside inside a @b template class, then
///     there is a need to define inner @b Base type, which specifies
///     exact type of the @ref nil::marshalling::types::variant class. For example:
///     @code
///     template <typename... TExtraOptions>
///     class MyField : public
///         nil::marshalling::types::variant<
///             MyFieldBase,
///             std::tuple<Field1, Field2, Field3>,
///             TExtraOptions...
///         >
///     {
///         // Duplicate the base class definition
///         using Base =
///             nil::marshalling::types::variant<
///                 MyFieldBase,
///                 std::tuple<Field1, Field2, Field3>,
///                 TExtraOptions...
///             >;
///     public:
///         MARSHALLING_VARIANT_MEMBERS_ACCESS(member1, member2, member3);
///     };
///     @endcode
#define MARSHALLING_VARIANT_MEMBERS_ACCESS(...)                                                   \
    MARSHALLING_EXPAND(MARSHALLING_DEFINE_FIELD_ENUM(__VA_ARGS__))                                \
    MARSHALLING_AS_VARIANT_FUNC {                                                                 \
        auto &var = nil::marshalling::types::to_field_base(*this);                                \
        using Var = typename std::decay<decltype(var)>::type;                                     \
        static_assert(std::tuple_size<typename Var::members_type>::value == FieldIdx_numOfValues, \
                      "Invalid number of names for variant field");                               \
        return var;                                                                               \
    }                                                                                             \
    MARSHALLING_AS_VARIANT_CONST_FUNC {                                                           \
        auto &var = nil::marshalling::types::to_field_base(*this);                                \
        using Var = typename std::decay<decltype(var)>::type;                                     \
        static_assert(std::tuple_size<typename Var::members_type>::value == FieldIdx_numOfValues, \
                      "Invalid number of names for variant field");                               \
        return var;                                                                               \
    }                                                                                             \
    MARSHALLING_DO_VARIANT_MEM_ACC_FUNC(as_variant(), __VA_ARGS__)

/// @brief Similar to MARSHALLING_VARIANT_MEMBERS_ACCESS(), but dedicated for
///     non-template classes.
/// @details The MARSHALLING_VARIANT_MEMBERS_ACCESS() macro is a generic one,
///     which can be used in any class (template, or non-template). However,
///     some compilers (such as <b>g++-4.9</b> and below, @b clang-4.0 and below) may fail
///     to compile it even though it uses valid C++11 constructs. If the
///     compilation fails and the class it is being used in is @b NOT a
///     template one, please use @ref MARSHALLING_VARIANT_MEMBERS_ACCESS_NOTEMPLATE()
///     instead.
/// @related nil::marshalling::types::variant
#define MARSHALLING_VARIANT_MEMBERS_ACCESS_NOTEMPLATE(...)         \
    MARSHALLING_EXPAND(MARSHALLING_DEFINE_FIELD_ENUM(__VA_ARGS__)) \
    MARSHALLING_DO_VARIANT_MEM_ACC_FUNC_NOTEMPLATE(__VA_ARGS__)

        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_VARIANT_HPP
