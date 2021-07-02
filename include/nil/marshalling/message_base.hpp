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
/// Provides common base class for the custom messages with default implementation.

#ifndef MARSHALLING_MESSAGE_BASE_HPP
#define MARSHALLING_MESSAGE_BASE_HPP

#include <nil/marshalling/detail/message/implementation_builder.hpp>
#include <nil/marshalling/detail/macro_common.hpp>
#include <nil/marshalling/detail/fields_access.hpp>

namespace nil {
    namespace marshalling {

        /// @brief Base class for all the custom protocol messages.
        /// @details The main purpose of this class is to provide default implementation
        ///     for some pure virtual functions defined in @ref message class. Just
        ///     like with @ref message class, the provided methods implementation
        ///     depends on the options passed as TOption template parameter.
        /// @tparam TMessage The main interface class of the custom protocol messages.
        ///     It may be either @ref message class itself or any other class that
        ///     extends @ref message. The @ref message_base inherits from class provided
        ///     as TMessage template parameter. As the result the real inheritance
        ///     diagram will look like: nil::marshalling::message <-- TMessage <-- nil::marshalling::message_base.
        /// @tparam TOptions Variadic template parameter that can include zero or more
        ///     options that specify behaviour. The options may be comma separated as well as
        ///     bundled into std::tuple. Supported options are:
        ///     @li nil::marshalling::option::StaticNumIdImpl - In case message have numeric IDs
        ///         (nil::marshalling::message::msg_id_type is of integral or enum type), usage of
        ///         this option will cause this class to implement get_id_impl() virtual
        ///         function that returns provided numeric value.
        ///     @li nil::marshalling::option::NoIdImpl - Some message may not have valid IDs and
        ///         their get_id() function is never going to be called. Usage of this
        ///         option will create dummy implementation of get_id_impl() virtual
        ///         function that contains always failing assertion. In DEBUG mode
        ///         compilation the application will crash while in release mode the
        ///         default constructed value of nil::marshalling::message::msg_id_type will be returned.
        ///     @li nil::marshalling::option::msg_type - Provide type of actual message that
        ///         inherits from this nil::marshalling::message_base class.
        ///     @li nil::marshalling::option::FieldsImpl - Usually implementation of read, write,
        ///         validity check, and length calculation is pretty straight forward. For
        ///         example the message is considered valid if all the field values
        ///         are considered to be valid, or read operation is to perform read for
        ///         all the fields in the message. If the nil::marshalling::option::FieldsImpl
        ///         option with all the message field classes bundled into
        ///         the std::tuple is provided, then @ref message_base class can implement
        ///         read_impl(), write_impl(), valid_impl(), length_impl() virtual functions
        ///         declared as pure in nil::marshalling::message interface. The option also
        ///         provides an accessor functions to the all the field objects: fields().
        ///     @li nil::marshalling::option::ZeroFieldsImpl - This option is an alias to
        ///         nil::marshalling::option::FieldsImpl<std::tuple<> >, which provides implementation
        ///         read_impl(), write_impl(), valid_impl(), length_impl() virtual functions
        ///         when message contains no fields, i.e. read_impl() and writeImple() will
        ///         always report success doing nothing, valid_impl() will always return
        ///         true, and length_impl() will always return 0.
        ///     @li nil::marshalling::option::NoReadImpl - Inhibit the implementation of read_impl().
        ///     @li nil::marshalling::option::NoWriteImpl - Inhibit the implementation of write_impl().
        ///     @li nil::marshalling::option::NoLengthImpl - Inhibit the implementation of length_impl().
        ///     @li nil::marshalling::option::NoValidImpl - Inhibit the implementation of valid_impl().
        ///     @li nil::marshalling::option::NoDispatchImpl - Inhibit the implementation of dispatch_impl().
        ///     @li nil::marshalling::option::has_custom_refresh - Notify @ref nil::marshalling::message_base that
        ///             there is custom eval_refresh() member function in the message definition
        ///             class.
        ///     @li nil::marshalling::option::has_do_get_id - Enable implementation of get_id_impl() even if
        ///         nil::marshalling::option::StaticNumIdImpl option wasn't used. Must be paired with
        ///         nil::marshalling::option::msg_type.
        /// @extends message
        /// @headerfile nil/marshalling/message_base.h
        /// @see @ref to_message_base()
        template<typename TMessage, typename... TOptions>
        class message_base : public detail::message::impl_builder_type<TMessage, TOptions...> {
            using base_impl_type = detail::message::impl_builder_type<TMessage, TOptions...>;

        public:
            /// @brief All the options provided to this class bundled into struct.
            using impl_options_type = detail::message::impl_options_parser<TOptions...>;

#ifdef FOR_DOXYGEN_DOC_ONLY

            /// @brief All field classes provided with nil::marshalling::option::fields_impl option.
            /// @detail The type is not defined if nil::marshalling::option::fields_impl option
            ///     wasn't provided to nil::marshalling::message_base.
            using all_fields_type = FieldsProvidedWithOption;

            /// @brief Get an access to the fields of the message.
            /// @detail The function doesn't exist if nil::marshalling::option::fields_impl option
            ///     wasn't provided to nil::marshalling::message_base.
            /// @return reference to the fields of the message.
            all_fields_type& fields();

            /// @brief Get an access to the fields of the message.
            /// @detail The function doesn't exist if nil::marshalling::option::fields_impl option
            ///     wasn't provided to nil::marshalling::message_base.
            /// @return Const reference to the fields of the message.
            const all_fields_type& fields() const;

            /// @brief Compile time check of whether the message fields are
            ///     version dependent.
            /// @detail The function doesn't exist if nil::marshalling::option::fields_impl option
            ///     wasn't provided to nil::marshalling::message_base.
            /// @return @b true if at least one of the fields is version dependent.
            static constexpr bool are_fields_version_dependent();

            /// @brief Default implementation of ID retrieval functionality.
            /// @detail This function exists only if nil::marshalling::option::static_num_id_impl option
            ///     was provided to nil::marshalling::message_base. @n
            /// @return Numeric ID of the message.
            static constexpr msg_id_param_type eval_get_id();

            /// @brief Default implementation of read functionality.
            /// @detail This function exists only if nil::marshalling::option::fields_impl option
            ///     was provided to nil::marshalling::message_base. @n
            ///     To make this function works, every field class must provide "read"
            ///     function with following signature:
            ///     @code
            ///     template <typename TIter>
            ///     status_type read(TIter& iter, std::size_t size);
            ///     @endcode
            ///     This function will invoke such "read()" member function for every
            ///     field object listed with nil::marshalling::option::fields_impl option. If
            ///     any field doesn't report status_type::success, then read operation
            ///     stops, i.e. the provided iterator is not advanced any more.
            /// @tparam TIter type of the iterator used for reading.
            /// @param[in, out] iter iterator used for reading the data.
            /// @param[in] size Maximum number of bytes that can be read.
            /// @return Status of the operation.
            template<typename TIter>
            status_type eval_read(TIter& iter, std::size_t size);

            /// @brief Default implementation of write functionality.
            /// @detail This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided
            ///     to nil::marshalling::message_base. @n
            ///     To make this function works, every field class must provide "write"
            ///     function with following signature:
            ///     @code
            ///     template <typename TIter>
            ///     status_type write(TIter& iter, std::size_t size) const;
            ///     @endcode
            ///     This function will invoke such "write()" member function for every
            ///     field object listed with nil::marshalling::option::fields_impl option. If
            ///     any field doesn't report status_type::success, then write operation
            ///     stops, i.e. the provided iterator is not advanced any more.
            /// @tparam TIter type of the iterator used for writing.
            /// @param[in, out] iter iterator used for writing the data.
            /// @param[in] size Maximum number of bytes that can be written.
            /// @return Status of the operation.
            template<typename TIter>
            status_type eval_write(TIter& iter, std::size_t size) const;

            /// @brief Default implementation of validity check functionality.
            /// @detail This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided to nil::marshalling::message_base.
            ///     To make this function works, every field class must provide "valid()"
            ///     function with following signature:
            ///     @code
            ///     bool valid() const;
            ///     @endcode
            ///     This function will invoke such "valid()" member function for every
            ///     field object listed with nil::marshalling::option::fields_impl option.
            /// @return true when @b all fields are valid.
            bool eval_valid() const;

            /// @brief Default implementation of refreshing functionality.
            /// @detail This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided to nil::marshalling::message_base.
            ///     To make this function works, every field class must provide "refresh()"
            ///     function with following signature:
            ///     @code
            ///     bool refresh() const;
            ///     @endcode
            ///     This function will invoke such "refresh()" member function for every
            ///     field object listed with nil::marshalling::option::fields_impl option and will
            ///     return @b true if <b>at least</b> one of the invoked functions returned
            ///     @b true.
            /// @return true when <b>at least</b> one of the fields has been updated.
            bool eval_refresh() const;

            /// @brief Default implementation of length calculation functionality.
            /// @detail This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided to nil::marshalling::message_base.
            ///     To make this function works, every field class must provide "length()"
            ///     function with following signature:
            ///     @code
            ///     std::size_t length() const;
            ///     @endcode
            ///     This function will invoke such "length()" member function for every
            ///     field object listed with nil::marshalling::option::fields_impl option. The
            ///     final result is a summary of the "length" values of all the
            ///     fields.
            /// @return Serialisation length of the message.
            std::size_t eval_length() const;

            /// @brief Default implementation of partial length calculation functionality.
            /// @detail Similar to @ref length() member function but starts the calculation
            ///     at the the field specified using @b TFromIdx template parameter.
            /// @tparam TFromIdx Index of the field, from which length calculation will start
            /// @return Calculated serialization length
            /// @pre TFromIdx < std::tuple_size<all_fields_type>::value
            template<std::size_t TFromIdx>
            std::size_t eval_length_from() const;

            /// @brief Default implementation of partial length calculation functionality.
            /// @detail Similar to @ref length() member function but stops the calculation
            ///     at the the field specified using @b TUntilIdx template parameter.
            /// @tparam TUntilIdx Index of the field, at which the calculation will stop.
            ///     The length of the filed with index @b TUntilIdx will @b NOT be taken
            ///     into account.
            /// @return Calculated serialization length
            /// @pre TUntilIdx <= std::tuple_size<all_fields_type>::value
            template<std::size_t TUntilIdx>
            std::size_t eval_length_until() const;

            /// @brief Default implementation of partial length calculation functionality.
            /// @detail Similar to @ref length() member function but starts the calculation
            ///     at the the field specified using @b TFromIdx template parameter, and
            ///     stops the calculation
            ///     at the the field specified using @b TUntilIdx template parameter.
            /// @tparam TFromIdx Index of the field, from which length calculation will start
            /// @tparam TUntilIdx Index of the field, at which the calculation will stop.
            ///     The length of the filed with index @b TUntilIdx will @b NOT be taken
            ///     into account.
            /// @return Calculated serialization length
            /// @pre TFromIdx < std::tuple_size<all_fields_type>::value
            /// @pre TUntilIdx <= std::tuple_size<all_fields_type>::value
            /// @pre TFromIdx < TUntilIdx
            template<std::size_t TFromIdx, std::size_t TUntilIdx>
            std::size_t eval_length_from_until() const;

            /// @brief Compile time constant of minimal serialization length.
            /// @detail This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided to nil::marshalling::message_base.
            ///     To make this function works, every field class must provide "min_length()"
            ///     function with following signature:
            ///     @code
            ///     static constexpr std::size_t min_length();
            ///     @endcode
            /// @return Minimal serialization length of the message.
            static constexpr std::size_t eval_min_length();

            /// @brief Compile time constant of minimal partial serialization length.
            /// @detail Similar to @ref eval_min_length() member function but starts the calculation
            ///     at the the field specified using @b TFromIdx template parameter.
            /// @tparam TFromIdx Index of the field, from which length calculation will start
            /// @return Calculated minimal serialization length
            /// @pre TFromIdx < std::tuple_size<all_fields_type>::value
            template<std::size_t TFromIdx>
            static constexpr std::size_t eval_min_length_from();

            /// @brief Compile time constant of minimal partial serialization length.
            /// @detail Similar to @ref eval_min_length() member function but stops the calculation
            ///     at the the field specified using @b TUntilIdx template parameter.
            /// @tparam TUntilIdx Index of the field, at which the calculation will stop.
            ///     The length of the filed with index @b TUntilIdx will @b NOT be taken
            ///     into account.
            /// @return Calculated minimal serialization length
            /// @pre TUntilIdx <= std::tuple_size<all_fields_type>::value
            template<std::size_t TUntilIdx>
            static constexpr std::size_t eval_min_length_until();

            /// @brief Compile time constant of minimal partial serialization length.
            /// @detail Similar to @ref eval_min_length() member function but starts the calculation
            ///     at the the field specified using @b TFromIdx template parameter, and
            ///     stops the calculation
            ///     at the the field specified using @b TUntilIdx template parameter.
            /// @tparam TFromIdx Index of the field, from which length calculation will start
            /// @tparam TUntilIdx Index of the field, at which the calculation will stop.
            ///     The length of the filed with index @b TUntilIdx will @b NOT be taken
            ///     into account.
            /// @return Calculated minimal serialization length
            /// @pre TFromIdx < std::tuple_size<all_fields_type>::value
            /// @pre TUntilIdx <= std::tuple_size<all_fields_type>::value
            /// @pre TFromIdx < TUntilIdx
            template<std::size_t TFromIdx, std::size_t TUntilIdx>
            std::size_t eval_min_length_from_until() const;

            /// @brief Compile time constant of maximal serialization length.
            /// @detail This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided to nil::marshalling::message_base.
            ///     To make this function works, every field class must provide "max_length()"
            ///     function with following signature:
            ///     @code
            ///     static constexpr std::size_t max_length();
            ///     @endcode
            /// @return Minimal serialization length of the message.
            static constexpr std::size_t eval_max_length();

            /// @brief Compile time constant of maximal partial serialization length.
            /// @detail Similar to @ref eval_max_length() member function but starts the calculation
            ///     at the the field specified using @b TFromIdx template parameter.
            /// @tparam TFromIdx Index of the field, from which length calculation will start
            /// @return Calculated minimal serialization length
            /// @pre TFromIdx < std::tuple_size<all_fields_type>::value
            template<std::size_t TFromIdx>
            static constexpr std::size_t eval_max_length_from();

            /// @brief Compile time constant of maximal partial serialization length.
            /// @detail Similar to @ref eval_max_length() member function but stops the calculation
            ///     at the the field specified using @b TUntilIdx template parameter.
            /// @tparam TUntilIdx Index of the field, at which the calculation will stop.
            ///     The length of the filed with index @b TUntilIdx will @b NOT be taken
            ///     into account.
            /// @return Calculated minimal serialization length
            /// @pre TUntilIdx <= std::tuple_size<all_fields_type>::value
            template<std::size_t TUntilIdx>
            static constexpr std::size_t eval_max_length_until();

            /// @brief Compile time constant of maximal partial serialization length.
            /// @detail Similar to @ref eval_max_length() member function but starts the calculation
            ///     at the the field specified using @b TFromIdx template parameter, and
            ///     stops the calculation
            ///     at the the field specified using @b TUntilIdx template parameter.
            /// @tparam TFromIdx Index of the field, from which length calculation will start
            /// @tparam TUntilIdx Index of the field, at which the calculation will stop.
            ///     The length of the filed with index @b TUntilIdx will @b NOT be taken
            ///     into account.
            /// @return Calculated minimal serialization length
            /// @pre TFromIdx < std::tuple_size<all_fields_type>::value
            /// @pre TUntilIdx <= std::tuple_size<all_fields_type>::value
            /// @pre TFromIdx < TUntilIdx
            template<std::size_t TFromIdx, std::size_t TUntilIdx>
            std::size_t eval_max_length_from_until() const;

            /// @brief Update version information of all the fields.
            /// @detail This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided to nil::marshalling::message_base and
            ///     @ref nil::marshalling::option::version_in_extra_transport_fields was provided to the
            ///     message interface class (@ref nil::marshalling::message). @n
            ///     This function will invoke such @b set_version() member function for every
            ///     field object listed with nil::marshalling::option::fields_impl option and will
            ///     return @b true if <b>at least</b> one of the invoked functions returned
            ///     @b true (similar to @ref eval_refresh()).
            /// @return true when <b>at least</b> one of the fields has been updated.
            bool eval_fields_version_update();

#endif    // #ifdef FOR_DOXYGEN_DOC_ONLY

        protected:
            ~message_base() noexcept = default;

#ifdef FOR_DOXYGEN_DOC_ONLY
            /// @brief Implementation of ID retrieval functionality.
            /// @detail This function may exist only if ID retrieval is possible, i.e.
            ///     the ID type has been privded to nil::marshalling::message using
            ///     nil::marshalling::option::msg_id_type option and the polymorphic ID retrieval
            ///     functionality was requested (using nil::marshalling::option::id_info_interface).
            ///     In addition to the conditions listed earlier this function is
            ///     provided if local eval_get_id() function was generated. If not,
            ///     it may still be provided if
            ///     the derived class is known (nil::marshalling::option::msg_type option
            ///     was used) and the nil::marshalling::option::has_do_get_id option is used
            ///     to declare the derived type having eval_get_id() member function
            ///     defined.
            /// @return ID value passed as template parameter to nil::marshalling::option::static_num_id_impl
            ///     option.
            virtual msg_id_param_type get_id_impl() const override;

            /// @brief Implementation of dispatch functionality.
            /// @detail This function exists only if the following conditions are @b true:
            ///     @li nil::marshalling::option::handler option
            ///     option was provided to nil::marshalling::message.
            ///     @li nil::marshalling::option::msg_type option was used to specify actual type
            ///     of the inheriting message class.
            ///     @li nil::marshalling::option::no_dispatch_impl option was @b NOT used.
            ///
            ///     In order to properly implement the dispatch functionality
            ///     this class imposes several requirements. First of all, the custom
            ///     message class must provide its own type as an argument to
            ///     nil::marshalling::option::msg_type option:
            ///     @code
            ///     class MyMessageBase :  public nil::marshalling::message<...> { ...};
            ///
            ///     class Message1 :
            ///         public nil::marshalling::message_base<
            ///             MyMessageBase,
            ///             ...
            ///             nil::marshalling::option::msg_type<Message1>
            ///             ...
            ///         >
            ///     {
            ///         ...
            ///     };
            ///     @endcode
            ///     Second, The @ref handler type (inherited from nil::marshalling::message) must
            ///     implement "handle()" member function for every message type (specified as
            ///     Message1, Message2, ...) it is supposed to handle:
            ///     @code
            ///     class MyHandler {
            ///     public:
            ///         DispatchRetType handle(Message1& msg);
            ///         DispatchRetType handle(Message2& msg);
            ///         ...
            ///     }
            ///     @endcode
            ///     The "handle()" functions may be virtual. If the handler is capable
            ///     of handling only limited number of messages, there is
            ///     a need to provide additional "handle()" member function to implement
            ///     default handling functionality (usually ignore the message by doing
            ///     nothing) for all other messages that weren't handled explicitly.
            ///     @code
            ///     class MyHandler {
            ///     public:
            ///         ...
            ///         DispatchRetType handle(message_base& msg);
            ///     }
            ///     @endcode
            ///     Where "message_base" is a common base class for all the possible
            ///     messages.
            ///
            ///     Once the requirements above are properly implemented, the implementation
            ///     of this message is very simple:
            ///     @code
            ///     DispatchRetType dispatch_impl(handler& handler)
            ///     {
            ///         typedef <actual-message-type-provided-with-option> Actual;
            ///         return handler.handle(static_cast<Actual&>(*this));
            ///     }
            ///     @endcode
            ///     The code above forces a compiler to choose appropriate @b handle()
            ///     function in the handler class, based on the actual type of the message.
            ///     If such function is not found, the compiler will choose to call
            ///     the one that covers all possible messages @b "void handle(message_base& msg)".
            /// @param handler reference to handler object.
            virtual DispatchRetType dispatch_impl(handler& handler) override;

            /// @brief Implementation of polymorphic read functionality.
            /// @detail This function exists if nil::marshalling::option::read_iterator option
            ///         was provided to nil::marshalling::message class when specifying interface, and
            ///         nil::marshalling::option::no_read_impl option was @b NOT used to inhibit
            ///         the implementation. @n
            ///         If nil::marshalling::option::msg_type option was used to specify the actual
            ///         type of the message, and if it contains custom eval_read()
            ///         function, it will be invoked. Otherwise, the invocation of
            ///         nil::marshalling::message_base::eval_read() will be chosen in case fields were
            ///         specified using nil::marshalling::option::fields_impl option.
            /// @param[in, out] iter iterator used for reading the data.
            /// @param[in] size Maximum number of bytes that can be read.
            /// @return Status of the operation.
            virtual status_type read_impl(read_iterator& iter, std::size_t size) override;

            /// @brief Helper function that allows to read only limited number of fields.
            /// @detail Sometimes the default implementation of eval_read() is incorrect.
            ///     For example, some bit in specific field specifies whether other field
            ///     exists or must be skipped. In this case the derived class must
            ///     implement different read functionality. To help in such task this
            ///     function provides an ability to read all the fields up to (not including) requested
            ///     field. The overriding eval_read() function in the custom message
            ///     definition class may use this function for such task.
            ///     This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided to nil::marshalling::message_base.
            ///     The requirements from field classes is the same as explained in
            ///     eval_read() documentation.
            /// @tparam TIdx Zero based index of the field to read until. The function
            ///     returns when field with index "TIdx - 1" (if such exists) has been
            ///     read, while field with index "TIdx" still hasn't.
            /// @tparam TIter type of the iterator used for reading.
            /// @param[in, out] iter iterator used for reading the data.
            /// @param[in] size Maximum number of bytes that can be read.
            /// @return Status of the operation.
            /// @pre TIdx <= std::tuple_size<all_fields_type>::value
            template<std::size_t TIdx, typename TIter>
            status_type eval_read_fields_until(TIter& iter, std::size_t& size);

            /// @brief Same as @ref eval_read_fields_until().
            template<std::size_t TIdx, typename TIter>
            status_type read_fields_until(TIter& iter, std::size_t& size);

            /// @brief Helper function that allows to read only limited number of fields.
            /// @detail Similar to @ref eval_read_fields_until(), but doesn't check for errors
            ///     and doesn't report status. This function can be used instead of
            ///     @ref eval_read_fields_until() when correction of the read operation was
            ///     ensured by other means prior to its invocation.
            /// @tparam TIdx Zero based index of the field to read until. The function
            ///     returns when field with index "TIdx - 1" (if such exists) has been
            ///     read, while field with index "TIdx" still hasn't.
            /// @tparam TIter type of the iterator used for reading.
            /// @param[in, out] iter iterator used for reading the data.
            /// @pre TIdx <= std::tuple_size<all_fields_type>::value
            template<std::size_t TIdx, typename TIter>
            void eval_read_fields_no_status_until(TIter& iter);

            /// @brief Same as @ref eval_read_fields_no_status_until().
            template<std::size_t TIdx, typename TIter>
            void read_fields_no_status_until(TIter& iter);

            /// @brief Helper function that allows to read only limited number of fields.
            /// @detail Sometimes the default implementation of eval_read() is incorrect.
            ///     For example, some bit in specific field specifies whether other field
            ///     exists or must be skipped. In this case the derived class must
            ///     implement different read functionality. To help in such task
            ///     @ref eval_read_fields_until() function allows to read fields up to a specified one,
            ///     while this function provides an ability to resume reading from some
            ///     other field in the middle. The overriding eval_read() function in the
            ///     custom message definition class may use this function for such task.
            ///     This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided to nil::marshalling::message_base.
            ///     The requirements from field classes is the same as explained in
            ///     eval_read() documentation.
            /// @tparam TIdx Zero based index of the field to read from. The function
            ///     reads all the fields between the one indexed TIdx (included) and
            ///     the last one (also included).
            /// @tparam TIter type of the iterator used for reading.
            /// @param[in, out] iter iterator used for reading the data.
            /// @param[in] size Maximum number of bytes that can be read.
            /// @return Status of the operation.
            /// @pre TIdx < std::tuple_size<all_fields_type>::value
            template<std::size_t TIdx, typename TIter>
            status_type eval_read_fields_from(TIter& iter, std::size_t& size);

            /// @brief Same as @ref eval_read_fields_from().
            template<std::size_t TIdx, typename TIter>
            status_type read_fields_from(TIter& iter, std::size_t& size);

            /// @brief Helper function that allows to read only limited number of fields.
            /// @detail Similar to @ref eval_read_fields_from(), but doesn't check for errors
            ///     and doesn't report status. This function can be used instead of
            ///     @ref eval_read_fields_from() when correction of the read operation was
            ///     ensured by other means prior to its invocation.
            /// @tparam TIdx Zero based index of the field to read from. The function
            ///     reads all the fields between the one indexed TIdx (included) and
            ///     the last one (also included).
            /// @tparam TIter type of the iterator used for reading.
            /// @param[in, out] iter iterator used for reading the data.
            /// @pre TIdx < std::tuple_size<all_fields_type>::value
            template<std::size_t TIdx, typename TIter>
            void eval_read_fields_no_status_from(TIter& iter);

            /// @brief Same as @ref eval_read_fields_no_status_from().
            template<std::size_t TIdx, typename TIter>
            void read_fields_no_status_from(TIter& iter);

            /// @brief Helper function that allows to read only limited number of fields.
            /// @detail Sometimes the default implementation of eval_read() is incorrect.
            ///     For example, some bit in specific field specifies whether other fields
            ///     exist or must be skipped. In this case the derived class must
            ///     implement different read functionality. In similar way to
            ///     eval_read_fields_from() and eval_read_fields_until() this function provides an
            ///     ability to read any number of fields.
            ///     This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided to nil::marshalling::message_base.
            ///     The requirements from field classes is the same as explained in
            ///     eval_read() documentation.
            /// @tparam TFromIdx Zero based index of the field to read from.
            /// @tparam TUntilIdx Zero based index of the field to read until (not included).
            /// @tparam TIter type of the iterator used for reading.
            /// @param[in, out] iter iterator used for reading the data.
            /// @param[in] size Maximum number of bytes that can be read.
            /// @return Status of the operation.
            /// @pre TFromIdx < std::tuple_size<all_fields_type>::value
            /// @pre TUntilIdx <= std::tuple_size<all_fields_type>::value
            /// @pre TFromIdx < TUntilIdx
            template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
            status_type eval_read_fields_from_until(TIter& iter, std::size_t& size);

            /// @brief Same as @ref eval_read_fields_from_until().
            template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
            status_type read_fields_from_until(TIter& iter, std::size_t& size);

            /// @brief Helper function that allows to read only limited number of fields.
            /// @detail Similar to @ref eval_read_fields_from_until(), but doesn't check for errors
            ///     and doesn't report status. This function can be used instead of
            ///     @ref eval_read_fields_from_until() when correction of the read operation was
            ///     ensured by other means prior to its invocation.
            /// @tparam TFromIdx Zero based index of the field to read from.
            /// @tparam TUntilIdx Zero based index of the field to read until (not included).
            /// @tparam TIter type of the iterator used for reading.
            /// @param[in, out] iter iterator used for reading the data.
            /// @pre TFromIdx < std::tuple_size<all_fields_type>::value
            /// @pre TUntilIdx <= std::tuple_size<all_fields_type>::value
            /// @pre TFromIdx < TUntilIdx
            template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
            void eval_read_fields_no_status_from_until(TIter& iter);

            /// @brief Same as @ref eval_read_fields_no_status_from_until().
            template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
            void read_fields_no_status_from_until(TIter& iter);

            /// @brief Implementation of polymorphic write functionality.
            /// @detail This function exists if nil::marshalling::option::write_iterator option
            ///         was provided to nil::marshalling::message class when specifying interface, and
            ///         nil::marshalling::option::no_write_impl option was @b NOT used to inhibit
            ///         the implementation. @n
            ///         If nil::marshalling::option::msg_type option was used to specify the actual
            ///         type of the message, and if it contains custom eval_write()
            ///         function, it will be invoked. Otherwise, the invocation of
            ///         nil::marshalling::message_base::eval_write() will be chosen in case fields were
            ///         specified using nil::marshalling::option::fields_impl option.
            /// @param[in, out] iter iterator used for writing the data.
            /// @param[in] size Maximum number of bytes that can be written.
            /// @return Status of the operation.
            virtual status_type write_impl(write_iterator& iter, std::size_t size) const override;

            /// @brief Helper function that allows to write only limited number of fields.
            /// @detail In a similar way to eval_read_fields_until(), this function allows
            ///     writing limited number of fields starting from the first one.
            ///     This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided to nil::marshalling::message_base.
            ///     The requirements from field classes is the same as explained in
            ///     eval_write() documentation.
            /// @tparam TIdx Zero based index of the field to write until. The function
            ///     returns when field with index "TIdx - 1" (if such exists) has been
            ///     written, while field with index "TIdx" still hasn't.
            /// @tparam TIter type of iterator used for writing.
            /// @param[in, out] iter iterator used for writing the data.
            /// @param[in] size Maximum number of bytes that can be written.
            /// @return Status of the operation.
            /// @pre TIdx <= std::tuple_size<all_fields_type>::value
            template<std::size_t TIdx, typename TIter>
            status_type eval_write_fields_until(TIter& iter, std::size_t size) const;

            /// @brief Same as @ref eval_write_fields_until().
            template<std::size_t TIdx, typename TIter>
            status_type write_fields_until(TIter& iter, std::size_t size) const;

            /// @brief Helper function that allows to write only limited number of fields.
            /// @detail Similar to @ref eval_write_fields_until(), but doesn't check for errors
            ///     and doesn't report status. This function can be used instead of
            ///     @ref eval_write_fields_until() when correction of the write operation was
            ///     ensured by other means prior to its invocation.
            /// @tparam TIdx Zero based index of the field to write until. The function
            ///     returns when field with index "TIdx - 1" (if such exists) has been
            ///     written, while field with index "TIdx" still hasn't.
            /// @tparam TIter type of the iterator used for writing.
            /// @param[in, out] iter iterator used for reading the data.
            /// @pre TIdx <= std::tuple_size<all_fields_type>::value
            template<std::size_t TIdx, typename TIter>
            void eval_write_fields_no_status_until(TIter& iter) const;

            /// @brief Same as @ref eval_write_fields_no_status_until().
            template<std::size_t TIdx, typename TIter>
            void write_fields_no_status_until(TIter& iter) const;

            /// @brief Helper function that allows to write only limited number of fields.
            /// @detail In a similar way to eval_read_fields_from(), this function allows
            ///     writing limited number of fields starting from the requested one until
            ///     the end.
            ///     This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided to nil::marshalling::message_base.
            ///     The requirements from field classes is the same as explained in
            ///     eval_write() documentation.
            /// @tparam TIdx Zero based index of the field to write from.
            /// @tparam TIter type of iterator used for writing.
            /// @param[in, out] iter iterator used for writing the data.
            /// @param[in] size Maximum number of bytes that can be written.
            /// @return Status of the operation.
            /// @pre TIdx < std::tuple_size<all_fields_type>::value
            template<std::size_t TIdx, typename TIter>
            status_type eval_write_fields_from(TIter& iter, std::size_t size) const;

            /// @brief Same as @ref eval_write_fields_from().
            template<std::size_t TIdx, typename TIter>
            status_type write_fields_from(TIter& iter, std::size_t size) const;

            /// @brief Helper function that allows to write only limited number of fields.
            /// @detail Similar to @ref eval_write_fields_from(), but doesn't check for errors
            ///     and doesn't report status. This function can be used instead of
            ///     @ref eval_write_fields_from() when correction of the write operation was
            ///     ensured by other means prior to its invocation.
            /// @tparam TIdx Zero based index of the field to write from.
            /// @tparam TIter type of the iterator used for writing.
            /// @param[in, out] iter iterator used for reading the data.
            /// @pre TIdx < std::tuple_size<all_fields_type>::value
            template<std::size_t TIdx, typename TIter>
            void eval_write_fields_no_status_from(TIter& iter) const;

            /// @brief Same as @ref eval_write_fields_no_status_from().
            template<std::size_t TIdx, typename TIter>
            void write_fields_no_status_from(TIter& iter) const;

            /// @brief Helper function that allows to write only limited number of fields.
            /// @detail In a similar way to eval_read_fields_from_until(), this function allows
            ///     writing limited number of fields between the requested indices.
            ///     This function exists only if nil::marshalling::option::fields_impl or
            ///     nil::marshalling::option::zero_fields_impl option was provided to nil::marshalling::message_base.
            ///     The requirements from field classes is the same as explained in
            ///     eval_write() documentation.
            /// @tparam TFromIdx Zero based index of the field to write from.
            /// @tparam TUntilIdx Zero based index of the field to write until (not including).
            /// @tparam TIter type of iterator used for writing.
            /// @param[in, out] iter iterator used for writing the data.
            /// @param[in] size Maximum number of bytes that can be written.
            /// @return Status of the operation.
            /// @pre TFromIdx < std::tuple_size<all_fields_type>::value
            /// @pre TUntilIdx <= std::tuple_size<all_fields_type>::value
            /// @pre TFromIdx < TUntilIdx
            template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
            status_type eval_write_fields_from_until(TIter& iter, std::size_t size) const;

            /// @brief Same as @ref eval_write_fields_no_status_from().
            template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
            status_type write_fields_from_until(TIter& iter, std::size_t size) const;

            /// @brief Helper function that allows to write only limited number of fields.
            /// @detail Similar to @ref eval_write_fields_from_until(), but doesn't check for errors
            ///     and doesn't report status. This function can be used instead of
            ///     @ref eval_write_fields_from_until() when correction of the write operation was
            ///     ensured by other means prior to its invocation.
            /// @tparam TFromIdx Zero based index of the field to write from.
            /// @tparam TUntilIdx Zero based index of the field to write until (not including).
            /// @tparam TIter type of iterator used for writing.
            /// @param[in, out] iter iterator used for reading the data.
            /// @pre TFromIdx < std::tuple_size<all_fields_type>::value
            /// @pre TUntilIdx <= std::tuple_size<all_fields_type>::value
            /// @pre TFromIdx < TUntilIdx
            template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
            void eval_write_fields_no_status_from_until(TIter& iter) const;

            /// @brief Same as @ref eval_write_fields_no_status_from_until().
            template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
            void write_fields_no_status_from_until(TIter& iter) const;

            /// @brief Implementation of polymorphic validity check functionality.
            /// @detail This function exists if nil::marshalling::option::valid_check_interface option
            ///         was provided to nil::marshalling::message class when specifying interface, and
            ///         nil::marshalling::option::no_valid_impl option was @b NOT used to inhibit
            ///         the implementation. @n
            ///         If nil::marshalling::option::msg_type option was used to specify the actual
            ///         type of the message, and if it contains custom eval_valid()
            ///         function, it will be invoked. Otherwise, the invocation of
            ///         nil::marshalling::message_base::eval_valid() will be chosen in case fields were
            ///         specified using nil::marshalling::option::fields_impl option.
            virtual bool valid_impl() const override;

            /// @brief Implementation of polymorphic length calculation functionality.
            /// @detail This function exists if nil::marshalling::option::length_info_interface option
            ///         was provided to nil::marshalling::message class when specifying interface, and
            ///         nil::marshalling::option::no_length_impl option was @b NOT used to inhibit
            ///         the implementation. @n
            ///         If nil::marshalling::option::msg_type option was used to specify the actual
            ///         type of the message, and if it contains custom eval_length()
            ///         function, it will be invoked. Otherwise, the invocation of
            ///         nil::marshalling::message_base::eval_length() will be chosen in case fields were
            ///         specified using nil::marshalling::option::fields_impl option.
            /// @return Serialisation length of the message.
            virtual std::size_t length_impl() const override;

            /// @brief Implementation of polymorphic refresh functionality.
            /// @detail This function exists if nil::marshalling::option::refresh_interface option
            ///         was provided to nil::marshalling::message class when specifying interface,
            ///         and nil::marshalling::option::has_custom_refresh option was used (either on
            ///         on of the fields or when defining a message class) to
            ///         to notify about existence of custom refresh functionality.
            ///         If nil::marshalling::option::msg_type option was used to specify the actual
            ///         message class, the @b this pointer will be downcasted to it to
            ///         invoke eval_refresh() member function defined there. If such
            ///         is not defined the default eval_refresh() member function from
            ///         this class will be used.
            /// @return @b true in case fields were updated, @b false if nothing has changed.
            virtual bool refresh_impl() override;

            /// @brief Implementation of polymorphic name retrieval functionality.
            /// @detail This function exists if @ref nil::marshalling::option::name_interface option
            ///         was provided to @ref nil::marshalling::message class when specifying interface,
            ///         and @ref nil::marshalling::option::has_name as well as @ref nil::marshalling::option::msg_type
            ///         options ware used for this class.
            ///         This function downcasts @b this pointer to actual message type and
            ///         invokes @b eval_name() member function.
            /// @return @b true in case fields were updated, @b false if nothing has changed.
            virtual const char* name_impl() const override;

#endif    // #ifdef FOR_DOXYGEN_DOC_ONLY
        };

        /// @brief message object equality comparison operator
        /// @details messages are considered equal if all their fields are considered equal
        /// @related message_base
        template<typename TMessage1, typename TMessage2, typename... TOptions>
        bool operator==(const message_base<TMessage1, TOptions...>& msg1,
                        const message_base<TMessage2, TOptions...>& msg2) {
            return msg1.fields() == msg2.fields();
        }

        /// @brief message object inequality comparison operator
        /// @details messages are considered not equal if any their fields are considered inequal.
        /// @related message_base
        template<typename TMessage1, typename TMessage2, typename... TOptions>
        bool operator!=(const message_base<TMessage1, TOptions...>& msg1,
                        const message_base<TMessage2, TOptions...>& msg2) {
            return !(msg1 == msg2);
        }

        /// @brief Upcast type of the message object to nil::marshalling::message_base in order to have
        ///     access to its internal types.
        template<typename TMessage, typename... TOptions>
        inline message_base<TMessage, TOptions...>& to_message_base(message_base<TMessage, TOptions...>& msg) {
            return msg;
        }

        /// @brief Upcast type of the message object to nil::marshalling::message_base in order to have
        ///     access to its internal types.
        template<typename TMessage, typename... TOptions>
        inline const message_base<TMessage, TOptions...>&
            to_message_base(const message_base<TMessage, TOptions...>& msg) {
            return msg;
        }

    }    // namespace marshalling
}    // namespace nil

/// @brief Add convenience access enum and functions to message fields.
/// @details The @ref nil::marshalling::message_base class provides access to its fields via
///     @ref nil::marshalling::message_base::fields() member function(s). The fields are bundled
///     into <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>
///     and can be accessed using indices with
///     <a href="http://en.cppreference.com/w/cpp/utility/tuple/get">std::get</a>.
///     For convenience, the fields should be named. The MARSHALLING_MSG_FIELDS_ACCESS()
///     macro does exactly that. @n
///     As an example, let's assume that custom message uses 3 fields of any
///     types:
///     @code
///     typedef ... Field1;
///     typedef ... Field2;
///     typedef ... Field3;
///
///     typedef std::tuple<Field1, Field2, Field3> MyMessageFields
///
///     class Message1 : public nil::marshalling::message_base<MyInterface,
///     nil::marshalling::option::FieldsImpl<MyMessageFields> >
///     {
///     public:
///         MARSHALLING_MSG_FIELDS_ACCESS(name1, name2, name3);
///     };
///     @endcode
///     The usage of the MARSHALLING_MSG_FIELDS_ACCESS() macro with the list of the field's names
///     is equivalent to having the following definitions inside the message class
///     @code
///     class Message1 : public nil::marshalling::message_base<...>
///     {
///         using Base = nil::marshalling::message_base<...>;
///     public:
///         enum FieldIdx {
///             FieldIdx_name1,
///             FieldIdx_name2,
///             FieldIdx_name3,
///             FieldIdx_nameOfValues
///         };
///
///         static_assert(std::tuple_size<Base::all_fields_type>::value == FieldIdx_nameOfValues,
///             "Number of expected fields is incorrect");
///
///         // Accessor to "name1" field.
///         auto field_name1() -> decltype(std::get<FieldIdx_name1>(Base::fields()))
///         {
///             return std::get<FieldIdx_name1>(Base::fields());
///         }
///
///         // Accessor to "name1" field.
///         auto field_name1() const -> decltype(std::get<FieldIdx_name1>(Base::fields()))
///         {
///             return std::get<FieldIdx_name1>(Base::fields());
///         }
///
///         // Accessor to "name2" field.
///         auto field_name2() -> decltype(std::get<FieldIdx_name2>(Base::fields()))
///         {
///             return std::get<FieldIdx_name2>(Base::fields());
///         }
///
///         // Accessor to "name2" field.
///         auto field_name2() const -> decltype(std::get<FieldIdx_name2>(Base::fields()))
///         {
///             return std::get<FieldIdx_name2>(Base::fields());
///         }
///
///         // Accessor to "name3" field.
///         auto field_name3() -> decltype(std::get<FieldIdx_name3>(Base::fields()))
///         {
///             return std::get<FieldIdx_name3>(Base::fields());
///         }
///
///         // Accessor to "name3" field.
///         auto field_name3() const -> decltype(std::get<FieldIdx_name3>(Base::fields()))
///         {
///             return std::get<FieldIdx_name3>(Base::fields());
///         }
///     };
///     @endcode
///     @b NOTE, that provided names @b name1, @b name2, and @b name3 have
///     found their way to the following definitions:
///     @li @b FieldIdx enum. The names are prefixed with @b FieldIdx_. The
///         @b FieldIdx_nameOfValues value is automatically added at the end.
///     @li Accessor functions prefixed with @b field_
///
///     As the result, the fields can be accessed using @b FieldIdx enum
///     @code
///     void handle(Message1& msg)
///     {
///         auto& allFields = msg.fields();
///         auto& field1 = std::get<Message1::FieldIdx_name1>(allFields);
///         auto& field2 = std::get<Message1::FieldIdx_name2>(allFields);
///         auto& field3 = std::get<Message1::FieldIdx_name3>(allFields);
///
///         auto value1 = field1.value();
///         auto value2 = field2.value();
///         auto value3 = field3.value();
///     }
///     @endcode
///     or using accessor functions:
///     @code
///     void handle(message1& msg)
///     {
///         auto value1 = field_name1().value();
///         auto value2 = field_name2().value();
///         auto value3 = field_name3().value();
///     }
///     @endcode
/// @param[in] ... List of fields' names.
/// @related nil::marshalling::message_base
#define MARSHALLING_MSG_FIELDS_ACCESS(...)                                            \
    MARSHALLING_EXPAND(MARSHALLING_DEFINE_FIELD_ENUM(__VA_ARGS__))                    \
    MARSHALLING_MSG_FIELDS_ACCESS_FUNC {                                              \
        auto& val = nil::marshalling::to_message_base(*this).fields();                \
        using AllFieldsTuple = typename std::decay<decltype(val)>::type;              \
        static_assert(std::tuple_size<AllFieldsTuple>::value == FieldIdx_numOfValues, \
                      "Invalid number of names for fields tuple");                    \
        return val;                                                                   \
    }                                                                                 \
    MARSHALLING_MSG_FIELDS_ACCESS_CONST_FUNC {                                        \
        auto& val = nil::marshalling::to_message_base(*this).fields();                \
        using AllFieldsTuple = typename std::decay<decltype(val)>::type;              \
        static_assert(std::tuple_size<AllFieldsTuple>::value == FieldIdx_numOfValues, \
                      "Invalid number of names for fields tuple");                    \
        return val;                                                                   \
    }                                                                                 \
    MARSHALLING_EXPAND(MARSHALLING_DO_FIELD_ACC_FUNC(all_fields_type, fields(), __VA_ARGS__))

#endif    // MARSHALLING_MESSAGE_BASE_HPP
