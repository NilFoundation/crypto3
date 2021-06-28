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
/// Contains definition of message object interface and various base classes
/// for custom messages.

#ifndef MARSHALLING_MESSAGE_HPP
#define MARSHALLING_MESSAGE_HPP

#include <cstdint>
#include <memory>
#include <type_traits>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/field_type.hpp>

#include <nil/marshalling/detail/message/interface_builder.hpp>
#include <nil/marshalling/detail/transport_fields_access.hpp>

namespace nil {
    namespace marshalling {

        /// @brief Main interface class for all the messages.
        /// @details Provides basic interface for all the messages.
        /// @tparam TOptions Variadic template parameter that contain any number of
        ///     options to define functionality/behaviour of the message.
        ///     The options may be comma separated as well as bundled
        ///     into std::tuple. Supported options are:
        ///     @li @ref nil::marshalling::option::BigEndian or @ref nil::marshalling::option::LittleEndian - options
        ///         used to specify endianness of the serialization. If this option is
        ///         @ref field_type internal types get defined.
        ///         used, read_data() functions as well as @ref endian_type and
        ///     @li @ref nil::marshalling::option::msg_id_type - an option used to specify type of the ID
        ///         value used to identify the message. If this option is used,
        ///         the @ref msg_id_type and
        ///         @ref msg_id_param_type types get defined.
        ///     @li @ref nil::marshalling::option::IdInfoInterface - an option used to provide polymorphic
        ///         id retrieval functionality. If this option is used in conjunction with
        ///         nil::marshalling::option::msg_id_type, the
        ///         get_id() member function is defined.
        ///     @li @ref nil::marshalling::option::read_iterator - an option used to specify type of iterator
        ///         used for reading. If this option is not used, then @ref read()
        ///         member function doesn't exist.
        ///     @li @ref nil::marshalling::option::write_iterator - an option used to specify type of iterator
        ///         used for writing. If this option is not used, then @ref write()
        ///         member function doesn't exist.
        ///     @li @ref nil::marshalling::option::ValidCheckInterface - an option used to add @ref valid()
        ///         member function to the default interface.
        ///     @li @ref nil::marshalling::option::LengthInfoInterface - an option used to add @ref length()
        ///         member function to the default interface.
        ///     @li @ref nil::marshalling::option::RefreshInterface - an option used to add @ref refresh()
        ///         member function to the default interface.
        ///     @li @ref nil::marshalling::option::NameInterface - an option used to add @ref name()
        ///         member function to the default interface.
        ///     @li @ref nil::marshalling::option::handler_type - an option used to specify type of message handler
        ///         object used to handle the message when it received. If this option
        ///         is not used, then dispatch() member function doesn't exist. See
        ///         dispatch() documentation for details.
        ///     @li @ref nil::marshalling::option::NoVirtualDestructor - Force the destructor to be
        ///         non-virtual, even if there are virtual functions in use.
        ///     @li @ref nil::marshalling::option::extra_transport_fields_type - Provide extra fields that
        ///         are read / written by transport layers, but may influence the way
        ///         the message being serialized / deserialized and/or handled.
        ///     @li @ref nil::marshalling::option::version_in_extra_transport_fields - Provide index of
        ///         the version field in extra transport fields.
        ///     @headerfile nil/marshalling/message.h
        template<typename... TOptions>
        class message : public detail::message::interface_builder_type<TOptions...> {
            using base_impl_type = detail::message::interface_builder_type<TOptions...>;

        public:
            /// @brief All the options bundled into struct.
            using interface_options_type = detail::message::interface_options_parser<TOptions...>;

            /// @brief Destructor.
            /// @details Becomes @b virtual if the message interface is defined to expose
            ///     any polymorphic behavior, i.e. if there is at least one virtual function.
            ///     It is possible to explicitly suppress @b virtual declaration by
            ///     using nil::marshalling::option::NoVirtualDestructor option.
            ~message() noexcept = default;

            /// @brief Compile type inquiry whether message interface class defines @ref msg_id_type
            ///     and @ref msg_id_param_type types.
            static constexpr bool has_msg_id_type() {
                return interface_options_type::has_msg_id_type;
            }

            /// @brief Compile type inquiry whether message interface class defines @ref endian_type
            ///     and @ref field_type types.
            static constexpr bool has_endian() {
                return interface_options_type::has_endian;
            }

            /// @brief Compile type inquiry whether message interface class defines
            ///     @ref get_id() and @ref get_id_impl() member functions.
            static constexpr bool has_get_id() {
                return has_msg_id_type() && interface_options_type::has_msg_id_info;
            }

            /// @brief Compile type inquiry whether message interface class defines
            ///     @ref read() and @ref read_impl() member functions as well as @ref
            ///     read_iterator type.
            static constexpr bool has_read() {
                return interface_options_type::has_read_iterator;
            }

            /// @brief Compile type inquiry whether message interface class defines
            ///     @ref write() and @ref write_impl() member functions as well as @ref
            ///     write_iterator type.
            static constexpr bool has_write() {
                return interface_options_type::has_write_iterator;
            }

            /// @brief Compile type inquiry whether message interface class defines
            ///     @ref valid() and @ref valid_impl() member functions.
            static constexpr bool has_valid() {
                return interface_options_type::has_valid;
            }

            /// @brief Compile type inquiry whether message interface class defines
            ///     @ref length() and @ref length_impl() member functions.
            static constexpr bool has_length() {
                return interface_options_type::has_length;
            }

            /// @brief Compile type inquiry whether message interface class defines
            ///     @ref refresh() and @ref refresh_impl() member functions.
            static constexpr bool has_refresh() {
                return interface_options_type::has_refresh;
            }

            /// @brief Compile type inquiry whether message interface class defines
            ///     @ref dispatch() and @ref dispatch_impl() member functions as well as @ref
            ///     handler_type and @ref DispatchRetType types.
            static constexpr bool has_dispatch() {
                return interface_options_type::has_handler;
            }

            /// @brief Compile type inquiry whether message interface class defines
            ///     @ref transport_fields() member functions as well as @ref
            ///     transport_fields_type type.
            static constexpr bool has_transport_fields() {
                return interface_options_type::has_extra_transport_fields;
            }

            /// @brief Compile type inquiry whether there is version information
            ///     inside transport fields.
            static constexpr bool has_version_in_transport_fields() {
                return interface_options_type::has_version_in_extra_transport_fields;
            }

            /// @brief Compile type inquiry whether message interface class defines
            ///     @ref name() and @ref name_impl() member functions.
            static constexpr bool has_name() {
                return interface_options_type::has_name;
            }

#ifdef FOR_DOXYGEN_DOC_ONLY
            /// @brief type used for message ID.
            /// @detail The type exists only if nil::marshalling::option::msg_id_type option
            ///     was provided to nil::marshalling::message to specify it.
            /// @see has_msg_id_type()
            using msg_id_type = typename base_impl_type::msg_id_type;

            /// @brief type used for message ID passed as parameter or returned from function.
            /// @detail It is equal to @ref msg_id_type for numeric types and becomes
            ///     "const-reference-to" @ref msg_id_type for more complex types.
            ///      The type exists only if @ref msg_id_type exists, i.e.
            ///      the nil::marshalling::option::msg_id_type option was used.
            using msg_id_param_type = typename base_impl_type::msg_id_param_type;

            /// @brief Serialisation endian type.
            /// @detail The type exists only if nil::marshalling::option::big_endian or
            ///     nil::marshalling::option::little_endian options were used to specify it.
            /// @see @ref has_endian()
            using endian_type = typename base_impl_type::endian_base_type;

            /// @brief type of default base class for all the fields.
            /// @detail Requires definition of the @ref endian type, i.e. the type
            ///     exist only if nil::marshalling::option::big_endian or
            ///     nil::marshalling::option::little_endian options were used.
            using field_type = base_impl_type::field_type;

            /// @brief Retrieve ID of the message.
            /// @detail Invokes pure virtual @ref get_id_impl(). This function exists
            ///     only if nil::marshalling::option::msg_id_type option was used to specify type
            ///     of the ID value and nil::marshalling::option::id_info_interface option are used.
            /// @return ID of the message.
            /// @see @ref has_get_id();
            msg_id_param_type get_id() const;

            /// @brief type of the iterator used for reading message contents from
            ///     sequence of bytes stored somewhere.
            /// @detail The type exists only if nil::marshalling::option::read_iterator option
            ///     was provided to nil::marshalling::message to specify one.
            /// @see @ref has_read()
            using read_iterator = TypeProvidedWithOption;

            /// @brief Read message contents using provided iterator.
            /// @detail The function exists only if nil::marshalling::option::read_iterator option
            ///     was provided to nil::marshalling::message to specify type of the @ref read_iterator.
            ///     The contents of the message are updated with bytes being read.
            ///     The buffer is external and maintained by the caller.
            ///     The provided iterator is advanced. The function invokes virtual
            ///     read_impl() function.
            /// @param[in, out] iter iterator used for reading the data.
            /// @param[in] size Maximum number of bytes that can be read.
            /// @return Status of the operation.
            /// @see @ref has_read()
            status_type read(read_iterator& iter, std::size_t size);

            /// @brief type of the iterator used for writing message contents into
            ///     sequence of bytes stored somewhere.
            /// @detail The type exists only if nil::marshalling::option::write_iterator option
            ///     was provided to nil::marshalling::message to specify one.
            /// @see @ref hasWrite()
            using write_iterator = TypeProvidedWithOption;

            /// @brief Write message contents using provided iterator.
            /// @detail The function exists only if nil::marshalling::option::write_iterator option
            ///     was provided to nil::marshalling::message to specify type of the @ref write_iterator.
            ///     The contents of the message are serialized into buffer. The buffer
            ///     is external and is maintained by the caller.
            ///     The provided iterator is advanced. The function invokes virtual
            ///     write_impl() function.
            /// @param[in, out] iter iterator used for writing the data.
            /// @param[in] size Maximum number of bytes that can be written.
            /// @return Status of the operation.
            /// @see @ref has_write()
            status_type write(write_iterator& iter, std::size_t size) const;

            /// @brief Check validity of message contents.
            /// @detail The function exists only if nil::marshalling::option::valid_check_interface option
            ///     was provided to nil::marshalling::message. The function invokes virtual valid_impl() function.
            /// @return true for valid contents, false otherwise.
            /// @see @ref has_valid()
            bool valid() const;

            /// @brief Get number of bytes required to serialise this message.
            /// @detail The function exists only if nil::marshalling::option::length_info_interface option
            ///     was provided to nil::marshalling::message. The function invokes virtual length_impl() function.
            /// @return Number of bytes required to serialise this message.
            /// @see @ref has_length()
            std::size_t length() const;

            /// @brief Refresh to contents of the message.
            /// @detail Many protocols define their messages in a way that the content
            ///     of some fields may depend on the value of the other field(s). For
            ///     example, providing in one field the information about number of
            ///     elements in the list that will follow later. Another example is
            ///     having bits in a bitmask field specifying whether other optional
            ///     fields exist. In this case, directly modifying value of some
            ///     fields may leave a message contents in an inconsistent state.
            ///     Having refresh() member function allows the developer to bring
            ///     the message into a consistent state prior to sending it over
            ///     I/O link . @n
            ///     The function exists only if nil::marshalling::option::refresh_interface option
            ///     was provided to nil::marshalling::message. The function invokes virtual
            ///     refresh_impl() function.
            /// @return true in case the contents of the message were modified, false if
            ///     all the fields of the message remained unchanged.
            bool refresh();

            /// @brief Get name of the message.
            /// @detail The function exists only if @ref nil::marshalling::option::name_interface option
            ///     was provided to nil::marshalling::message. The function invokes virtual
            ///     @ref name_impl() function.
            /// @see @ref has_name()
            const char* name() const;

            /// @brief type of the message handler object.
            /// @detail The type exists only if nil::marshalling::option::handler option
            ///     was provided to nil::marshalling::message to specify one.
            using handler = TypeProvidedWithOption;

            /// @brief Return type of the @ref dispatch() member function.
            /// @detail Equal to @b handler::RetType if such exists, @b void otherwise.
            using DispatchRetType = typename handler::RetType;

            /// @brief Dispatch message to the handler for processing.
            /// @detail The function exists only if nil::marshalling::option::handler option
            ///     was provided to nil::marshalling::message to specify type of the handler.
            ///     The function invokes virtual dispatch_impl() function.
            /// @param handler handler object to dispatch message to.
            DispatchRetType dispatch(handler& handler);

            /// @brief @b std::tuple of extra fields from transport layers that
            ///     may affect the way the message fields get serialized / deserialized.
            /// @detail The type exists only if @ref nil::marshalling::option::extra_transport_fields
            ///     option has been provided to @ref nil::marshalling::message class to specify them.
            /// @see @ref has_transport_fields()
            using transport_fields_type = FieldsProvidedWithOption;

            /// @brief Get access to extra transport fields.
            /// @detail The function exists only if @ref nil::marshalling::option::extra_transport_fields
            ///     option has been provided to @ref nil::marshalling::message class to specify them.
            ////    Some protocols may use additional values in transport information, such
            ///     as message version for example. Such values may influence the way
            ///     message data is being serialized / deserialized.
            ///     The provided extra transport fields are @b NOT serialized as part
            ///     of message payload. Their values are expected to be set by transport layer(s)
            ///     when such information is read. The transport layers are also responsible to
            ///     take the updated information from the relevant field and write it
            ///     when message contents being written.
            /// @see @ref has_transport_fields()
            transport_fields_type& transport_fields();

            /// @brief Const version of @ref transport_fields
            /// @detail The function exists only if @ref nil::marshalling::option::extra_transport_fields
            ///     option has been provided to @ref nil::marshalling::message class to specify them.
            /// @see @ref has_transport_fields()
            const transport_fields_type& transport_fields() const;

            /// @brief type used for version info
            /// @detail The type exists only if @ref nil::marshalling::option::version_in_extra_transport_fields
            ///     option has been provided.
            using version_type = typename base_impl_type::version_type;

            /// @brief Access to version information
            /// @detail The function exists only if @ref nil::marshalling::option::version_in_extra_transport_fields
            ///     option has been provided.
            version_type& version();

            /// @brief Const access to version information
            /// @detail The function exists only if @ref nil::marshalling::option::version_in_extra_transport_fields
            ///     option has been provided.
            const version_type& version() const;
#endif    // #ifdef FOR_DOXYGEN_DOC_ONLY

        protected:
#ifdef FOR_DOXYGEN_DOC_ONLY
            /// @brief Pure virtual function used to retrieve ID of the message.
            /// @detail Called by get_id(), must be implemented in the derived class.
            ///     This function exists
            ///     only if nil::marshalling::option::msg_id_type option was used to specify type
            ///     of the ID value as well as nil::marshalling::option::id_info_interface.
            /// @return ID of the message.
            /// @see @ref has_get_id();
            virtual msg_id_param_type get_id_impl() const = 0;

            /// @brief Virtual function used to implement read operation.
            /// @detail Called by read(), expected be implemented in the derived class.
            ///     The function exists only if nil::marshalling::option::read_iterator option
            ///     was provided to nil::marshalling::message to specify type of the @ref read_iterator.
            /// @param[in, out] iter iterator used for reading the data.
            /// @param[in] size Maximum number of bytes that can be read.
            /// @return Status of the operation. If not overridden returns
            ///     nil::marshalling::status_type::not_supported.
            /// @see @ref has_read()
            virtual nil::marshalling::status_type read_impl(read_iterator& iter, std::size_t size);

            /// @brief Virtual function used to implement write operation.
            /// @detail Called by write(), expected be implemented in the derived class.
            ///     The function exists only if nil::marshalling::option::write_iterator option
            ///     was provided to nil::marshalling::message to specify type of the @ref write_iterator.
            /// @param[in, out] iter iterator used for writing the data.
            /// @param[in] size Maximum number of bytes that can be written.
            /// @return Status of the operation. If not overridden returns
            ///     nil::marshalling::status_type::not_supported.
            /// @see @ref has_write()
            virtual nil::marshalling::status_type write_impl(write_iterator& iter, std::size_t size) const;

            /// @brief Pure virtual function used to implement contents validity check.
            /// @detail Called by valid(), must be implemented in the derived class.
            ///     The function exists only if nil::marshalling::option::valid_check_interface option
            ///     was provided to nil::marshalling::message.
            /// @return true for valid contents, false otherwise.
            /// @see @ref has_valid()
            virtual bool valid_impl() const = 0;

            /// @brief Pure virtual function used to retrieve number of bytes required
            ///     to serialise this message.
            /// @detail Called by length(), must be implemented in the derived class.
            ///     The function exists only if nil::marshalling::option::length_info_interface option
            ///     was provided to nil::marshalling::message.
            /// @return Number of bytes required to serialise this message.
            /// @see @ref has_length()
            virtual std::size_t length_impl() const = 0;

            /// @brief Virtual function used to bring contents of the message
            ///     into a consistent state.
            /// @detail Called by refresh(), can be overridden in the derived class.
            ///     If not overridden, does nothing and returns false indicating that
            ///     contents of the message haven't been changed.
            ///     The function exists only if nil::marshalling::option::refresh_interface option
            ///     was provided to nil::marshalling::message.
            /// @return true in case the contents of the message were modified, false if
            ///     all the fields of the message remained unchanged.
            virtual bool refresh_impl();

            /// @brief Pure virtual function used to dispatch message to the handler
            ///     object for processing.
            /// @detail Called by dispatch(), must be implemented in the derived class.
            ///     The function exists only if nil::marshalling::option::handler option was
            ///     provided to nil::marshalling::message to specify type of the handler.
            /// @param handler handler object to dispatch message to.
            virtual DispatchRetType dispatch_impl(handler& handler) = 0;

            /// @brief Pure virtual function used to retrieve actual message name.
            /// @detail Called by @ref name(), must be implemented in the derived class.
            ///     The function exists only if nil::marshalling::option::name_interface option was
            ///     provided to @ref nil::marshalling::message.
            virtual const char* name_impl() const = 0;

            /// @brief Write data into the output area.
            /// @detail Use this function to write data to the output area using
            ///     provided iterator. This function requires knowledge about serialization
            ///     endian. It exists only if endian type was
            ///     specified using nil::marshalling::option::big_endian or nil::marshalling::option::little_endian
            ///     options to the class.
            /// @tparam T type of the value to write. Must be integral.
            /// @tparam type of output iterator
            /// @param[in] value Integral type value to be written.
            /// @param[in, out] iter Output iterator.
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least sizeof(T) times.
            /// @post The iterator is advanced.
            /// @note Thread safety: Safe for distinct buffers, unsafe otherwise.
            template<typename T, typename TIter>
            static void write_data(T value, TIter& iter);

            /// @brief Write partial data into the output area.
            /// @detail Use this function to write partial data to the output area using
            ///     provided iterator. This function requires knowledge about serialization
            ///     endian. It exists only if endian type was
            ///     specified using nil::marshalling::option::big_endian or nil::marshalling::option::little_endian
            ///     options to the class.
            /// @tparam TSize length of the value in bytes known in compile time.
            /// @tparam T type of the value to write. Must be integral.
            /// @tparam TIter type of output iterator
            /// @param[in] value Integral type value to be written.
            /// @param[in, out] iter Output iterator.
            /// @pre TSize <= sizeof(T)
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least TSize times.
            /// @post The iterator is advanced.
            /// @note Thread safety: Safe for distinct buffers, unsafe otherwise.
            template<std::size_t TSize, typename T, typename TIter>
            static void write_data(T value, TIter& iter);

            /// @brief Read data from input area.
            /// @detail Use this function to read data from the input area using
            ///     provided iterator. This function requires knowledge about serialization
            ///     endian. It exists only if endian type was
            ///     specified using nil::marshalling::option::big_endian or nil::marshalling::option::little_endian
            ///     options to the class.
            /// @tparam T Return type
            /// @tparam TIter type of input iterator
            /// @param[in, out] iter Input iterator.
            /// @return The integral type value.
            /// @pre TSize <= sizeof(T)
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least sizeof(T) times.
            /// @post The iterator is advanced.
            /// @note Thread safety: Safe for distinct stream buffers, unsafe otherwise.
            template<typename T, typename TIter>
            static T read_data(TIter& iter);

            /// @brief Read partial data from input area.
            /// @detail Use this function to read partial data from the input area using
            ///     provided iterator. This function requires knowledge about serialization
            ///     endian. It exists only if endian type was
            ///     specified using nil::marshalling::option::big_endian or nil::marshalling::option::little_endian
            ///     options to the class.
            /// @tparam T Return type
            /// @tparam TSize number of bytes to read
            /// @tparam TIter type of input iterator
            /// @param[in, out] iter Input iterator.
            /// @return The integral type value.
            /// @pre TSize <= sizeof(T)
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least TSize times.
            /// @post The internal pointer of the stream buffer is advanced.
            /// @note Thread safety: Safe for distinct stream buffers, unsafe otherwise.
            template<typename T, std::size_t TSize, typename TIter>
            static T read_data(TIter& iter);

#endif    // #ifdef FOR_DOXYGEN_DOC_ONLY
        };

        /// @brief Upcast type of the message object to nil::marshalling::message in order to have
        ///     access to its internal types.
        template<typename... TOptions>
        inline message<TOptions...>& to_message(message<TOptions...>& msg) {
            return msg;
        }

        /// @brief Upcast type of the message object to nil::marshalling::message in order to have
        ///     access to its internal types.
        template<typename... TOptions>
        inline const message<TOptions...>& to_message(const message<TOptions...>& msg) {
            return msg;
        }

        /// @brief Create and initialise iterator for polymorphic read
        /// @tparam TMessage Type of message interface class.
        /// @param[in] val Value to initialise the iterator with.
        /// @return Initialised iterator for polymorphic read.
        template<typename TMessage, typename TVal>
        typename TMessage::read_iterator read_iterator_for(const TVal& val) {
            return typename TMessage::read_iterator(val);
        }

        /// @brief Create and initialise iterator for polymorphic write
        /// @tparam TMessage Type of message interface class.
        /// @param[in] val Value to initialise the iterator with.
        /// @return Initialised iterator for polymorphic write.
        template<typename TMessage, typename TVal>
        typename TMessage::write_iterator write_iterator_for(const TVal& val) {
            return typename TMessage::write_iterator(val);
        }

    }    // namespace marshalling
}    // namespace nil

/// @brief Add convenience access enum and functions to extra transport fields.
/// @details The nil::marshalling::message class provides access to its extra transport fields via
///     nil::marshalling::message_base::transport_fields() member function(s). The fields are bundled
///     into <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>
///     and can be accessed using indices with
///     <a href="http://en.cppreference.com/w/cpp/utility/tuple/get">std::get</a>.
///     For convenience, the fields should be named. The MARSHALLING_MSG_TRANSPORT_FIELDS_ACCESS()
///     macro does exactly that. @n
///     As an example, let's assume that custom message uses 3 fields of any
///     types:
///     @code
///     typedef ... TransportField1;
///     typedef ... TransportField2;
///     typedef ... TransportField3;
///
///     typedef std::tuple<TransportField1, TransportField2, TransportField3> MyExtraTransportFields
///
///     class MyInterface : public
///         nil::marshalling::message<
///             ...
///             nil::marshalling::option::extra_transport_fields<MyExtraTransportFields> >
///     {
///     public:
///         MARSHALLING_MSG_TRANSPORT_FIELDS_ACCESS(name1, name2, name3);
///     };
///     @endcode
///     The usage of the MARSHALLING_MSG_TRANSPORT_FIELDS_ACCESS() macro with the list of the extra transport field's
///     names is equivalent to having the following definitions inside the message class
///     @code
///     class MyInterface : public nil::marshalling::message<...>
///     {
///         using Base = nil::marshalling::message<...>;
///     public:
///         enum TransportFieldIdx {
///             TransportFieldIdx_name1,
///             TransportFieldIdx_name2,
///             TransportFieldIdx_name3,
///             TransportFieldIdx_nameOfValues
///         };
///
///         static_assert(std::tuple_size<Base::transport_fields_type>::value == TransportFieldIdx_nameOfValues,
///             "Number of expected transport fields is incorrect");
///
///         // Accessor to "name1" transport field.
///         auto transportField_name1() -> decltype(std::get<FieldIdx_name1>(Base::transport_fields()))
///         {
///             return std::get<FieldIdx_name1>(Base::transport_fields());
///         }
///
///         // Accessor to "name1" field.
///         auto transportField_name1() const -> decltype(std::get<FieldIdx_name1>(Base::transport_fields()))
///         {
///             return std::get<FieldIdx_name1>(Base::transport_fields());
///         }
///
///         // Accessor to "name2" field.
///         auto transportField_name2() -> decltype(std::get<FieldIdx_name2>(Base::transport_fields()))
///         {
///             return std::get<FieldIdx_name2>(Base::transport_fields());
///         }
///
///         // Accessor to "name2" field.
///         auto transportField_name2() const -> decltype(std::get<FieldIdx_name2>(Base::transport_fields()))
///         {
///             return std::get<FieldIdx_name2>(Base::transport_fields());
///         }
///
///         // Accessor to "name3" field.
///         auto transportField_name3() -> decltype(std::get<FieldIdx_name3>(Base::transport_fields()))
///         {
///             return std::get<FieldIdx_name3>(Base::transport_fields());
///         }
///
///         // Accessor to "name3" field.
///         auto transportField_name3() const -> decltype(std::get<FieldIdx_name3>(Base::transport_fields()))
///         {
///             return std::get<FieldIdx_name3>(Base::transport_fields());
///         }
///     };
///     @endcode
///     @b NOTE, that provided names @b name1, @b name2, and @b name3 have
///     found their way to the following definitions:
///     @li @b TransportFieldIdx enum. The names are prefixed with @b TransportFieldIdx_. The
///         @b TransportFieldIdx_nameOfValues value is automatically added at the end.
///     @li Accessor functions prefixed with @b transportField_
///
///     As the result, the fields can be accessed using @b TransportFieldIdx enum
///     @code
///     void handle(Message1& msg)
///     {
///         auto& transport_fields = msg.transport_fields();
///         auto& field1 = std::get<Message1::TransportFieldIdx_name1>(transport_fields);
///         auto& field2 = std::get<Message1::TransportFieldIdx_name2>(transport_fields);
///         auto& field3 = std::get<Message1::TransportFieldIdx_name3>(transport_fields);
///
///         auto value1 = field1.value();
///         auto value2 = field2.value();
///         auto value3 = field3.value();
///     }
///     @endcode
///     or using accessor functions:
///     @code
///     void handle(Message1& msg)
///     {
///         auto value1 = transportField_name1().value();
///         auto value2 = transportField_name2().value();
///         auto value3 = transportField_name3().value();
///     }
///     @endcode
/// @param[in] ... List of fields' names.
/// @related nil::marshalling::message
#define MARSHALLING_MSG_TRANSPORT_FIELDS_ACCESS(...)                                                 \
    MARSHALLING_EXPAND(MARSHALLING_DEFINE_TRANSPORT_FIELD_ENUM(__VA_ARGS__))                         \
    MARSHALLING_MSG_TRANSPORT_FIELDS_ACCESS_FUNC {                                                   \
        auto& msgBase = nil::marshalling::to_message(*this);                                         \
        using MsgBase = typename std::decay<decltype(msgBase)>::type;                                \
        static_assert(MsgBase::has_transport_fields(),                                               \
                      "Message interface class doesn't define extra transport fields.");             \
        using TransportFieldsTuple = typename MsgBase::transport_fields_type;                        \
        static_assert(std::tuple_size<TransportFieldsTuple>::value == TransportFieldIdx_numOfValues, \
                      "Invalid number of names for transport fields tuple");                         \
        return msgBase.transport_fields();                                                           \
    }                                                                                                \
    MARSHALLING_MSG_TRANSPORT_FIELDS_ACCESS_CONST_FUNC {                                             \
        return nil::marshalling::to_message(*this).transport_fields();                               \
    }                                                                                                \
    MARSHALLING_EXPAND(MARSHALLING_DO_TRANSPORT_FIELD_ACC_FUNC(transport_fields_type, transport_fields(), __VA_ARGS__))

#endif    // MARSHALLING_MESSAGE_HPP
