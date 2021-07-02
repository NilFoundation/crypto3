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

/// @file nil/marshalling/protocol/msg_id_layer.hpp
/// This file contains "Message ID" protocol layer of the "marshalling" module.

#ifndef MARSHALLING_MSG_ID_LAYER_HPP
#define MARSHALLING_MSG_ID_LAYER_HPP

#include <array>
#include <tuple>
#include <algorithm>
#include <utility>
#include <tuple>
#include <limits>

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/processing/tuple.hpp>
#include <nil/marshalling/protocol/protocol_layer_base.hpp>
#include <nil/marshalling/msg_factory.hpp>
#include <nil/marshalling/types/no_value.hpp>
#include <nil/marshalling/type_traits.hpp>

namespace nil {
    namespace marshalling {
        namespace protocol {

            /// @brief Protocol layer that uses uses message ID field as a prefix to all the
            ///        subsequent data written by other (next) layers.
            /// @details The main purpose of this layer is to process the message ID information.
            ///     Holds instance of nil::marshalling::msg_factory as its private member and uses it
            ///     to create message(s) with the required ID.
            /// @tparam TField field_type type that contains message ID.
            /// @tparam TMessage Interface class for the @b input messages
            /// @tparam TAllMessages Types of all @b input messages, bundled in std::tuple,
            ///     that this protocol stack must be able to read() as well as create (using create_msg()).
            /// @tparam TNextLayer Next transport layer type.
            /// @tparam TOptions All the options that will be forwarded to definition of
            ///     message factory type (nil::marshalling::msg_factory).
            /// @headerfile nil/marshalling/protocol/MsgIdLayer.h
            template<typename TField, typename TMessage, typename TAllMessages, typename TNextLayer,
                     typename... TOptions>
            class msg_id_layer
                : public protocol_layer_base<TField, TNextLayer,
                                             msg_id_layer<TField, TMessage, TAllMessages, TNextLayer, TOptions...>> {
                static_assert(nil::detail::is_tuple<TAllMessages>::value, "TAllMessages must be of std::tuple type");
                using base_impl_type
                    = protocol_layer_base<TField, TNextLayer,
                                          msg_id_layer<TField, TMessage, TAllMessages, TNextLayer, TOptions...>>;

                using factory_type = nil::marshalling::msg_factory<TMessage, TAllMessages, TOptions...>;

                static_assert(TMessage::interface_options_type::has_msg_id_type,
                              "Usage of msg_id_layer requires support for ID type. "
                              "Use nil::marshalling::option::msg_id_type option in message interface type definition.");

            public:
                /// @brief All supported message types bundled in std::tuple.
                /// @see nil::marshalling::msg_factory::all_messages_type.
                using all_messages_type = typename factory_type::all_messages_type;

                /// @brief Type of smart pointer that will hold allocated message object.
                /// @details Same as nil::marshalling::msg_factory::msg_ptr_type.
                using msg_ptr_type = typename factory_type::msg_ptr_type;

                /// @brief Type of the @b input message interface.
                using message_type = TMessage;

                /// @brief Type of message ID
                using msg_id_type = typename message_type::msg_id_type;

                /// @brief Type of message ID when passed by the parameter
                using msg_id_param_type = typename message_type::msg_id_param_type;

                /// @brief Type of the field object used to read/write message ID value.
                using field_type = typename base_impl_type::field_type;

                static_assert(is_int_value<field_type>::value
                                  || is_enum_value<field_type>::value
                                  || is_no_value<field_type>::value,
                              "field_type must be of int_value or enum_value types");

                /// @brief Default constructor.
                explicit msg_id_layer() = default;

                /// @brief Copy constructor.
                msg_id_layer(const msg_id_layer &) = default;

                /// @brief Move constructor.
                msg_id_layer(msg_id_layer &&) = default;

                /// @brief Copy assignment.
                msg_id_layer &operator=(const msg_id_layer &) = default;

                /// @brief Move assignment.
                msg_id_layer &operator=(msg_id_layer &&) = default;

                /// @brief Destructor
                ~msg_id_layer() noexcept = default;

                /// @brief Customized read functionality, invoked by @ref read().
                /// @details The function will read message ID from the data sequence first,
                ///     generate appropriate (or validate provided) message object based on the read ID and
                ///     forward the read() request to the next layer.
                ///     If the message object cannot be generated (the message type is not
                ///     provided inside @b TAllMessages template parameter), but
                ///     the @ref nil::marshalling::option::SupportGenericMessage option has beed used,
                ///     the @ref nil::marshalling::generic_message may be generated instead.@n
                ///     @b NOTE, that @b msg parameter can be either reference to a smart pointer,
                ///     which will hold allocated object, or to previously allocated object itself.
                ///     In case of the latter, the function will compare read and expected message
                ///     ID value and will return @ref nil::marshalling::ErrorStatus::InvalidMsgId in case of mismatch.
                /// @tparam TMsg Type of the @b msg parameter
                /// @tparam TIter Type of iterator used for reading.
                /// @tparam TNextLayerReader next layer reader object type.
                /// @param[out] field field_type object to read.
                /// @param[in, out] msg Reference to smart pointer that will hold
                ///                 allocated message object, or to the previously allocated
                ///                 message object itself (which extends @ref nil::marshalling::message_base).
                /// @param[in, out] iter Input iterator used for reading.
                /// @param[in] size Size of the data in the sequence
                /// @param[out] missingSize If not nullptr and return value is
                ///             nil::marshalling::ErrorStatus::NotEnoughData it will contain
                ///             minimal missing data length required for the successful
                ///             read attempt.
                /// @param[in] nextLayerReader Next layer reader object.
                /// @return Status of the operation.
                /// @pre @b msg parameter, in case of being a smart pointer, doesn't point to any object:
                ///      @code assert(!msg); @endcode
                /// @pre Iterator must be valid and can be dereferenced and incremented at
                ///      least "size" times;
                /// @post The iterator will be advanced by the number of bytes was actually
                ///       read. In case of an error, distance between original position and
                ///       advanced will pinpoint the location of the error.
                /// @post Returns nil::marshalling::ErrorStatus::Success if and only if msg points
                ///       to a valid object (in case of being a smart pointer).
                /// @post missingSize output value is updated if and only if function
                ///       returns nil::marshalling::ErrorStatus::NotEnoughData.
                template<typename TMsg, typename TIter, typename TNextLayerReader>
                nil::marshalling::status_type eval_read(field_type &field, TMsg &msg, TIter &iter, std::size_t size,
                                                        std::size_t *missingSize, TNextLayerReader &&nextLayerReader) {
                    auto es = field.read(iter, size);
                    if (es == nil::marshalling::status_type::not_enough_data) {
                        base_impl_type::update_missing_size(field, size, missingSize);
                    }

                    if (es != status_type::success) {
                        return es;
                    }

                    using tag = typename std::conditional<
                        base_impl_type::template is_message_obj_ref<typename std::decay<decltype(msg)>::type>(),
                        direct_op_tag, polymorphic_op_tag>::type;

                    return eval_read_internal(field, msg, iter, size - field.length(), missingSize,
                                              std::forward<TNextLayerReader>(nextLayerReader), tag());
                }

                /// @brief Customized write functionality, invoked by @ref write().
                /// @details The function will write ID of the message to the data
                ///     sequence, then call write() member function of the next
                ///     protocol layer. If @b TMsg type is recognised to be actual message
                ///     type (inherited from nil::marshalling::message_base while using
                ///     nil::marshalling::option::StaticNumIdImpl option to specify its numeric ID),
                ///     its defined @b eval_get_id() member function (see nil::marshalling::message_base::eval_get_id())
                ///     non virtual function is called. Otherwise polymorphic @b get_id()
                ///     member function is used to retrieve the message ID information, which
                ///     means the message interface class must use nil::marshalling::option::IdInfoInterface
                ///     option to define appropriate interface.
                /// @tparam TMsg Type of the message being written.
                /// @tparam TIter Type of iterator used for writing.
                /// @tparam TNextLayerWriter next layer writer object type.
                /// @param[out] field field_type object to update and write.
                /// @param[in] msg Reference to message object
                /// @param[in, out] iter Output iterator used for writing.
                /// @param[in] size Max number of bytes that can be written.
                /// @param[in] nextLayerWriter Next layer writer object.
                /// @return Status of the write operation.
                /// @pre Iterator must be valid and can be dereferenced and incremented at
                ///      least "size" times;
                /// @post The iterator will be advanced by the number of bytes was actually
                ///       written. In case of an error, distance between original position
                ///       and advanced will pinpoint the location of the error.
                /// @return Status of the write operation.
                template<typename TMsg, typename TIter, typename TNextLayerWriter>
                status_type eval_write(field_type &field, const TMsg &msg, TIter &iter, std::size_t size,
                                       TNextLayerWriter &&nextLayerWriter) const {
                    using msg_type = typename std::decay<decltype(msg)>::type;
                    field.value() = get_msg_id(msg, id_retrieve_tag<msg_type>());
                    auto es = field.write(iter, size);
                    if (es != status_type::success) {
                        return es;
                    }

                    MARSHALLING_ASSERT(field.length() <= size);
                    return nextLayerWriter.write(msg, iter, size - field.length());
                }

                /// @copybrief ProtocolLayerBase::create_msg
                /// @details Hides and overrides create_msg() function inherited from
                ///     @ref ProtocolLayerBase. This function forwards the request to the
                ///     message factory object (@ref nil::marshalling::msg_factory) embedded as a private
                ///     data member of this class.
                /// @param[in] id ID of the message
                /// @param[in] idx Relative index of the message with the same ID.
                /// @return Smart pointer to the created message object.
                /// @see nil::marshalling::msg_factory::create_msg()
                msg_ptr_type create_msg(msg_id_param_type id, unsigned idx = 0) {
                    return factory_.create_msg(id, idx);
                }

            private:
                struct polymorphic_op_tag { };
                struct direct_op_tag { };

                template<typename TMsg>
                using id_retrieve_tag = typename std::conditional<detail::protocol_layer_has_do_get_id<TMsg>::value,
                                                                  direct_op_tag, polymorphic_op_tag>::type;

                struct id_param_as_is_tag { };
                struct id_param_cast_tag { };

                template<typename TId>
                using id_param_tag_type = typename std::conditional<std::is_base_of<msg_id_type, TId>::value,
                                                                    id_param_as_is_tag, id_param_cast_tag>::type;

                template<typename TMsg>
                static msg_id_param_type get_msg_id(const TMsg &msg, polymorphic_op_tag) {
                    using msg_type = typename std::decay<decltype(msg)>::type;
                    static_assert(nil::marshalling::is_message<msg_type>(),
                                  "The message class is expected to inherit from nil::marshalling::message");
                    static_assert(msg_type::interface_options_type::has_msg_id_info,
                                  "The message interface class must expose polymorphic ID retrieval functionality, "
                                  "use nil::marshalling::option::id_info_interface option to define it.");

                    return msg.get_id();
                }

                template<typename TMsg>
                static constexpr msg_id_param_type get_msg_id(const TMsg &msg, direct_op_tag) {
                    return msg.eval_get_id();
                }

                template<typename TIter, typename TNextLayerReader>
                nil::marshalling::status_type eval_read_internal_polymorphic(field_type &field, msg_ptr_type &msgPtr,
                                                                             TIter &iter, std::size_t size,
                                                                             std::size_t *missingSize,
                                                                             TNextLayerReader &&nextLayerReader) {
                    MARSHALLING_ASSERT(!msgPtr);
                    auto &id = field.value();
                    auto remLen = size;

                    auto es = nil::marshalling::status_type::success;
                    unsigned idx = 0;
                    while (true) {
                        msgPtr = create_msg_internal(id, idx);
                        if (!msgPtr) {
                            break;
                        }

                        using IterType = typename std::decay<decltype(iter)>::type;
                        static_assert(std::is_same<typename std::iterator_traits<IterType>::iterator_category,
                                                   std::random_access_iterator_tag>::value,
                                      "iterator used for reading is expected to be random access one");
                        IterType readStart = iter;
                        es = nextLayerReader.read(msgPtr, iter, remLen, missingSize);
                        if (es == nil::marshalling::status_type::success) {
                            return es;
                        }

                        msgPtr.reset();
                        iter = readStart;
                        ++idx;
                    }

                    if ((0U < idx) && factory_type::has_unique_ids()) {
                        return es;
                    }

                    MARSHALLING_ASSERT(!msgPtr);
                    auto idxLimit = msg_count_internal(id);
                    if (idx < idxLimit) {
                        return nil::marshalling::status_type::msg_alloc_failure;
                    }

                    msgPtr = create_generic_msg_internal(id);
                    if (!msgPtr) {
                        if (idx == 0) {
                            return nil::marshalling::status_type::invalid_msg_id;
                        }

                        return es;
                    }

                    es = nextLayerReader.read(msgPtr, iter, remLen, missingSize);
                    if (es != nil::marshalling::status_type::success) {
                        msgPtr.reset();
                    }

                    return es;
                }

                template<typename TMsg, typename TIter, typename TNextLayerReader>
                nil::marshalling::status_type eval_read_internal_direct(field_type &field, TMsg &msg, TIter &iter,
                                                                        std::size_t size, std::size_t *missingSize,
                                                                        TNextLayerReader &&nextLayerReader) {
                    using msg_type = typename std::decay<decltype(msg)>::type;
                    static_assert(detail::protocol_layer_has_do_get_id<msg_type>::value,
                                  "Explicit message type is expected to expose compile type message ID by "
                                  "using \"static_num_id_impl\" option");

                    auto &id = field.value();
                    if (static_cast<msg_id_type>(id) != msg_type::eval_get_id()) {
                        return status_type::invalid_msg_id;
                    }

                    return nextLayerReader.read(msg, iter, size, missingSize);
                }

                template<typename TMsg, typename TIter, typename TNextLayerReader>
                nil::marshalling::status_type eval_read_internal(field_type &field, TMsg &msg, TIter &iter,
                                                                 std::size_t size, std::size_t *missingSize,
                                                                 TNextLayerReader &&nextLayerReader,
                                                                 polymorphic_op_tag) {
                    return eval_read_internal_polymorphic(field, msg, iter, size, missingSize,
                                                          std::forward<TNextLayerReader>(nextLayerReader));
                }

                template<typename TMsg, typename TIter, typename TNextLayerReader>
                nil::marshalling::status_type eval_read_internal(field_type &field, TMsg &msg, TIter &iter,
                                                                 std::size_t size, std::size_t *missingSize,
                                                                 TNextLayerReader &&nextLayerReader, direct_op_tag) {
                    return eval_read_internal_direct(field, msg, iter, size, missingSize,
                                                     std::forward<TNextLayerReader>(nextLayerReader));
                }

                template<typename TId>
                msg_ptr_type create_msg_internal_tagged(TId &&id, unsigned idx, id_param_as_is_tag) {
                    return create_msg(std::forward<TId>(id), idx);
                }

                template<typename TId>
                msg_ptr_type create_msg_internal_tagged(TId &&id, unsigned idx, id_param_cast_tag) {
                    return create_msg(static_cast<msg_id_type>(id), idx);
                }

                template<typename TId>
                msg_ptr_type create_msg_internal(TId &&id, unsigned idx) {
                    using IdType = typename std::decay<decltype(id)>::type;
                    return create_msg_internal_tagged(std::forward<TId>(id), idx, id_param_tag_type<IdType>());
                }

                template<typename TId>
                msg_ptr_type create_generic_msg_internal_tagged(TId &&id, id_param_as_is_tag) {
                    return factory_.create_generic_msg(std::forward<TId>(id));
                }

                template<typename TId>
                msg_ptr_type create_generic_msg_internal_tagged(TId &&id, id_param_cast_tag) {
                    return factory_.create_generic_msg(static_cast<msg_id_type>(id));
                }

                template<typename TId>
                msg_ptr_type create_generic_msg_internal(TId &&id) {
                    using IdType = typename std::decay<decltype(id)>::type;
                    return create_generic_msg_internal_tagged(std::forward<TId>(id), id_param_tag_type<IdType>());
                }

                template<typename TId>
                std::size_t msg_count_internal_tagged(TId &&id, id_param_as_is_tag) {
                    return factory_.msg_count(std::forward<TId>(id));
                }

                template<typename TId>
                std::size_t msg_count_internal_tagged(TId &&id, id_param_cast_tag) {
                    return factory_.msg_count(static_cast<msg_id_type>(id));
                }

                template<typename TId>
                std::size_t msg_count_internal(TId &&id) {
                    using IdType = typename std::decay<decltype(id)>::type;
                    return msg_count_internal_tagged(std::forward<TId>(id), id_param_tag_type<IdType>());
                }

                factory_type factory_;
            };

            namespace detail {
                template<typename T>
                struct msg_id_layer_check_helper {
                    static const bool value = false;
                };

                template<typename TField, typename TMessage, typename TAllMessages, typename TNextLayer,
                         typename... TOptions>
                struct msg_id_layer_check_helper<
                    msg_id_layer<TField, TMessage, TAllMessages, TNextLayer, TOptions...>> {
                    static const bool value = true;
                };

            }    // namespace detail

            /// @brief Compile time check of whether the provided type is
            ///     a variant of @ref MsgIdLayer
            /// @related MsgIdLayer
            template<typename T>
            constexpr bool is_msg_id_layer() {
                return detail::msg_id_layer_check_helper<T>::value;
            }

        }    // namespace protocol

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MSG_ID_LAYER_HPP
