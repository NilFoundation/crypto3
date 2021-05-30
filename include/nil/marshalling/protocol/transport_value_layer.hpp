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

#ifndef MARSHALLING_TRANSPORT_VALUE_LAYER_HPP
#define MARSHALLING_TRANSPORT_VALUE_LAYER_HPP

#include <nil/marshalling/protocol/protocol_layer_base.hpp>
#include <nil/marshalling/protocol/detail/transport_value_layer_adapter.hpp>

namespace nil {
    namespace marshalling {
        namespace protocol {

            /// @brief Protocol layer that reads a value from transport wrapping and
            ///     reassigns it to appropriate "extra transport" data member of the
            ///     created message object.
            /// @details Some protocols may put some values, which influence the way
            ///     of how message contents are read and/or how the message is handled.
            ///     For example protocol version information. This layer will read
            ///     the field's value and will re-assign it to specified message object's
            ///     "extra transport" data member field. This layer requires extra support
            ///     from the defined message interface object - there is a need to pass
            ///     @ref nil::marshalling::option::extra_transport_fields_type option to the interface definition
            ///     @ref nil::marshalling::message class.
            ///     This layer is a mid level layer, expects other mid level layer or
            ///     MsgDataLayer to be its next one.
            /// @tparam TField Type of the field that is used read / write extra transport value.
            /// @tparam TIdx Index of "extra transport" field that message object contains
            ///     (accessed via @ref nil::marshalling::message::transport_fields()).
            /// @tparam TNextLayer Next transport layer in protocol stack.
            /// @tparam TOptions Extending functionality options. Supported options are:
            ///     @li @ref nil::marshalling::option::PseudoValue - Mark the handled value to be "pseudo"
            ///         one, i.e. the field is not getting serialized.
            /// @headerfile nil/marshalling/protocol/TransportValueLayer.h
            /// @extends ProtocolLayerBase
            template<typename TField, std::size_t TIdx, typename TNextLayer, typename... TOptions>
            class transport_value_layer
                : public detail::transport_value_layer_adapter_type<
                      protocol_layer_base<TField, TNextLayer,
                                          transport_value_layer<TField, TIdx, TNextLayer, TOptions...>,
                                          nil::marshalling::option::protocol_layer_force_read_until_data_split>,
                      TOptions...> {
                using base_impl_type = detail::transport_value_layer_adapter_type<
                    protocol_layer_base<TField, TNextLayer,
                                        transport_value_layer<TField, TIdx, TNextLayer, TOptions...>,
                                        nil::marshalling::option::protocol_layer_force_read_until_data_split>,
                    TOptions...>;

            public:
                /// @brief Type of the field object used to read/write "sync" value.
                using field_type = typename base_impl_type::field_type;

                /// @brief Parsed options
                using transport_parsed_options_type = detail::transport_value_layer_options_parser<TOptions...>;

                /// @brief Default constructor
                transport_value_layer() = default;

                /// @brief Copy constructor.
                transport_value_layer(const transport_value_layer &) = default;

                /// @brief Move constructor.
                transport_value_layer(transport_value_layer &&) = default;

                /// @brief Destructor
                ~transport_value_layer() noexcept = default;

                /// @brief Customized read functionality, invoked by @ref read().
                /// @details Reads the value from the input data and assigns it to appropriate
                ///     extra transport field inside the message object (accessed via
                ///     nil::marshalling::message::transport_fields()). @n
                ///     Note, that this operation works fine even if message object is created
                ///     after reading the transport value. There is "inner magic" that causes
                ///     read operation to proceed until @b DATA layer
                ///     (implemented by @ref nil::marshalling::protocol::MsgDataLayer), assigns the
                ///     read value to message object, then proceeds to reading the message
                ///     contents, i.e. when @ref nil::marshalling::message::read() function is invoked
                ///     the message object already has the value of the transport field updated.
                /// @tparam TMsg Type of the @b msg parameter.
                /// @tparam TIter Type of iterator used for reading.
                /// @tparam TNextLayerReader next layer reader object type.
                /// @param[out] field field_type object to read.
                /// @param[in, out] msg Reference to smart pointer, that already holds or
                ///     will hold allocated message object, or reference to actual message
                ///     object (which extends @ref nil::marshalling::message_base).
                /// @param[in, out] iter Input iterator used for reading.
                /// @param[in] size Size of the data in the sequence
                /// @param[out] missingSize If not nullptr and return value is
                ///     nil::marshalling::ErrorStatus::NotEnoughData it will contain
                ///     minimal missing data length required for the successful
                ///     read attempt.
                /// @param[in] nextLayerReader Next layer reader object.
                /// @return Status of the read operation.
                /// @pre Iterator must be valid and can be dereferenced and incremented at
                ///      least "size" times;
                /// @post The iterator will be advanced by the number of bytes was actually
                ///       read. In case of an error, distance between original position and
                ///       advanced will pinpoint the location of the error.
                /// @post missingSize output value is updated if and only if function
                ///       returns nil::marshalling::ErrorStatus::NotEnoughData.
                template<typename TMsg, typename TIter, typename TNextLayerReader>
                nil::marshalling::status_type eval_read(field_type &field, TMsg &msg, TIter &iter, std::size_t size,
                                                        std::size_t *missingSize, TNextLayerReader &&nextLayerReader) {
                    auto es = read_field_internal(field, iter, size, missingSize, value_tag());
                    if (es != nil::marshalling::status_type::success) {
                        return es;
                    }

                    es = nextLayerReader.read(msg, iter, size, missingSize);

                    using tag = typename std::conditional<
                        base_impl_type::template is_message_obj_ref<typename std::decay<decltype(msg)>::type>(),
                        msg_obj_tag, smart_ptr_tag>::type;

                    if (valid_msg(msg, tag())) {
                        auto &allTransportFields = transport_fields(msg, tag());
                        auto &transportField = std::get<TIdx>(allTransportFields);

                        using field_type = typename std::decay<decltype(transportField)>::type;
                        using value_type = typename field_type::value_type;

                        transportField.value() = static_cast<value_type>(field.value());
                    }
                    return es;
                }

                /// @brief Customized write functionality, invoked by @ref write().
                /// @details The function will write the appriprate extra transport value
                ///     held by the message object being written.
                /// @tparam TMsg Type of message object.
                /// @tparam TIter Type of iterator used for writing.
                /// @tparam TNextLayerWriter next layer writer object type.
                /// @param[out] field field_type object to update and write.
                /// @param[in] msg Reference to message object
                /// @param[in, out] iter Output iterator.
                /// @param[in] size Max number of bytes that can be written.
                /// @param[in] nextLayerWriter Next layer writer object.
                /// @return Status of the write operation.
                /// @pre Iterator must be valid and can be dereferenced and incremented at
                ///      least "size" times;
                /// @post The iterator will be advanced by the number of bytes was actually
                ///       written. In case of an error, distance between original position
                ///       and advanced will pinpoint the location of the error.
                template<typename TMsg, typename TIter, typename TNextLayerWriter>
                nil::marshalling::status_type eval_write(field_type &field, const TMsg &msg, TIter &iter,
                                                         std::size_t size, TNextLayerWriter &&nextLayerWriter) const {
                    using msg_type = typename std::decay<decltype(msg)>::type;
                    static_assert(msg_type::has_transport_fields(),
                                  "message interface class hasn't defined transport fields, "
                                  "use nil::marshalling::option::extra_transport_fields option.");
                    static_assert(TIdx < std::tuple_size<typename msg_type::transport_fields_type>::value,
                                  "TIdx is too big, exceeds the amount of transport fields defined in interface class");

                    using value_type = typename field_type::value_type;

                    auto &transportField = std::get<TIdx>(msg.transport_fields());
                    field.value() = static_cast<value_type>(transportField.value());

                    auto es = write_field_internal(field, iter, size, value_tag());
                    if (es != status_type::success) {
                        return es;
                    }

                    return nextLayerWriter.write(msg, iter, size);
                }

                /// @brief Customising field length calculation
                /// @details If the layer is marked as "pseudo" (using @ref nil::marshalling::option::PseudoValue)
                ///     option, then the report length is 0.
                static constexpr std::size_t eval_field_length() {
                    return eval_field_length_internal(value_tag());
                }

                /// @brief Customising field length calculation
                /// @details If the layer is marked as "pseudo" (using @ref nil::marshalling::option::PseudoValue)
                ///     option, then the report length is 0.
                template<typename TMsg>
                static std::size_t eval_field_length(const TMsg &) {
                    return eval_field_length();
                }

#ifdef FOR_DOXYGEN_DOC_ONLY
                /// @brief Access to pseudo field stored internally.
                /// @detail The function exists only if @ref nil::marshalling::option::pseudo_value
                ///     option has been used.
                field_type &pseudo_field();

                /// @brief Const access to pseudo field stored internally.
                /// @detail The function exists only if @ref nil::marshalling::option::pseudo_value
                ///     option has been used.
                const field_type &pseudo_field() const;
#endif
            private:
                struct smart_ptr_tag { };
                struct msg_obj_tag { };

                struct pseudo_value_tag { };
                struct normal_value_tag { };

                using value_tag = typename std::conditional<transport_parsed_options_type::has_pseudo_value,
                                                            pseudo_value_tag, normal_value_tag>::type;

                template<typename TMsg>
                static bool valid_msg(TMsg &msgPtr, smart_ptr_tag) {
                    using MsgPtrType = typename std::decay<decltype(msgPtr)>::type;
                    using MessageInterfaceType = typename MsgPtrType::element_type;
                    static_assert(MessageInterfaceType::has_transport_fields(),
                                  "message interface class hasn't defined transport fields, "
                                  "use nil::marshalling::option::extra_transport_fields option.");
                    static_assert(TIdx < std::tuple_size<typename MessageInterfaceType::transport_fields_type>::value,
                                  "TIdx is too big, exceeds the amount of transport fields defined in interface class");

                    return static_cast<bool>(msgPtr);
                }

                template<typename TMsg>
                static bool valid_msg(TMsg &msg, msg_obj_tag) {
                    using msg_type = typename std::decay<decltype(msg)>::type;
                    static_assert(msg_type::has_transport_fields(),
                                  "message interface class hasn't defined transport fields, "
                                  "use nil::marshalling::option::extra_transport_fields option.");
                    static_assert(TIdx < std::tuple_size<typename msg_type::transport_fields_type>::value,
                                  "TIdx is too big, exceeds the amount of transport fields defined in interface class");

                    return true;
                }

                template<typename TMsg>
                static auto transport_fields(TMsg &msgPtr, smart_ptr_tag) -> decltype(msgPtr->transport_fields()) {
                    return msgPtr->transport_fields();
                }

                template<typename TMsg>
                static auto transport_fields(TMsg &msg, msg_obj_tag) -> decltype(msg.transport_fields()) {
                    return msg.transport_fields();
                }

                static constexpr std::size_t eval_field_length_internal(pseudo_value_tag) {
                    return 0U;
                }

                static constexpr std::size_t eval_field_length_internal(normal_value_tag) {
                    return base_impl_type::eval_field_length();
                }

                template<typename TIter>
                nil::marshalling::status_type read_field_internal(field_type &field, TIter &iter, std::size_t &len,
                                                                  std::size_t *missingSize, pseudo_value_tag) {
                    static_cast<void>(iter);
                    static_cast<void>(len);
                    static_cast<void>(missingSize);
                    field = base_impl_type::pseudo_field();
                    return nil::marshalling::status_type::success;
                }

                template<typename TIter>
                nil::marshalling::status_type read_field_internal(field_type &field, TIter &iter, std::size_t &len,
                                                                  std::size_t *missingSize, normal_value_tag) {
                    auto es = field.read(iter, len);
                    if (es == nil::marshalling::status_type::not_enough_data) {
                        base_impl_type::update_missing_size(field, len, missingSize);
                    } else {
                        len -= field.length();
                    }
                    return es;
                }

                template<typename TIter>
                nil::marshalling::status_type write_field_internal(field_type &field, TIter &iter, std::size_t &len,
                                                                   pseudo_value_tag) const {
                    static_cast<void>(iter);
                    static_cast<void>(len);
                    field = base_impl_type::pseudo_field();
                    return nil::marshalling::status_type::success;
                }

                template<typename TIter>
                nil::marshalling::status_type write_field_internal(field_type &field, TIter &iter, std::size_t &len,
                                                                   normal_value_tag) const {
                    auto es = field.write(iter, len);
                    if (es == nil::marshalling::status_type::success) {
                        MARSHALLING_ASSERT(field.length() <= len);
                        len -= field.length();
                    }
                    return es;
                }
            };

            namespace detail {
                template<typename T>
                struct transport_value_layer_check_helper {
                    static const bool value = false;
                };

                template<typename TField, std::size_t TIdx, typename TNextLayer>
                struct transport_value_layer_check_helper<transport_value_layer<TField, TIdx, TNextLayer>> {
                    static const bool value = true;
                };

            }    // namespace detail

            /// @brief Compile time check of whether the provided type is
            ///     a variant of @ref TransportValueLayer
            /// @related TransportValueLayer
            template<typename T>
            constexpr bool is_transport_value_layer() {
                return detail::transport_value_layer_check_helper<T>::value;
            }

        }    // namespace protocol
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_TRANSPORT_VALUE_LAYER_HPP
