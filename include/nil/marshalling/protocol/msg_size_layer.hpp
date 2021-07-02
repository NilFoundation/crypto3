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

#ifndef MARSHALLING_MSG_SIZE_LAYER_HPP
#define MARSHALLING_MSG_SIZE_LAYER_HPP

#include <iterator>
#include <type_traits>
#include <nil/marshalling/types/int_value.hpp>
#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/protocol/protocol_layer_base.hpp>

namespace nil {
    namespace marshalling {
        namespace protocol {

            /// @brief Protocol layer that uses size field as a prefix to all the
            ///        subsequent data written by other (next) layers.
            /// @details The main purpose of this layer is to provide information about
            ///     the remaining size of the serialized message. This layer is a mid level
            ///     layer, expects other mid level layer or MsgDataLayer to be its next one.
            /// @tparam TField Type of the field that describes the "size" field.
            /// @tparam TNextLayer Next transport layer in protocol stack.
            /// @headerfile nil/marshalling/protocol/MsgSizeLayer.h
            template<typename TField, typename TNextLayer>
            class msg_size_layer
                : public protocol_layer_base<TField, TNextLayer, msg_size_layer<TField, TNextLayer>,
                                             nil::marshalling::option::protocol_layer_disallow_read_until_data_split> {
                using base_impl_type
                    = protocol_layer_base<TField, TNextLayer, msg_size_layer<TField, TNextLayer>,
                                          nil::marshalling::option::protocol_layer_disallow_read_until_data_split>;

            public:
                /// @brief Type of the field object used to read/write remaining size value.
                using field_type = typename base_impl_type::field_type;

                static_assert(is_int_value<field_type>::value,
                              "field_type must be of int_value type");

                /// @brief Default constructor
                explicit msg_size_layer() = default;

                /// @brief Copy constructor
                msg_size_layer(const msg_size_layer &) = default;

                /// @brief Move constructor
                msg_size_layer(msg_size_layer &&) = default;

                /// @brief Destructor.
                ~msg_size_layer() noexcept = default;

                /// @brief Copy assignment.
                msg_size_layer &operator=(const msg_size_layer &) = default;

                /// @brief Move assignment.
                msg_size_layer &operator=(msg_size_layer &&) = default;

                /// @cond SKIP_DOC

                static constexpr std::size_t eval_field_length() {
                    return base_impl_type::eval_field_length();
                }

                template<typename TMsg>
                constexpr std::size_t eval_field_length(const TMsg &msg) const {
                    return field_length_internal(msg, length_tag());
                }
                /// @endcond

                /// @brief Customized read functionality, invoked by @ref read().
                /// @details Reads size of the subsequent data from the input data sequence
                ///          and calls read() member function of the next layer with
                ///          the size specified in the size field. The function will also
                ///          compare the provided size of the data with value
                ///          read from the buffer. If the latter is greater than
                ///          former, nil::marshalling::ErrorStatus::NotEnoughData will be returned.
                ///          However, if buffer contains enough data, but the next layer
                ///          reports it's not enough (returns nil::marshalling::ErrorStatus::NotEnoughData),
                ///          nil::marshalling::ErrorStatus::ProtocolError will be returned.
                /// @tparam TMsg Type of @b msg parameter.
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
                    using IterType = typename std::decay<decltype(iter)>::type;
                    using IterTag = typename std::iterator_traits<IterType>::iterator_category;
                    static_assert(std::is_base_of<std::random_access_iterator_tag, IterTag>::value,
                                  "Current implementation of msg_size_layer requires iterator used for reading to be "
                                  "random-access one.");

                    auto es = field.read(iter, size);
                    if (es == status_type::not_enough_data) {
                        base_impl_type::update_missing_size(field, size, missingSize);
                    }

                    if (es != status_type::success) {
                        return es;
                    }

                    auto fromIter = iter;
                    auto actualRemainingSize = (size - field.length());
                    auto requiredRemainingSize = static_cast<std::size_t>(field.value());

                    if (actualRemainingSize < requiredRemainingSize) {
                        if (missingSize != nullptr) {
                            *missingSize = requiredRemainingSize - actualRemainingSize;
                        }
                        return status_type::not_enough_data;
                    }

                    // not passing missingSize farther on purpose
                    es = nextLayerReader.read(msg, iter, requiredRemainingSize, nullptr);
                    if (es == status_type::not_enough_data) {
                        base_impl_type::reset_msg(msg);
                        return status_type::protocol_error;
                    }

                    if (es != status_type::protocol_error) {
                        iter = fromIter;
                        std::advance(iter, requiredRemainingSize);
                    }

                    auto consumed = static_cast<std::size_t>(std::distance(fromIter, iter));
                    if (consumed < requiredRemainingSize) {
                        auto diff = requiredRemainingSize - consumed;
                        std::advance(iter, diff);
                    }
                    return es;
                }

                /// @brief Customized write functionality, invoked by @ref write().
                /// @details The function will write number of bytes required to serialise
                ///     the message, then invoke the write() member function of the next
                ///     layer. The calculation of the required length is performed by invoking
                ///     "length(msg)".
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
                status_type eval_write(field_type &field, const TMsg &msg, TIter &iter, std::size_t size,
                                       TNextLayerWriter &&nextLayerWriter) const {
                    using msg_type = typename std::decay<decltype(msg)>::type;
                    return write_internal(field, msg, iter, size, std::forward<TNextLayerWriter>(nextLayerWriter),
                                          msg_length_tag<msg_type>());
                }

                /// @brief Customized update functionality, invoked by @ref update().
                /// @details Should be called when @ref eval_write() returns
                /// nil::marshalling::ErrorStatus::UpdateRequired.
                /// @tparam TIter Type of iterator used for updating.
                /// @tparam TNextLayerWriter next layer updater object type.
                /// @param[out] field field_type object to update.
                /// @param[in, out] iter Any random access iterator.
                /// @param[in] size Number of bytes that have been written using write().
                /// @param[in] nextLayerUpdater Next layer updater object.
                /// @return Status of the update operation.
                template<typename TIter, typename TNextLayerUpdater>
                nil::marshalling::status_type eval_update(field_type &field, TIter &iter, std::size_t size,
                                                          TNextLayerUpdater &&nextLayerUpdater) const {
                    field.value() = size - field_type::max_length();
                    if (field.length() != field_type::max_length()) {
                        field.value() = size - field.length();
                    }

                    auto es = field.write(iter, size);
                    if (es != status_type::success) {
                        return es;
                    }

                    return nextLayerUpdater.update(iter, size - field.length());
                }

            private:
                using fixed_length_tag = typename base_impl_type::fixed_length_tag;
                using var_length_tag = typename base_impl_type::var_length_tag;
                using length_tag = typename base_impl_type::length_tag;
                struct msg_has_length_tag { };
                struct msg_no_length_tag { };

                template<typename TMsg>
                using msg_length_tag = typename std::conditional<detail::protocol_layer_has_fields_impl<TMsg>::value
                                                                     || TMsg::interface_options_type::has_length,
                                                                 msg_has_length_tag, msg_no_length_tag>::type;

                template<typename TMsg, typename TIter, typename TWriter>
                status_type write_internal_has_length(field_type &field, const TMsg &msg, TIter &iter, std::size_t size,
                                                      TWriter &&nextLayerWriter) const {
                    using FieldValueType = typename field_type::value_type;
                    field.value() = static_cast<FieldValueType>(base_impl_type::next_layer().length(msg));
                    auto es = field.write(iter, size);
                    if (es != status_type::success) {
                        return es;
                    }

                    MARSHALLING_ASSERT(field.length() <= size);
                    return nextLayerWriter.write(msg, iter, size - field.length());
                }

                template<typename TMsg, typename TIter, typename TWriter>
                status_type write_internal_random_access(field_type &field, const TMsg &msg, TIter &iter,
                                                         std::size_t size, TWriter &&nextLayerWriter) const {
                    auto valueIter = iter;

                    field.value() = 0;
                    auto es = field.write(iter, size);
                    if (es != status_type::success) {
                        return es;
                    }

                    auto dataIter = iter;

                    auto sizeLen = field.length();
                    es = nextLayerWriter.write(msg, iter, size - sizeLen);
                    if (es != status_type::success) {
                        return es;
                    }

                    field.value() = static_cast<typename field_type::value_type>(std::distance(dataIter, iter));
                    MARSHALLING_ASSERT(field.length() == sizeLen);
                    return field.write(valueIter, sizeLen);
                }

                template<typename TMsg, typename TIter, typename TWriter>
                status_type write_internal_output(field_type &field, const TMsg &msg, TIter &iter, std::size_t size,
                                                  TWriter &&nextLayerWriter) const {
                    field.value() = 0;
                    auto es = field.write(iter, size);
                    if (es != status_type::success) {
                        return es;
                    }

                    es = nextLayerWriter.write(msg, iter, size - field.length());
                    if ((es != status_type::success) && (es != status_type::update_required)) {
                        return es;
                    }

                    return status_type::update_required;
                }

                template<typename TMsg, typename TIter, typename TWriter>
                status_type write_internal_no_length_tagged(field_type &field, const TMsg &msg, TIter &iter,
                                                            std::size_t size, TWriter &&nextLayerWriter,
                                                            std::random_access_iterator_tag) const {
                    return write_internal_random_access(field, msg, iter, size, std::forward<TWriter>(nextLayerWriter));
                }

                template<typename TMsg, typename TIter, typename TWriter>
                status_type write_internal_no_length_tagged(field_type &field, const TMsg &msg, TIter &iter,
                                                            std::size_t size, TWriter &&nextLayerWriter,
                                                            std::output_iterator_tag) const {
                    return write_internal_output(field, msg, iter, size, std::forward<TWriter>(nextLayerWriter));
                }

                template<typename TMsg, typename TIter, typename TWriter>
                status_type write_internal_no_length(field_type &field, const TMsg &msg, TIter &iter, std::size_t size,
                                                     TWriter &&nextLayerWriter) const {
                    using IterType = typename std::decay<decltype(iter)>::type;
                    using tag = typename std::iterator_traits<IterType>::iterator_category;
                    return write_internal_no_length_tagged(field, msg, iter, size,
                                                           std::forward<TWriter>(nextLayerWriter), tag());
                }

                template<typename TMsg, typename TIter, typename TWriter>
                status_type write_internal(field_type &field, const TMsg &msg, TIter &iter, std::size_t size,
                                           TWriter &&nextLayerWriter, msg_has_length_tag) const {
                    return write_internal_has_length(field, msg, iter, size, std::forward<TWriter>(nextLayerWriter));
                }

                template<typename TMsg, typename TIter, typename TWriter>
                status_type write_internal(field_type &field, const TMsg &msg, TIter &iter, std::size_t size,
                                           TWriter &&nextLayerWriter, msg_no_length_tag) const {
                    return write_internal_no_length(field, msg, iter, size, std::forward<TWriter>(nextLayerWriter));
                }

                template<typename TMsg>
                constexpr std::size_t field_length_internal(const TMsg &msg, fixed_length_tag) const {
                    return base_impl_type::eval_field_length(msg);
                }

                template<typename TMsg>
                std::size_t field_length_internal(const TMsg &msg, var_length_tag) const {
                    using FieldValueType = typename field_type::value_type;
                    auto remSize = base_impl_type::next_layer().length(msg);
                    return field_type(static_cast<FieldValueType>(remSize)).length();
                }
            };

            namespace detail {
                template<typename T>
                struct msg_size_layer_check_helper {
                    static const bool value = false;
                };

                template<typename TField, typename TNextLayer>
                struct msg_size_layer_check_helper<msg_size_layer<TField, TNextLayer>> {
                    static const bool value = true;
                };

            }    // namespace detail

            /// @brief Compile time check of whether the provided type is
            ///     a variant of @ref MsgSizeLayer
            /// @related MsgSizeLayer
            template<typename T>
            constexpr bool is_msg_size_layer() {
                return detail::msg_size_layer_check_helper<T>::value;
            }

        }    // namespace protocol
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MSG_SIZE_LAYER_HPP
