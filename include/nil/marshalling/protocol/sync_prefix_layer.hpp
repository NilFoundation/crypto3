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

#ifndef MARSHALLING_SYNC_PREFIX_LAYER_HPP
#define MARSHALLING_SYNC_PREFIX_LAYER_HPP

#include <nil/marshalling/protocol/protocol_layer_base.hpp>

namespace nil {
    namespace marshalling {
        namespace protocol {

            /// @brief Protocol layer that uses "sync" field as a prefix to all the
            ///        subsequent data written by other (next) layers.
            /// @details The main purpose of this layer is to provide a constant synchronisation
            ///     prefix to help identify the beginning of the serialized message.
            ///     This layer is a mid level layer, expects other mid level layer or
            ///     MsgDataLayer to be its next one.
            /// @tparam TField Type of the field that is used as sync prefix. The "sync"
            ///     field type definition must use options (nil::marshalling::option::DefaultNumValue)
            ///     to specify its default value to be equal to the expected "sync" value.
            /// @tparam TNextLayer Next transport layer in protocol stack.
            /// @headerfile nil/marshalling/protocol/SyncPrefixLayer.h
            template<typename TField, typename TNextLayer>
            class sync_prefix_layer
                : public protocol_layer_base<TField, TNextLayer, sync_prefix_layer<TField, TNextLayer>> {
                using base_impl_type = protocol_layer_base<TField, TNextLayer, sync_prefix_layer<TField, TNextLayer>>;

            public:
                /// @brief Type of the field object used to read/write "sync" value.
                using field_type = typename base_impl_type::field_type;

                /// @brief Default constructor
                sync_prefix_layer() = default;

                /// @brief Copy constructor.
                sync_prefix_layer(const sync_prefix_layer &) = default;

                /// @brief Move constructor.
                sync_prefix_layer(sync_prefix_layer &&) = default;

                /// @brief Destructor
                ~sync_prefix_layer() noexcept = default;

                /// @brief Customized read functionality, invoked by @ref read().
                /// @details Reads the "sync" value from the input data. If the read value
                ///     is NOT as expected (doesn't equal to the default constructed
                ///     @ref field_type), then nil::marshalling::ErrorStatus::ProtocolError is returned.
                ////    If the read "sync" value as expected, the read() member function of
                ///     the next layer is called.
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
                    auto es = field.read(iter, size);
                    if (es == nil::marshalling::status_type::not_enough_data) {
                        base_impl_type::update_missing_size(field, size, missingSize);
                    }

                    if (es != nil::marshalling::status_type::success) {
                        return es;
                    }

                    if (field != field_type()) {
                        // doesn't match expected
                        return nil::marshalling::status_type::protocol_error;
                    }

                    return nextLayerReader.read(msg, iter, size - field.length(), missingSize);
                }

                /// @brief Customized write functionality, invoked by @ref write().
                /// @details The function will write proper "sync" value to the output
                ///     buffer, then call the write() function of the next layer.
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
                    auto es = field.write(iter, size);
                    if (es != status_type::success) {
                        return es;
                    }

                    MARSHALLING_ASSERT(field.length() <= size);
                    return nextLayerWriter.write(msg, iter, size - field.length());
                }
            };

            namespace detail {
                template<typename T>
                struct sync_prefix_layer_check_helper {
                    static const bool value = false;
                };

                template<typename TField, typename TNextLayer>
                struct sync_prefix_layer_check_helper<sync_prefix_layer<TField, TNextLayer>> {
                    static const bool value = true;
                };

            }    // namespace detail

            /// @brief Compile time check of whether the provided type is
            ///     a variant of @ref SyncPrefixLayer
            /// @related SyncPrefixLayer
            template<typename T>
            constexpr bool is_sync_prefix_layer() {
                return detail::sync_prefix_layer_check_helper<T>::value;
            }

        }    // namespace protocol
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_SYNC_PREFIX_LAYER_HPP
