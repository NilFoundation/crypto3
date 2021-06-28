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

#ifndef MARSHALLING_CHECKSUM_PREFIX_LAYER_HPP
#define MARSHALLING_CHECKSUM_PREFIX_LAYER_HPP

#include <iterator>
#include <type_traits>
#include <nil/marshalling/types/int_value.hpp>
#include <nil/marshalling/protocol/protocol_layer_base.hpp>
#include <nil/marshalling/protocol/detail/checksum_layer_options_parser.hpp>

namespace nil {
    namespace marshalling {

        namespace protocol {
            /// @brief Protocol layer that is responsible to calculate checksum on the
            ///     data written by all the wrapped internal layers and prepend it before
            ///     the written data. When reading, this layer is responsible to verify
            ///     the checksum reported at the beginning of the read data.
            /// @details This protocol layer handles checksum value that usually precedes the
            ///     data. Some protocols use checksum value that follows the data. In this
            ///     case use @ref ChecksumLayer instead.
            /// @tparam TField Type of the field that is used as to represent checksum value.
            /// @tparam TCalc The checksum calculater class that is used to calculate
            ///     the checksum value on the provided buffer. It must have the operator()
            ///     defined with the following signature:
            ///     @code
            ///     template <typename TIter>
            ///     ResultType operator()(TIter& iter, std::size_t len) const;
            ///     @endcode
            ///     It is up to the checksum calculator to choose the "ResultType" it
            ///     returns. The falue is going to be casted to field_type::value_type before
            ///     assigning it as a value of the check field being read and/or written.
            /// @tparam TNextLayer Next transport layer in protocol stack.
            /// @tparam TOptions Extending functionality options. Supported options are:
            ///     @li @ref nil::marshalling::option::ChecksumLayerVerifyBeforeRead - By default, the
            ///         @b ChecksumPrefixLayer will invoke @b read operation of inner (wrapped) layers
            ///         and only if it is successful, it will calculate and verify the
            ///         checksum value. Usage of @ref nil::marshalling::option::ChecksumLayerVerifyBeforeRead
            ///         modifies the default behaviour by forcing the checksum verification
            ///         prior to invocation of @b read operation in the wrapped layer(s).
            /// @headerfile nil/marshalling/protocol/ChecksumPrefixLayer.h
            template<typename TField, typename TCalc, typename TNextLayer, typename... TOptions>
            class checksum_prefix_layer
                : public protocol_layer_base<TField, TNextLayer,
                                             checksum_prefix_layer<TField, TCalc, TNextLayer, TOptions...>,
                                             nil::marshalling::option::protocol_layer_disallow_read_until_data_split> {
                using base_impl_type
                    = protocol_layer_base<TField, TNextLayer,
                                          checksum_prefix_layer<TField, TCalc, TNextLayer, TOptions...>,
                                          nil::marshalling::option::protocol_layer_disallow_read_until_data_split>;

            public:
                /// @brief Parsed options
                using parsed_options_type = detail::checksum_layer_options_parser<TOptions...>;

                /// @brief Type of the field object used to read/write checksum value.
                using field_type = typename base_impl_type::field_type;

                /// @brief Default constructor.
                checksum_prefix_layer() = default;

                /// @brief Copy constructor
                checksum_prefix_layer(const checksum_prefix_layer &) = default;

                /// @brief Move constructor
                checksum_prefix_layer(checksum_prefix_layer &&) = default;

                /// @brief Destructor.
                ~checksum_prefix_layer() noexcept = default;

                /// @brief Copy assignment
                checksum_prefix_layer &operator=(const checksum_prefix_layer &) = default;

                /// @brief Move assignment
                checksum_prefix_layer &operator=(checksum_prefix_layer &&) = default;

                /// @brief Customized read functionality, invoked by @ref read().
                /// @details First, reads the expected checksum value field, then
                ///     executes the read() member function of the next layer.
                ///     If the call returns nil::marshalling::ErrorStatus::Success, it calculated the
                ///     checksum of the read data and
                ///     compares it to the calculated. If checksums match,
                ///     nil::marshalling::ErrorStatus::Success is returned, otherwise
                ///     function returns nil::marshalling::ErrorStatus::ProtocolError.
                /// @tparam TMsg Type of the @b msg parameter.
                /// @tparam TIter Type of iterator used for reading.
                /// @tparam TNextLayerReader next layer reader object type.
                /// @param[out] field field_type object to read.
                /// @param[in, out] msg Reference to smart pointer that already holds or
                ///     will hold allocated message object
                /// @param[in, out] iter Input iterator used for reading.
                /// @param[in] size Size of the data in the sequence
                /// @param[out] missingSize If not nullptr and return value is
                ///     nil::marshalling::ErrorStatus::NotEnoughData it will contain
                ///     minimal missing data length required for the successful
                ///     read attempt.
                /// @param[in] nextLayerReader Next layer reader object.
                /// @return Status of the read operation.
                /// @pre Iterator must be "random access" one.
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
                    static_assert(std::is_same<typename std::iterator_traits<IterType>::iterator_category,
                                               std::random_access_iterator_tag>::value,
                                  "The read operation is expected to use random access iterator");

                    if (size < field_type::min_length()) {
                        return status_type::not_enough_data;
                    }

                    auto checksumEs = field.read(iter, field_type::min_length());
                    if (checksumEs == status_type::not_enough_data) {
                        base_impl_type::update_missing_size(field, size, missingSize);
                    }

                    if (checksumEs != status_type::success) {
                        return checksumEs;
                    }

                    return read_internal(field, msg, iter, size - field.length(), missingSize,
                                         std::forward<TNextLayerReader>(nextLayerReader), verify_tag());
                }

                /// @brief Customized write functionality, invoked by @ref write().
                /// @details First, reserves the appropriate number of bytes in the
                ///     output buffer which are supposed to contain valid checksum
                ///     value, then executes the write() member function of the next layer.
                ///     If the call returns nil::marshalling::ErrorStatus::Success and it is possible
                ///     to re-read what has been written (random access iterator is used
                ///     for writing), the real checksum value is calculated and updated in the
                ///     previously reserved area. In case non-random access iterator
                ///     type is used for writing (for example std::back_insert_iterator), then
                ///     this function returns
                ///     nil::marshalling::ErrorStatus::UpdateRequired to indicate that call to
                ///     update() with random access iterator is required in order to be
                ///     able to update written checksum information.
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
                    using IterType = typename std::decay<decltype(iter)>::type;
                    using tag = typename std::iterator_traits<IterType>::iterator_category;

                    field.value() = 0;
                    return write_internal(field, msg, iter, size, std::forward<TNextLayerWriter>(nextLayerWriter),
                                          tag());
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
                    auto checksumIter = iter;
                    std::advance(iter, field_type::max_length());

                    auto fromIter = iter;
                    auto es = nextLayerUpdater.update(iter, size - field_type::max_length());
                    if (es != nil::marshalling::status_type::success) {
                        return es;
                    }

                    MARSHALLING_ASSERT(fromIter <= iter);
                    auto len = static_cast<std::size_t>(std::distance(fromIter, iter));
                    MARSHALLING_ASSERT(len == (size - field_type::max_length()));
                    using FieldValueType = typename field_type::value_type;
                    field.value() = static_cast<FieldValueType>(TCalc()(fromIter, len));
                    es = field.write(checksumIter, field_type::max_length());
                    return es;
                }

            private:
                static_assert(is_int_value<field_type>::value,
                              "The checksum field is expected to be of int_value type");

                static_assert(field_type::min_length() == field_type::max_length(),
                              "The checksum field is expected to be of fixed length");

                struct verify_before_read_tag { };
                struct verify_after_read_tag { };

                using verify_tag = typename std::conditional<parsed_options_type::has_verify_before_read,
                                                             verify_before_read_tag, verify_after_read_tag>::type;

                template<typename TMsg, typename TIter, typename TReader>
                status_type verify_read(field_type &field, TMsg &msg, TIter &iter, std::size_t size,
                                        std::size_t *missingSize, TReader &&nextLayerReader) {
                    auto fromIter = iter;

                    auto checksum = TCalc()(fromIter, size);
                    auto expectedValue = field.value();

                    if (expectedValue != static_cast<decltype(expectedValue)>(checksum)) {
                        base_impl_type::reset_msg(msg);
                        return status_type::protocol_error;
                    }

                    return nextLayerReader.read(msg, iter, size, missingSize);
                }

                template<typename TMsg, typename TIter, typename TReader>
                status_type read_verify(field_type &field, TMsg &msg, TIter &iter, std::size_t size,
                                        std::size_t *missingSize, TReader &&nextLayerReader) {
                    auto fromIter = iter;

                    auto es = nextLayerReader.read(msg, iter, size, missingSize);
                    if ((es == status_type::not_enough_data) || (es == status_type::protocol_error)) {
                        return es;
                    }

                    auto len = static_cast<std::size_t>(std::distance(fromIter, iter));
                    auto checksum = TCalc()(fromIter, len);
                    auto expectedValue = field.value();

                    if (expectedValue != static_cast<decltype(expectedValue)>(checksum)) {
                        base_impl_type::reset_msg(msg);
                        return status_type::protocol_error;
                    }

                    return es;
                }

                template<typename TMsg, typename TIter, typename TReader>
                status_type read_internal(field_type &field, TMsg &msg, TIter &iter, std::size_t size,
                                          std::size_t *missingSize, TReader &&nextLayerReader, verify_before_read_tag) {
                    return verify_read(field, msg, iter, size, missingSize, std::forward<TReader>(nextLayerReader));
                }

                template<typename TMsg, typename TIter, typename TReader>
                status_type read_internal(field_type &field, TMsg &msg, TIter &iter, std::size_t size,
                                          std::size_t *missingSize, TReader &&nextLayerReader, verify_after_read_tag) {
                    return read_verify(field, msg, iter, size, missingSize, std::forward<TReader>(nextLayerReader));
                }

                template<typename TMsg, typename TIter, typename TWriter>
                status_type write_internal_random_access(field_type &field, const TMsg &msg, TIter &iter,
                                                         std::size_t size, TWriter &&nextLayerWriter) const {
                    auto checksumIter = iter;
                    auto es = field.write(iter, size);
                    if (es != nil::marshalling::status_type::success) {
                        return es;
                    }

                    auto checksumLen = static_cast<std::size_t>(std::distance(checksumIter, iter));

                    auto fromIter = iter;
                    es = nextLayerWriter.write(msg, iter, size - checksumLen);
                    if (es != nil::marshalling::status_type::success) {
                        return es;
                    }

                    MARSHALLING_ASSERT(fromIter <= iter);
                    auto len = static_cast<std::size_t>(std::distance(fromIter, iter));

                    using FieldValueType = typename field_type::value_type;
                    auto checksum = TCalc()(fromIter, len);
                    field.value() = static_cast<FieldValueType>(checksum);

                    auto checksumEs = field.write(checksumIter, checksumLen);
                    static_cast<void>(checksumEs);
                    MARSHALLING_ASSERT(checksumEs == nil::marshalling::status_type::success);
                    return es;
                }

                template<typename TMsg, typename TIter, typename TWriter>
                status_type write_internal_output(field_type &field, const TMsg &msg, TIter &iter, std::size_t size,
                                                  TWriter &&nextLayerWriter) const {
                    auto es = field.write(iter, size);
                    if (es != nil::marshalling::status_type::success) {
                        return es;
                    }

                    es = nextLayerWriter.write(msg, iter, size - field_type::max_length());
                    if (es != nil::marshalling::status_type::success) {
                        return es;
                    }

                    return nil::marshalling::status_type::update_required;
                }

                template<typename TMsg, typename TIter, typename TWriter>
                status_type write_internal(field_type &field, const TMsg &msg, TIter &iter, std::size_t size,
                                           TWriter &&nextLayerWriter, std::random_access_iterator_tag) const {
                    return write_internal_random_access(field, msg, iter, size, std::forward<TWriter>(nextLayerWriter));
                }

                template<typename TMsg, typename TIter, typename TWriter>
                status_type write_internal(field_type &field, const TMsg &msg, TIter &iter, std::size_t size,
                                           TWriter &&nextLayerWriter, std::output_iterator_tag) const {
                    return write_internal_output(field, msg, iter, size, std::forward<TWriter>(nextLayerWriter));
                }
            };

            namespace detail {
                template<typename T>
                struct checksum_prefix_layer_check_helper {
                    static const bool value = false;
                };

                template<typename TField, typename TCalc, typename TNextLayer, typename... TOptions>
                struct checksum_prefix_layer_check_helper<
                    checksum_prefix_layer<TField, TCalc, TNextLayer, TOptions...>> {
                    static const bool value = true;
                };

            }    // namespace detail

            /// @brief Compile time check of whether the provided type is
            ///     a variant of @ref ChecksumPrefixLayer
            /// @related ChecksumLayer
            template<typename T>
            constexpr bool is_checksum_prefix_layer() {
                return detail::checksum_prefix_layer_check_helper<T>::value;
            }

        }    // namespace protocol

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_CHECKSUM_PREFIX_LAYER_HPP
