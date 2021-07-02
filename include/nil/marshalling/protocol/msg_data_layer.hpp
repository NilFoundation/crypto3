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

#ifndef MARSHALLING_MSG_DATA_LAYER_HPP
#define MARSHALLING_MSG_DATA_LAYER_HPP

#include <tuple>
#include <iterator>
#include <type_traits>

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/processing/tuple.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/int_value.hpp>
#include <nil/marshalling/message.hpp>
#include <nil/marshalling/message_base.hpp>
#include <nil/marshalling/protocol/protocol_layer_base.hpp>

namespace nil {
    namespace marshalling {

        namespace protocol {

            /// @brief Message data layer.
            /// @details Must always be the last layer in protocol stack.
            /// @tparam TExtraOpts Extra options to inner @ref field_type type which is defined
            ///     to be @ref nil::marshalling::types::array_list. This field is used only in @ref
            ///     all_fields_type type and @ref read_fields_cached() member function.
            /// @headerfile nil/marshalling/protocol/MsgDataLayer.h
            template<typename... TExtraOpts>
            class msg_data_layer {
            public:
                /// @brief Type of this layer
                using this_layer_type = msg_data_layer<TExtraOpts...>;

                /// @brief Get access to this layer object.
                this_layer_type &this_layer() {
                    return *this;
                }

                /// @brief Get "const" access to this layer object.
                const this_layer_type &this_layer() const {
                    return *this;
                }

                /// @brief Raw data field type.
                /// @details This field is used only in @ref all_fields_type field and @ref
                ///     read_fields_cached() member function.
                using field_type = nil::marshalling::types::array_list<
                    nil::marshalling::field_type<nil::marshalling::option::big_endian>, std::uint8_t, TExtraOpts...>;

                /// @brief All fields of the remaining transport layers, contains only @ref field_type.
                using all_fields_type = std::tuple<field_type>;

                /// @brief Static constant indicating amount of transport layers used.
                static const std::size_t layers_amount = 1;

                /// @brief Default constructor
                msg_data_layer() = default;

                /// @brief Copy constructor
                msg_data_layer(const msg_data_layer &) = default;

                /// @brief Move constructor
                msg_data_layer(msg_data_layer &&) = default;

                /// @brief Destructor
                ~msg_data_layer() noexcept = default;

                /// @brief Copy assignment operator
                msg_data_layer &operator=(const msg_data_layer &) = default;

                /// @brief Move assignment operator
                msg_data_layer &operator=(msg_data_layer &&) = default;

                /// @brief Compile time check whether split read "until" and "from" data
                ///     layer is allowed.
                /// @return Always @b true.
                static constexpr bool can_split_read() {
                    return true;
                }

                /// @brief Read the message contents.
                /// @details Calls the read() member function of the message object.
                /// @tparam TMsg Type of the @b msg parameter.
                /// @tparam TIter Type of iterator used for reading.
                /// @param[in] msg Reference to the smart pointer holding message object or
                ///     to the message object itself.
                /// @param[in, out] iter Iterator used for reading.
                /// @param[in] size Number of bytes available for reading.
                /// @param[out] missingSize In case there are not enough bytes in the buffer
                ///     (the function returns nil::marshalling::ErrorStatus::NotEnoughData), and this
                ///     pointer is not nullptr, then it is used to provide information of
                ///     minimal number of bytes that need to be provided before message could
                ///     be successfully read.
                /// @return Status of the read operation.
                /// @pre If @b msg is a smart pointer to message object, it must point to
                ///     a real object.
                /// @post missingSize output value is updated if and only if function
                ///       returns nil::marshalling::ErrorStatus::NotEnoughData.
                template<typename TMsg, typename TIter>
                static status_type read(TMsg &msg, TIter &iter, std::size_t size, std::size_t *missingSize = nullptr) {

                    using msg_type = typename std::decay<decltype(msg)>::type;
                    using tag = typename std::conditional<has_type_impl_options_type<msg_type>::value,
                                                          direct_op_tag, polymorphic_op_tag>::type;

                    return read_internal(msg, iter, size, missingSize, tag());
                }

                /// @brief Read transport fields until data layer.
                /// @details Does nothing because it is data layer.
                /// @return @ref nil::marshalling::ErrorStatus::Success;
                template<typename TMsg, typename TIter>
                static status_type read_until_data(TMsg &msg, TIter &iter, std::size_t size,
                                                   std::size_t *missingSize = nullptr) {
                    static_cast<void>(msg);
                    static_cast<void>(iter);
                    static_cast<void>(size);
                    static_cast<void>(missingSize);
                    return nil::marshalling::status_type::success;
                }

                /// @brief Same as @ref read().
                /// @details Expected to be called by the privous layers to properly
                ///     finalise read operation after the call to @ref read_until_data();
                /// @return @ref nil::marshalling::ErrorStatus::Success;
                template<typename TMsg, typename TIter>
                static status_type read_from_data(TMsg &msg, TIter &iter, std::size_t size,
                                                  std::size_t *missingSize = nullptr) {
                    return read(msg, iter, size, missingSize);
                }

                /// @brief Read the message contents while caching the read transport
                ///     information fields.
                /// @details Very similar to read() member function, but adds "allFields"
                ///     parameter to store raw data of the message.
                /// @tparam TIdx Index of the data field in Tall_fields_type, expected to be last
                ///     element in the tuple.
                /// @tparam Tall_fields_type std::tuple of all the transport fields, must be
                ///     @ref all_fields_type type defined in the last layer class that defines
                ///     protocol stack.
                /// @tparam TMsg Type of the @b msg parameter
                /// @tparam TIter Type of iterator used for reading.
                /// @param[out] allFields Reference to the std::tuple object that wraps all
                ///     transport fields (@ref all_fields_type type of the last protocol layer class).
                /// @param[in] msg Reference to the smart pointer holding message object or
                ///     to the message object itself.
                /// @param[in, out] iter Iterator used for reading.
                /// @param[in] size Number of bytes available for reading.
                /// @param[out] missingSize In case there are not enough bytes in the buffer
                ///     (the function returns nil::marshalling::ErrorStatus::NotEnoughData), and this
                ///     pointer is not nullptr, then it is used to provide information of
                ///     minimal number of bytes that need to be provided before message could
                ///     be successfully read.
                /// @return Status of the read operation.
                template<typename TAllFields, typename TMsg, typename TIter>
                static status_type read_fields_cached(TAllFields &allFields, TMsg &msg, TIter &iter, std::size_t size,
                                                      std::size_t *missingSize = nullptr) {

                    static_assert(nil::detail::is_tuple<TAllFields>::value,
                                  "Expected Tall_fields_type to be tuple.");

                    using AllFieldsDecayed = typename std::decay<TAllFields>::type;
                    static_assert(processing::tuple_is_tail_of<all_fields_type, AllFieldsDecayed>(),
                                  "Passed tuple is wrong.");
                    static const std::size_t Idx
                        = std::tuple_size<AllFieldsDecayed>::value - std::tuple_size<all_fields_type>::value;

                    static_assert((Idx + 1) == std::tuple_size<TAllFields>::value,
                                  "All fields must be read when msg_data_layer is reached");

                    using IterType = typename std::decay<decltype(iter)>::type;
                    using IterTag = typename std::iterator_traits<IterType>::iterator_category;
                    static_assert(std::is_base_of<std::random_access_iterator_tag, IterTag>::value,
                                  "Caching read from non random access iterators are not supported at this moment.");

                    auto &dataField = std::get<Idx>(allFields);

                    using field_type = typename std::decay<decltype(dataField)>::type;
                    static_assert(std::is_same<field_type, field_type>::value, "field_type has wrong type");

                    auto dataIter = iter;
                    auto es = read(msg, iter, size, missingSize);
                    if (es != status_type::success) {
                        return es;
                    }

                    auto dataSize = static_cast<std::size_t>(std::distance(dataIter, iter));
                    auto dataEs = dataField.read(dataIter, dataSize);
                    static_cast<void>(dataEs);
                    MARSHALLING_ASSERT(dataEs == nil::marshalling::status_type::success);
                    return es;
                }

                /// @brief Read transport fields with caching until data layer.
                /// @details Does nothing because it is data layer.
                /// @return @ref nil::marshalling::ErrorStatus::Success;
                template<typename TAllFields, typename TMsg, typename TIter>
                static status_type read_until_data_fields_cached(TAllFields &allFields, TMsg &msg, TIter &iter,
                                                                 std::size_t size, std::size_t *missingSize = nullptr) {
                    static_cast<void>(allFields);
                    static_cast<void>(msg);
                    static_cast<void>(iter);
                    static_cast<void>(size);
                    static_cast<void>(missingSize);
                    return nil::marshalling::status_type::success;
                }

                /// @brief Same as @ref read_fields_cached().
                /// @details Expected to be called by the privous layers to properly
                ///     finalise read operation after the call to @ref read_until_data_fields_cached();
                /// @return @ref nil::marshalling::ErrorStatus::Success;
                template<typename TAllFields, typename TMsg, typename TIter>
                static status_type read_from_data_fields_cached(TAllFields &allFields, TMsg &msg, TIter &iter,
                                                                std::size_t size, std::size_t *missingSize = nullptr) {
                    return read_fields_cached(allFields, msg, iter, size, missingSize);
                }

                /// @brief Write the message contents.
                /// @details The way the message contents are written is determined by the
                ///     type of the message. If TMsg type is recognised to be actual message
                ///     inheriting from nil::marshalling::message_base with its fields provided using
                ///     nil::marshalling::option::FieldsImpl option, the function calls @b eval_write
                ///     non-virtual function defined by nil::marshalling::message_base
                ///     (see nil::marshalling::message_base::eval_write) or redefined by the actual
                ///     message itself. Otherwise, TMsg type is expected to be the used
                ///     interface which allows polymorphic write functionality.
                ///     It must define @b write() member function which will be
                ///     called.
                /// @tparam TMsg Type of the message.
                /// @tparam TIter Type of the iterator used for writing.
                /// @param[in] msg Reference to the message object,
                /// @param[in, out] iter Iterator used for writing.
                /// @param[in] size Max number of bytes that can be written.
                /// @return Status of the write operation.
                template<typename TMsg, typename TIter>
                static status_type write(const TMsg &msg, TIter &iter, std::size_t size) {
                    using msg_type = typename std::decay<decltype(msg)>::type;

                    static_assert(nil::marshalling::is_message<msg_type>(),
                                  "The provided message object must inherit from nil::marshalling::message");

                    using tag = typename std::conditional<detail::protocol_layer_has_fields_impl<msg_type>::value,
                                                          direct_op_tag, polymorphic_op_tag>::type;

                    return write_internal(msg, iter, size, tag());
                }

                /// @brief Write the message contents while caching the written transport
                ///     information fields.
                /// @details Very similar to write() member function, but adds "allFields"
                ///     parameter to store raw data of the message.
                /// @tparam Tall_fields_type std::tuple of all the transport fields, must be
                ///     @ref all_fields_type type defined in the last layer class that defines
                ///     protocol stack.
                /// @tparam TMsg Type of the message.
                /// @tparam TIter Type of the iterator used for writing.
                /// @param[out] allFields Reference to the std::tuple object that wraps all
                ///     transport fields (@ref all_fields_type type of the last protocol layer class).
                /// @param[in] msg Reference to the message object that is being written,
                /// @param[in, out] iter Iterator used for writing.
                /// @param[in] size Max number of bytes that can be written.
                /// @return Status of the write operation.
                template<typename TAllFields, typename TMsg, typename TIter>
                static status_type write_fields_cached(TAllFields &allFields, const TMsg &msg, TIter &iter,
                                                       std::size_t size) {
                    static_assert(nil::detail::is_tuple<TAllFields>::value,
                                  "Expected TAllFields to be tuple.");

                    using AllFieldsDecayed = typename std::decay<TAllFields>::type;
                    static_assert(processing::tuple_is_tail_of<all_fields_type, AllFieldsDecayed>(),
                                  "Passed tuple is wrong.");
                    static const std::size_t Idx
                        = std::tuple_size<AllFieldsDecayed>::value - std::tuple_size<all_fields_type>::value;

                    static_assert((Idx + 1) == std::tuple_size<TAllFields>::value,
                                  "All fields must be written when msg_data_layer is reached");

                    auto &dataField = std::get<Idx>(allFields);
                    using ifield_type = typename std::decay<decltype(dataField)>::type;
                    static_assert(std::is_same<ifield_type, field_type>::value, "field_type has wrong type");

                    using IterType = typename std::decay<decltype(iter)>::type;
                    using IterTag = typename std::iterator_traits<IterType>::iterator_category;
                    return write_with_field_cached_internal(dataField, msg, iter, size, IterTag());
                }

                /// @brief Update recently written (using write()) message contents data.
                /// @details Sometimes, when NON random access iterator is used for writing
                ///     (for example std::back_insert_iterator), some transport data cannot
                ///     be properly written. In this case, write() function will return
                ///     nil::marshalling::ErrorStatus::UpdateRequired. When such status is returned
                ///     it is necessary to call update() with random access iterator on
                ///     the written buffer to update written dummy information with
                ///     proper values.
                ///     This function in this layer does nothing, just advances the iterator
                ///     by "size".
                /// @param[in, out] iter Any random access iterator.
                /// @param[in] size Number of bytes that have been written using write().
                /// @return Status of the update operation.
                template<typename TIter>
                static nil::marshalling::status_type update(TIter &iter, std::size_t size) {
                    std::advance(iter, size);
                    return nil::marshalling::status_type::success;
                }

                /// @brief Update recently written (using write_fields_cached()) message data as
                ///     well as cached transport information fields.
                /// @details Very similar to update() member function, but adds "allFields"
                ///     parameter to store raw data of the message.
                /// @tparam TIdx Index of the data field in Tall_fields_type, expected to be last
                ///     element in the tuple.
                /// @tparam Tall_fields_type std::tuple of all the transport fields, must be
                ///     @ref all_fields_type type defined in the last layer class that defines
                ///     protocol stack.
                /// @tparam TIter Type of the random access iterator.
                /// @param[out] allFields Reference to the std::tuple object that wraps all
                ///     transport fields (@ref all_fields_type type of the last protocol layer class).
                /// @param[in, out] iter Random access iterator to the written data.
                /// @param[in] size Number of bytes that have been written using write_fields_cached().
                /// @return Status of the update operation.
                template<std::size_t TIdx, typename TAllFields, typename TIter>
                static status_type update_fields_cached(TAllFields &allFields, TIter &iter, std::size_t size) {
                    static_assert(nil::detail::is_tuple<TAllFields>::value,
                                  "Expected TAllFields to be tuple.");

                    static_assert((TIdx + 1) == std::tuple_size<TAllFields>::value,
                                  "All fields must be written when msg_data_layer is reached");

                    static_cast<void>(allFields);
                    std::advance(iter, size);
                    return nil::marshalling::status_type::success;
                }

                /// @brief Get remaining length of wrapping transport information.
                /// @details The message data always get wrapped with transport information
                ///     to be successfully delivered to and unpacked on the other side.
                ///     This function return remaining length of the transport information.
                /// @return 0.
                static constexpr std::size_t length() {
                    return 0U;
                }

                /// @brief Get remaining length of wrapping transport information + length
                ///     of the provided message.
                /// @details This function usually gets called when there is a need to
                ///     identify the size of the buffer required to write provided message
                ///     wrapped in the transport information. This function is very similar
                ///     to length(), but adds also length of the message.
                /// @param[in] msg Message
                /// @return length of the message.
                template<typename TMsg>
                static constexpr std::size_t length(const TMsg &msg) {
                    using msg_type = typename std::decay<decltype(msg)>::type;

                    static_assert(nil::marshalling::is_message<msg_type>(),
                                  "The provided message object must inherit from nil::marshalling::message");

                    using tag = typename std::conditional<detail::protocol_layer_has_fields_impl<msg_type>::value,
                                                          msg_direct_length_tag, msg_has_length_tag>::type;
                    return get_msg_length(msg, tag());
                }

                /// @brief Access appropriate field from "cached" bundle of all the
                ///     protocol stack fields.
                /// @param allFields All fields of the protocol stack
                /// @return Reference to requested field.
                template<typename TAllFields>
                static auto access_cached_field(TAllFields &allFields)
                    -> decltype(std::get<std::tuple_size<typename std::decay<TAllFields>::type>::value
                                         - std::tuple_size<all_fields_type>::value>(allFields)) {
                    using AllFieldsDecayed = typename std::decay<TAllFields>::type;
                    static_assert(processing::tuple_is_tail_of<all_fields_type, AllFieldsDecayed>(),
                                  "Passed tuple is wrong.");
                    static const std::size_t Idx
                        = std::tuple_size<AllFieldsDecayed>::value - std::tuple_size<all_fields_type>::value;

                    return std::get<Idx>(allFields);
                }

            private:
                struct msg_has_length_tag { };
                struct msg_no_length_tag { };
                struct msg_direct_length_tag { };

                struct polymorphic_op_tag { };
                struct direct_op_tag { };

                template<typename TMsg, typename TIter>
                static status_type write_with_field_cached_internal(field_type &field, const TMsg &msg, TIter &iter,
                                                                    std::size_t size, std::random_access_iterator_tag) {
                    return write_with_field_cached_random_access(field, msg, iter, size);
                }

                template<typename TMsg, typename TIter>
                static status_type write_with_field_cached_internal(field_type &field, const TMsg &msg, TIter &iter,
                                                                    std::size_t size, std::output_iterator_tag) {
                    return write_with_field_cached_output(field, msg, iter, size);
                }

                template<typename TMsg, typename TIter>
                static status_type write_with_field_cached_random_access(field_type &field, const TMsg &msg,
                                                                         TIter &iter, std::size_t size) {
                    auto dataReadIter = iter;
                    auto es = write(msg, iter, size);
                    if (es != nil::marshalling::status_type::success) {
                        return es;
                    }

                    auto writtenCount = static_cast<std::size_t>(std::distance(dataReadIter, iter));
                    auto dataEs = field.read(dataReadIter, writtenCount);
                    MARSHALLING_ASSERT(dataEs == nil::marshalling::status_type::success);
                    static_cast<void>(dataEs);
                    return nil::marshalling::status_type::success;
                }

                template<typename TMsg, typename TCollection>
                static status_type write_with_field_cached_output(field_type &field, const TMsg &msg,
                                                                  std::back_insert_iterator<TCollection> &iter,
                                                                  std::size_t size) {
                    auto es = write(msg, iter, size);
                    if (es != nil::marshalling::status_type::success) {
                        return es;
                    }

                    TCollection col;
                    auto dataWriteIter = std::back_inserter(col);
                    auto dataWriteEs = write(msg, dataWriteIter, size);
                    MARSHALLING_ASSERT(dataWriteEs == nil::marshalling::status_type::success);
                    static_cast<void>(dataWriteEs);

                    auto dataReadIter = col.cbegin();
                    auto dataReadEs = field.read(dataReadIter, col.size());
                    MARSHALLING_ASSERT(dataReadEs == nil::marshalling::status_type::success);
                    static_cast<void>(dataReadEs);

                    return nil::marshalling::status_type::success;
                }

                template<typename TMsg>
                static std::size_t get_msg_length(const TMsg &msg, msg_has_length_tag) {
                    using msg_type = typename std::decay<decltype(msg)>::type;
                    static_assert(msg_type::interface_options_type::has_length,
                                  "message interface must define length()");
                    return msg.length();
                }

                template<typename TMsg>
                static constexpr std::size_t get_msg_length(const TMsg &msg, msg_direct_length_tag) {
                    using msg_type = typename std::decay<decltype(msg)>::type;
                    static_assert(msg_type::impl_options_type::has_fields_impl, "fields_impl option hasn't been used");
                    return msg.eval_length();
                }

                template<typename TMsg>
                static constexpr std::size_t get_msg_length(const TMsg &, msg_no_length_tag) {
                    return 0U;
                }

                template<typename TMsgPtr, typename TIter>
                static status_type read_internal_polymorphic(TMsgPtr &msgPtr, TIter &iter, std::size_t size,
                                                             std::size_t *missingSize = nullptr) {
                    using MsgPtrType = typename std::decay<decltype(msgPtr)>::type;
                    using msg_type = typename MsgPtrType::element_type;

                    static_assert(nil::marshalling::is_message<msg_type>(),
                                  "The provided message object must inherit from nil::marshalling::message");

                    static_assert(msg_type::interface_options_type::has_read_iterator,
                                  "message interface must support polymorphic read operation");

                    using IterType = typename std::decay<decltype(iter)>::type;

                    static_assert(std::is_convertible<IterType, typename msg_type::read_iterator>::value,
                                  "The provided iterator is not convertible to read_iterator defined by message class");

                    using ReadIter = typename std::add_lvalue_reference<typename msg_type::read_iterator>::type;

                    MARSHALLING_ASSERT(msgPtr);
                    auto result = msgPtr->read(static_cast<ReadIter>(iter), size);
                    if ((result == status_type::not_enough_data) && (missingSize != nullptr)) {
                        using tag = typename std::conditional<msg_type::interface_options_type::has_length,
                                                              msg_has_length_tag, msg_no_length_tag>::type;

                        auto msgLen = get_msg_length(*msgPtr, tag());
                        if (size < msgLen) {
                            *missingSize = msgLen - size;
                        } else {
                            *missingSize = 1;
                        }
                    }
                    return result;
                }

                template<typename TMsg, typename TIter>
                static status_type read_internal_direct(TMsg &msg, TIter &iter, std::size_t size,
                                                        std::size_t *missingSize = nullptr) {
                    using msg_type = typename std::decay<decltype(msg)>::type;

                    static_assert(nil::marshalling::is_message_base<msg_type>(),
                                  "The provided message object must inherit from nil::marshalling::message_base");

                    static_assert(detail::protocol_layer_has_fields_impl<msg_type>::value,
                                  "message class must use fields_impl option");

                    auto result = msg.eval_read(iter, size);
                    if ((result == status_type::not_enough_data) && (missingSize != nullptr)) {
                        auto msgLen = get_msg_length(msg, msg_direct_length_tag());
                        if (size < msgLen) {
                            *missingSize = msgLen - size;
                        } else {
                            *missingSize = 1;
                        }
                    }
                    return result;
                }

                template<typename TMsg, typename TIter>
                static status_type read_internal(TMsg &msg, TIter &iter, std::size_t size, std::size_t *missingSize,
                                                 polymorphic_op_tag) {
                    return read_internal_polymorphic(msg, iter, size, missingSize);
                }

                template<typename TMsg, typename TIter>
                static status_type read_internal(TMsg &msg, TIter &iter, std::size_t size, std::size_t *missingSize,
                                                 direct_op_tag) {
                    return read_internal_direct(msg, iter, size, missingSize);
                }

                template<typename TMsg, typename TIter>
                static status_type write_internal(const TMsg &msg, TIter &iter, std::size_t size, polymorphic_op_tag) {
                    return write_internal_polymorhpic(msg, iter, size);
                }

                template<typename TMsg, typename TIter>
                static status_type write_internal(const TMsg &msg, TIter &iter, std::size_t size, direct_op_tag) {
                    return write_internal_direct(msg, iter, size);
                }

                template<typename TMsg, typename TIter>
                static status_type write_internal_polymorhpic(const TMsg &msg, TIter &iter, std::size_t size) {
                    using msg_type = typename std::decay<decltype(msg)>::type;

                    static_assert(msg_type::interface_options_type::has_write_iterator,
                                  "message interface must support polymorphic write operation");

                    using IterType = typename std::decay<decltype(iter)>::type;

                    static_assert(
                        std::is_convertible<IterType, typename msg_type::write_iterator>::value,
                        "The provided iterator is not convertible to write_iterator defined by message class");

                    using WriteIter = typename std::add_lvalue_reference<typename msg_type::write_iterator>::type;

                    return msg.write(static_cast<WriteIter>(iter), size);
                }

                template<typename TMsg, typename TIter>
                static status_type write_internal_direct(const TMsg &msg, TIter &iter, std::size_t size) {
                    return msg.eval_write(iter, size);
                }
            };

            namespace detail {
                template<typename T>
                struct msg_data_layer_check_helper {
                    static const bool value = false;
                };

                template<typename... TExtraOpts>
                struct msg_data_layer_check_helper<msg_data_layer<TExtraOpts...>> {
                    static const bool value = true;
                };

            }    // namespace detail

            /// @brief Compile time check of whether the provided type is
            ///     a variant of @ref MsgDataLayer
            /// @related MsgDataLayer
            template<typename T>
            constexpr bool is_msg_data_layer() {
                return detail::msg_data_layer_check_helper<T>::value;
            }

            template<typename... TExtraOpts>
            constexpr msg_data_layer<TExtraOpts...> &to_protocol_layer_base(msg_data_layer<TExtraOpts...> &layer) {
                return layer;
            }

            template<typename... TExtraOpts>
            constexpr const msg_data_layer<TExtraOpts...> &
                to_protocol_layer_base(const msg_data_layer<TExtraOpts...> &layer) {
                return layer;
            }

        }    // namespace protocol

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MSG_DATA_LAYER_HPP
