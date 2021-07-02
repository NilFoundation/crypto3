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

#ifndef MARSHALLING_PROTOCOL_LAYER_BASE_HPP
#define MARSHALLING_PROTOCOL_LAYER_BASE_HPP

#include <tuple>
#include <utility>
#include <algorithm>

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/processing/tuple.hpp>
#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/marshalling/protocol/detail/protocol_layer_base_options_parser.hpp>
#include <nil/marshalling/detail/protocol_layers_access.hpp>

namespace nil {
    namespace marshalling {
        namespace protocol {
            namespace detail {

                template<class T, class R = void>
                struct protocol_layer_enable_if_has_all_messages {
                    using type = R;
                };

                template<class T, class Enable = void>
                struct protocol_layer_all_messages_helper {
                    using type = void;
                };

                template<class T>
                struct protocol_layer_all_messages_helper<
                    T, typename protocol_layer_enable_if_has_all_messages<typename T::all_messages_type>::type> {
                    using type = typename T::all_messages_type;
                };

                template<class T>
                using protocol_layer_all_messages_type = typename protocol_layer_all_messages_helper<T>::type;

                template<typename T, bool THasImpl>
                struct protocol_layer_has_fields_impl_helper;

                template<typename T>
                struct protocol_layer_has_fields_impl_helper<T, true> {
                    static const bool value = T::impl_options_type::has_fields_impl;
                };

                template<typename T>
                struct protocol_layer_has_fields_impl_helper<T, false> {
                    static const bool value = false;
                };

                template<typename T>
                struct protocol_layer_has_fields_impl {
                    static const bool value = protocol_layer_has_fields_impl_helper<
                        T, has_type_impl_options_type<T>::value>::value;
                };

                template<typename T, bool THasImpl>
                struct protocol_layer_has_do_get_id_helper;

                template<typename T>
                struct protocol_layer_has_do_get_id_helper<T, true> {
                    static const bool value = T::impl_options_type::has_static_msg_id;
                };

                template<typename T>
                struct protocol_layer_has_do_get_id_helper<T, false> {
                    static const bool value = false;
                };

                template<typename T>
                struct protocol_layer_has_do_get_id {
                    static const bool value = protocol_layer_has_do_get_id_helper<
                        T, has_type_impl_options_type<T>::value>::value;
                };

                template<class T, class R = void>
                struct protocol_layer_enable_if_has_msg_ptr {
                    using type = R;
                };

                template<class T, class Enable = void>
                struct protocol_layer_msg_ptr {
                    using type = void;
                };

                template<class T>
                struct protocol_layer_msg_ptr<
                    T, typename protocol_layer_enable_if_has_msg_ptr<typename T::msg_ptr_type>::type> {
                    using type = typename T::msg_ptr_type;
                };

            }    // namespace detail

            /// @brief Base class for all the middle (non @ref MsgDataLayer) protocol transport layers.
            /// @details Provides all the default and/or common functionality for the
            ///     middle transport layer. The inheriting actual layer class may
            ///     use and/or override the provided functionality by redefining member
            ///     function with the same signature. The @ref next_layer_type is stored as a private
            ///     data meber.
            /// @tparam TField Every middle layer will have a field containing extra
            ///     information for this layer. This template parameter is a type of such
            ///     field.
            /// @tparam TNextLayer Next layer this one wraps and forwards the calls to.
            /// @tparam TDerived Actual protocol layer class that extends this one.
            /// @tparam TOptions Extra options. Supported ones are:
            ///     @li @ref nil::marshalling::option::ProtocolLayerForceReadUntilDataSplit
            ///     @li @ref nil::marshalling::option::ProtocolLayerDisallowReadUntilDataSplit
            /// @headerfile nil/marshalling/protocol/ProtocolLayerBase.h
            template<typename TField, typename TNextLayer, typename TDerived, typename... TOptions>
            class protocol_layer_base {
            public:
                /// @brief Type of the field used for this layer.
                using field_type = TField;

                /// @brief Type of the next transport layer
                using next_layer_type = TNextLayer;

                /// @brief Parsed options structure
                using parsed_options_type = detail::protocol_layer_base_options_parser<TOptions...>;

                /// @brief Type of all the fields of all the transport layers
                ///     wrapped in std::tuple.
                /// @details The @ref field_type type is prepended to the @ref all_fields_type type
                ///     of the @ref next_layer_type and reported as @ref all_fields_type of this one.
                using all_fields_type = typename std::decay<decltype(std::tuple_cat(
                    std::declval<std::tuple<field_type>>(),
                    std::declval<typename TNextLayer::all_fields_type>()))>::type;

                /// @brief All supported messages.
                /// @details Same as next_layer_type::all_messages_type or void if such doesn't exist.
                using all_messages_type = detail::protocol_layer_all_messages_type<next_layer_type>;

                /// @brief Type of pointer to the message.
                /// @details Same as next_layer_type::msg_ptr_type or void if such doesn't exist.
                using msg_ptr_type = typename detail::protocol_layer_msg_ptr<next_layer_type>::type;

                /// @brief Actual derived class
                using this_layer_type = TDerived;

                /// @brief Static constant indicating amount of transport layers used.
                static const std::size_t layers_amount = 1 + next_layer_type::layers_amount;

                /// @brief Copy constructor
                protocol_layer_base(const protocol_layer_base &) = default;

                /// @brief Move constructor
                protocol_layer_base(protocol_layer_base &&) = default;

                /// @brief Constructor.
                /// @details Forwards all the parameters to the constructor of the embedded
                ///     @ref next_layer_type object.
                /// @param args Arguments to be passed to the constructor of the next layer
                template<typename... TArgs>
                explicit protocol_layer_base(TArgs &&...args) : nextLayer_(std::forward<TArgs>(args)...) {
                }

                /// @brief Desctructor
                ~protocol_layer_base() noexcept = default;

                /// @brief Copy assignment
                protocol_layer_base &operator=(const protocol_layer_base &) = default;

                /// @brief Get access to the next layer object.
                next_layer_type &next_layer() {
                    return nextLayer_;
                }

                /// @brief Get "const" access to the next layer object.
                const next_layer_type &next_layer() const {
                    return nextLayer_;
                }

                /// @brief Get access to this layer object.
                this_layer_type &this_layer() {
                    return static_cast<this_layer_type &>(*this);
                }

                /// @brief Get "const" access to this layer object.
                const this_layer_type &this_layer() const {
                    return static_cast<const this_layer_type &>(*this);
                }

                /// @brief Compile time check whether split read "until" and "from" data
                ///     layer is allowed.
                static constexpr bool can_split_read() {
                    return (!parsed_options_type::has_disallow_read_until_data_split)
                           && next_layer_type::can_split_read();
                }

                /// @brief Deserialise message from the input data sequence.
                /// @details The function will invoke @b eval_read() member function
                ///     provided by the derived class, which must have the following signature
                ///     and logic:
                ///     @code
                ///         template<typename TMsg, typename TIter, typename TNextLayerReader>
                ///         nil::marshalling::ErrorStatus eval_read(
                ///             field_type& field, // field object used to read required data
                ///             TMsg& msg, // Ref to smart pointer to message object, or message object itself
                ///             TIter& iter, // iterator used for reading
                ///             std::size_t size, // size of the remaining data
                ///             std::size_t* missingSize, // output of missing bytest count
                ///             TNextLayerReader&& nextLayerReader // next layer reader object
                ///             )
                ///         {
                ///             // internal logic prior next layer read, such as reading the field value
                ///             auto es = field.read(iter, size);
                ///             ...
                ///             // request next layer to perform read operation
                ///             es = nextLayerReader.read(msg, iter, size - field.length(), missingSize);
                ///             ... // internal logic after next layer read if applicable
                ///             return es;
                ///         };
                ///     @endcode
                ///     The signature of the @b nextLayerReader.read() function is
                ///     the same as the signature of this @b read() member function.
                /// @tparam TMsg Type of @b msg parameter
                /// @tparam TIter Type of iterator used for reading.
                /// @param[in, out] msg Reference to smart pointer, that already holds or
                ///     will hold allocated message object, or reference to actual message
                ///     object (which extends @ref nil::marshalling::message_base).
                /// @param[in, out] iter Input iterator used for reading.
                /// @param[in] size Size of the data in the sequence
                /// @param[out] missingSize If not nullptr and return value is
                ///             nil::marshalling::ErrorStatus::NotEnoughData it will contain
                ///             minimal missing data length required for the successful
                ///             read attempt.
                /// @return Status of the operation.
                /// @pre Iterator must be valid and can be dereferenced and incremented at
                ///      least "size" times;
                /// @post The iterator will be advanced by the number of bytes was actually
                ///       read. In case of an error, distance between original position and
                ///       advanced will pinpoint the location of the error.
                /// @post Returns nil::marshalling::ErrorStatus::Success if and only if msg points
                ///       to a valid object.
                /// @post missingSize output value is updated if and only if function
                ///       returns nil::marshalling::ErrorStatus::NotEnoughData.
                template<typename TMsg, typename TIter>
                nil::marshalling::status_type read(TMsg &msg, TIter &iter, std::size_t size,
                                                   std::size_t *missingSize = nullptr) {
                    using tag = typename std::conditional<parsed_options_type::has_force_read_until_data_split,
                                                          split_read_tag, normal_read_tag>::type;

                    static_assert(std::is_same<tag, normal_read_tag>::value || can_split_read(),
                                  "Read split is disallowed by at least one of the inner layers");
                    return read_internal(msg, iter, size, missingSize, tag());
                }

                /// @brief Perform read of data fields until data layer (message payload).
                /// @details Same as @b read by stops read operation when data layer is reached.
                ///     Expected to be followed by a call to @ref read_from_data().
                /// @tparam TMsg Type of @b msg parameter.
                /// @tparam TIter Type of iterator used for reading.
                /// @param[in, out] msg Reference to smart pointer, that already holds or
                ///     will hold allocated message object, or reference to actual message
                ///     object (which extends @ref nil::marshalling::message_base).
                /// @param[in, out] iter Input iterator used for reading.
                /// @param[in] size Size of the data in the sequence
                /// @param[out] missingSize If not nullptr and return value is
                ///             nil::marshalling::ErrorStatus::NotEnoughData it will contain
                ///             minimal missing data length required for the successful
                ///             read attempt.
                /// @return Status of the operation.
                /// @pre Iterator must be valid and can be dereferenced and incremented at
                ///      least "size" times;
                /// @post The iterator will be advanced by the number of bytes was actually
                ///       read. In case of an error, distance between original position and
                ///       advanced will pinpoint the location of the error.
                /// @post missingSize output value is updated if and only if function
                ///       returns nil::marshalling::ErrorStatus::NotEnoughData.
                template<typename TMsg, typename TIter>
                nil::marshalling::status_type read_until_data(TMsg &msg, TIter &iter, std::size_t size,
                                                              std::size_t *missingSize = nullptr) {

                    field_type field;
                    auto &derivedObj = static_cast<TDerived &>(*this);
                    return derivedObj.eval_read(field, msg, iter, size, missingSize,
                                                create_next_layer_until_data_reader());
                }

                /// @brief Finalise the read operation by reading the message payload.
                /// @details Should be called to finalise the read operation started by
                ///     @ref read_until_data().
                /// @tparam TMsg Type of @b msg parameter
                /// @tparam TIter Type of iterator used for reading.
                /// @param[in, out] msg Reference to smart pointer, that already holds or
                ///     will hold allocated message object, or reference to actual message
                ///     object (which extends @ref nil::marshalling::message_base).
                /// @param[in, out] iter Input iterator used for reading.
                /// @param[in] size Size of the data in the sequence
                /// @param[out] missingSize If not nullptr and return value is
                ///             nil::marshalling::ErrorStatus::NotEnoughData it will contain
                ///             minimal missing data length required for the successful
                ///             read attempt.
                /// @return Status of the operation.
                /// @pre Iterator must be valid and can be dereferenced and incremented at
                ///      least "size" times;
                /// @post The iterator will be advanced by the number of bytes was actually
                ///       read. In case of an error, distance between original position and
                ///       advanced will pinpoint the location of the error.
                /// @post missingSize output value is updated if and only if function
                ///       returns nil::marshalling::ErrorStatus::NotEnoughData.
                template<typename TMsg, typename TIter>
                nil::marshalling::status_type read_from_data(TMsg &msg, TIter &iter, std::size_t size,
                                                             std::size_t *missingSize = nullptr) {
                    return next_layer().read_from_data(msg, iter, size, missingSize);
                }

                /// @brief Deserialise message from the input data sequence while caching
                ///     the read transport information fields.
                /// @details Very similar to @ref read() member function, but adds "allFields"
                ///     parameter to store read transport information fields.
                ///     The function will also invoke the same @b eval_read() member function
                ///     provided by the derived class, as described with @ref read().
                /// @tparam Tall_fields_type std::tuple of all the transport fields, must be
                ///     @ref all_fields_type type defined in the last layer class that defines
                ///     protocol stack.
                /// @tparam TMsg Type of @b msg parameter.
                /// @tparam TIter Type of iterator used for reading.
                /// @param[out] allFields Reference to the std::tuple object that wraps all
                ///     transport fields (@ref all_fields_type type of the last protocol layer class).
                /// @param[in, out] msg Reference to smart pointer, that already holds or
                ///     will hold allocated message object, or reference to actual message
                ///     object (which extends @ref nil::marshalling::message_base).
                /// @param[in, out] iter Iterator used for reading.
                /// @param[in] size Number of bytes available for reading.
                /// @param[out] missingSize If not nullptr and return value is
                ///             nil::marshalling::ErrorStatus::NotEnoughData it will contain
                ///             minimal missing data length required for the successful
                ///             read attempt.
                /// @return Status of the operation.
                template<typename TAllFields, typename TMsg, typename TIter>
                nil::marshalling::status_type read_fields_cached(TAllFields &allFields, TMsg &msg, TIter &iter,
                                                                 std::size_t size, std::size_t *missingSize = nullptr) {
                    using AllFieldsDecayed = typename std::decay<TAllFields>::type;
                    static_assert(processing::tuple_is_tail_of<all_fields_type, AllFieldsDecayed>(),
                                  "Passed tuple is wrong.");
                    static const std::size_t Idx
                        = std::tuple_size<AllFieldsDecayed>::value - std::tuple_size<all_fields_type>::value;
                    auto &field = get_field<Idx>(allFields);
                    auto &derivedObj = static_cast<TDerived &>(*this);
                    return derivedObj.eval_read(field, msg, iter, size, missingSize,
                                                create_next_layer_cached_fields_reader(allFields));
                }

                /// @brief Perform read of data fields until data layer (message payload) while caching
                ///     the read transport information fields.
                /// @details Very similar to @ref read_until_data() member function, but adds "allFields"
                ///     parameter to store read transport information fields.
                ///     The function will also invoke the same @b eval_read() member function
                ///     provided by the derived class, as described with @ref read().
                /// @tparam Tall_fields_type std::tuple of all the transport fields, must be
                ///     @ref all_fields_type type defined in the last layer class that defines
                ///     protocol stack.
                /// @tparam TMsg Type of @b msg parameter
                /// @tparam TIter Type of iterator used for reading.
                /// @param[out] allFields Reference to the std::tuple object that wraps all
                ///     transport fields (@ref all_fields_type type of the last protocol layer class).
                /// @param[in, out] msg Reference to smart pointer, that already holds or
                ///     will hold allocated message object, or reference to actual message
                ///     object (which extends @ref nil::marshalling::message_base).
                /// @param[in, out] iter Iterator used for reading.
                /// @param[in] size Number of bytes available for reading.
                /// @param[out] missingSize If not nullptr and return value is
                ///             nil::marshalling::ErrorStatus::NotEnoughData it will contain
                ///             minimal missing data length required for the successful
                ///             read attempt.
                /// @return Status of the operation.
                template<typename TAllFields, typename TMsg, typename TIter>
                nil::marshalling::status_type read_until_data_fields_cached(TAllFields &allFields, TMsg &msg,
                                                                            TIter &iter, std::size_t size,
                                                                            std::size_t *missingSize = nullptr) {
                    using AllFieldsDecayed = typename std::decay<TAllFields>::type;
                    static_assert(processing::tuple_is_tail_of<all_fields_type, AllFieldsDecayed>(),
                                  "Passed tuple is wrong.");
                    static const std::size_t Idx
                        = std::tuple_size<AllFieldsDecayed>::value - std::tuple_size<all_fields_type>::value;

                    auto &field = get_field<Idx>(allFields);
                    auto &derivedObj = static_cast<TDerived &>(*this);
                    return derivedObj.eval_read(field, msg, iter, size, missingSize,
                                                create_next_layer_cached_fields_until_data_reader(allFields));
                }

                /// @brief Finalise the read operation by reading the message payload while caching
                ///     the read transport information fields.
                /// @details Should be called to finalise the read operation started by
                ///     @ref read_until_data_fields_cached().
                /// @tparam Tall_fields_type std::tuple of all the transport fields, must be
                ///     @ref all_fields_type type defined in the last layer class that defines
                ///     protocol stack.
                /// @tparam TMsg Type of @b msg parameter
                /// @tparam TIter Type of iterator used for reading.
                /// @param[out] allFields Reference to the std::tuple object that wraps all
                ///     transport fields (@ref all_fields_type type of the last protocol layer class).
                /// @param[in, out] msg Reference to smart pointer, that already holds or
                ///     will hold allocated message object, or reference to actual message
                ///     object (which extends @ref nil::marshalling::message_base).
                /// @param[in, out] iter Iterator used for reading.
                /// @param[in] size Number of bytes available for reading.
                /// @param[out] missingSize If not nullptr and return value is
                ///             nil::marshalling::ErrorStatus::NotEnoughData it will contain
                ///             minimal missing data length required for the successful
                ///             read attempt.
                /// @return Status of the operation.
                template<typename TAllFields, typename TMsg, typename TIter>
                nil::marshalling::status_type read_from_data_fields_cached(TAllFields &allFields, TMsg &msg,
                                                                           TIter &iter, std::size_t size,
                                                                           std::size_t *missingSize = nullptr) {
                    return next_layer().read_from_data_fields_cached(allFields, msg, iter, size, missingSize);
                }

                /// @brief Serialise message into output data sequence.
                /// @details The function will invoke @b eval_write() member function
                ///     provided by the derived class, which must have the following signature
                ///     and logic:
                ///     @code
                ///         template<typename TMsg, typename TIter, typename TNextLayerWriter>
                ///         nil::marshalling::ErrorStatus eval_write(
                ///             field_type& field, // field object used to update and write required data
                ///             const TMsg& msg, // reference to ready to be sent message object
                ///             TIter& iter, // iterator used for writing
                ///             std::size_t size, // Max number of bytes that can be written.
                ///             TNextLayerWriter&& nextLayerWriter // next layer writer object
                ///             )
                ///         {
                ///             // internal logic prior next layer write, such as
                ///             // updating field's value and writing it.
                ///             field.value() = ...;
                ///             auto es = field.write(iter, size);
                ///             ...
                ///             // request next layer to perform write operation
                ///             es = nextLayerWriter.write(msg, iter, size - field.length());
                ///             ... // internal logic after next layer write if applicable
                ///             return es;
                ///         };
                ///     @endcode
                ///     The signature of the @b nextLayerWriter.write() function is
                ///     the same as the signature of this @b write() member function.
                /// @tparam TMsg Type of the message being written.
                /// @tparam TIter Type of iterator used for writing.
                /// @param[in] msg Reference to message object
                /// @param[in, out] iter Output iterator used for writing.
                /// @param[in] size Max number of bytes that can be written.
                /// @return Status of the write operation.
                /// @pre Iterator must be valid and can be dereferenced and incremented at
                ///      least "size" times;
                /// @post The iterator will be advanced by the number of bytes was actually
                ///       written. In case of an error, distance between original position
                ///       and advanced will pinpoint the location of the error.
                /// @return Status of the write operation.
                template<typename TMsg, typename TIter>
                nil::marshalling::status_type write(const TMsg &msg, TIter &iter, std::size_t size) const {
                    field_type field;
                    auto &derivedObj = static_cast<const TDerived &>(*this);
                    return derivedObj.eval_write(field, msg, iter, size, create_next_layer_writer());
                }

                /// @brief Serialise message into output data sequence while caching the written transport
                ///     information fields.
                /// @details Very similar to @ref write() member function, but adds "allFields"
                ///     parameter to store raw data of the message.
                ///     The function will also invoke the same @b eval_write() member function
                ///     provided by the derived class, as described with @ref write().
                /// @tparam Tall_fields_type std::tuple of all the transport fields, must be
                ///     @ref all_fields_type type defined in the last layer class that defines
                ///     protocol stack.
                /// @tparam TMsg Type of the message being written.
                /// @tparam TIter Type of iterator used for writing.
                /// @param[out] allFields Reference to the std::tuple object that wraps all
                ///     transport fields (@ref all_fields_type type of the last protocol layer class).
                /// @param[in] msg Reference to the message object that is being written,
                /// @param[in, out] iter Iterator used for writing.
                /// @param[in] size Max number of bytes that can be written.
                /// @return Status of the write operation.
                template<typename TAllFields, typename TMsg, typename TIter>
                nil::marshalling::status_type write_fields_cached(TAllFields &allFields, const TMsg &msg, TIter &iter,
                                                                  std::size_t size) const {
                    using AllFieldsDecayed = typename std::decay<TAllFields>::type;
                    static_assert(processing::tuple_is_tail_of<all_fields_type, AllFieldsDecayed>(),
                                  "Passed tuple is wrong.");
                    static const std::size_t Idx
                        = std::tuple_size<AllFieldsDecayed>::value - std::tuple_size<all_fields_type>::value;

                    auto &field = get_field<Idx>(allFields);
                    auto &derivedObj = static_cast<const TDerived &>(*this);
                    return derivedObj.eval_write(field, msg, iter, size,
                                                 create_next_layer_cached_fields_writer(allFields));
                }

                /// @brief Get remaining length of wrapping transport information.
                /// @details The message data always get wrapped with transport information
                ///     to be successfully delivered to and unpacked on the other side.
                ///     This function return remaining length of the transport information.
                ///     It performs a call to @ref eval_field_length() member function to
                ///     get info about current field length. To update the default behaviour
                ///     just override the function in the derived class.
                /// @return length of the field + length reported by the next layer.
                constexpr std::size_t length() const {
                    return static_cast<const this_layer_type &>(*this).eval_field_length() + nextLayer_.length();
                }

                /// @brief Get remaining length of wrapping transport information + length
                ///     of the provided message.
                /// @details This function usually gets called when there is a need to
                ///     identify the size of the buffer required to write provided message
                ///     wrapped in the transport information. This function is very similar
                ///     to length(), but adds also length of the message.
                ///     It performs a call to @ref eval_field_length() member function with message parameter to
                ///     get info about current field length. To update the default behaviour
                ///     just override the function in the derived class.
                /// @tparam TMsg Type of message object.
                /// @param[in] msg Message object
                /// @return length of the field + length reported by the next layer.
                template<typename TMsg>
                constexpr std::size_t length(const TMsg &msg) const {
                    return static_cast<const this_layer_type &>(*this).eval_field_length(msg) + nextLayer_.length(msg);
                }

                /// @brief Update recently written (using write()) message contents data.
                /// @details Sometimes, when NON random access iterator is used for writing
                ///     (for example std::back_insert_iterator), some transport data cannot
                ///     be properly written. In this case, @ref write() function will return
                ///     nil::marshalling::ErrorStatus::UpdateRequired. When such status is returned
                ///     it is necessary to call update() with random access iterator on
                ///     the written buffer to update written dummy information with
                ///     proper values.@n
                ///     The function will invoke @b eval_update() member function
                ///     provided (or inherited) by the derived class, which must have the following signature
                ///     and logic:
                ///     @code
                ///         template<typename TIter, typename TNextLayerUpdater>
                ///         nil::marshalling::ErrorStatus eval_update(
                ///             field_type& field, // field object to update and re-write if necessary
                ///             TIter& iter, // iterator used for updateing
                ///             std::size_t size, // Number of remaning bytes in the output buffer.
                ///             TNextLayerUpdater&& nextLayerUpdater // next layer updater object
                ///             )
                ///         {
                ///             // internal logic prior next layer update, such as
                ///             // updating field's value and re-writing it.
                ///             field.value() = ...;
                ///             auto es = field.write(iter, size);
                ///             ...
                ///             // request next layer to perform update operation
                ///             es = nextLayerUpdater.update(iter, size - field.length());
                ///             ... // internal logic after next layer write if applicable
                ///             return es;
                ///         };
                ///     @endcode
                ///     The signature of the @b nextLayerUpdater.update() function is
                ///     the same as the signature of this @b update() member function.
                /// @param[in, out] iter Any random access iterator.
                /// @param[in] size Number of bytes that have been written using write().
                /// @return Status of the update operation.
                template<typename TIter>
                nil::marshalling::status_type update(TIter &iter, std::size_t size) const {
                    field_type field;
                    auto &derivedObj = static_cast<const TDerived &>(*this);
                    return derivedObj.eval_update(field, iter, size, create_next_layer_updater());
                }

                /// @brief Update recently written (using write_fields_cached()) message data as
                ///     well as cached transport information fields.
                /// @details Very similar to @ref update() member function, but adds "allFields"
                ///     parameter to store raw data of the message.@n
                ///     The function will also invoke the same @b eval_update() member function
                ///     provided by the derived class, as described with @ref write().
                /// @tparam TIdx Index of the data field in Tall_fields_type.
                /// @tparam Tall_fields_type std::tuple of all the transport fields, must be
                ///     @ref all_fields_type type defined in the last layer class that defines
                ///     protocol stack.
                /// @tparam TIter Type of the random access iterator.
                /// @param[out] allFields Reference to the std::tuple object that wraps all
                ///     transport fields (@ref all_fields_type type of the last protocol layer class).
                /// @param[in, out] iter Random access iterator to the written data.
                /// @param[in] size Number of bytes that have been written using write_fields_cached().
                /// @return Status of the update operation.
                template<typename TAllFields, typename TIter>
                status_type update_fields_cached(TAllFields &allFields, TIter &iter, std::size_t size) const {
                    using AllFieldsDecayed = typename std::decay<TAllFields>::type;
                    static_assert(processing::tuple_is_tail_of<all_fields_type, AllFieldsDecayed>(),
                                  "Passed tuple is wrong.");
                    static const std::size_t Idx
                        = std::tuple_size<AllFieldsDecayed>::value - std::tuple_size<all_fields_type>::value;

                    auto &field = get_field<Idx>(allFields);
                    auto &derivedObj = static_cast<const TDerived &>(*this);
                    return derivedObj.eval_update(field, iter, size,
                                                  create_next_layer_cached_fields_updater(allFields));
                }

                /// @brief Default implementation of the "update" functaionality.
                /// @details It will be invoked by @ref update() or @ref update_fields_cached()
                ///     member function, unless the derived class provides its own @ref eval_update()
                ///     member function to override the default behavior.@n
                ///     This function in this layer does nothing, just advances the iterator
                ///     by the length of the @ref field_type.
                /// @tparam TIter Type of iterator used for updating.
                /// @tparam TNextLayerWriter next layer updater object type.
                /// @param[out] field field_type that needs to be updated.
                /// @param[in, out] iter Any random access iterator.
                /// @param[in] size Number of bytes that have been written using @ref write().
                /// @param[in] nextLayerUpdater Next layer updater object.
                template<typename TIter, typename TNextLayerUpdater>
                nil::marshalling::status_type eval_update(field_type &field, TIter &iter, std::size_t size,
                                                          TNextLayerUpdater &&nextLayerUpdater) const {
                    return update_internal(field, iter, size, std::forward<TNextLayerUpdater>(nextLayerUpdater),
                                           length_tag());
                }

                /// @brief Default implementation of field length retrieval.
                static constexpr std::size_t eval_field_length() {
                    return field_type::min_length();
                }

                /// @brief Default implementation of field length retrieval when
                ///     message is known.
                template<typename TMsg>
                static constexpr std::size_t eval_field_length(const TMsg &) {
                    return eval_field_length();
                }

                /// @brief Create message object given the ID.
                /// @details The default implementation is to forwards this call to the next
                ///     layer. One of the layers (usually nil::marshalling::protocol::MsgIdLayer)
                ///     hides and overrides this implementation.
                /// @tparam TMsg Type of message ID.
                /// @param id ID of the message.
                /// @param idx Relative index of the message with the same ID.
                /// @return Smart pointer (variant of std::unique_ptr) to allocated message
                ///     object
                template<typename TId>
                msg_ptr_type create_msg(TId &&id, unsigned idx = 0) {
                    return next_layer().create_msg(std::forward<TId>(id), idx);
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

            protected:
                /// @brief Detect whether type is actual message object
                /// @tparam T Type of the object
                /// @return @b true if @b T type is extending @b nil::marshalling::message_base,
                ///     @b false otherwise.
                template<typename T>
                static constexpr bool is_message_obj_ref() {
                    return has_type_impl_options_type<T>::value;
                }

                /// @brief Reset msg in case it is a smart pointer (@ref msg_ptr_type).
                /// @details Does nothing if passed parameter is actual message object.
                /// @see @ref isMessageObjRef().
                template<typename TMsg>
                static void reset_msg(TMsg &msg) {
                    using tag =
                        typename std::conditional<is_message_obj_ref<typename std::decay<decltype(msg)>::type>(),
                                                  message_obj_tag, smart_ptr_tag>::type;
                    reset_msg_internal(msg, tag());
                }

                void update_missing_size(std::size_t size, std::size_t *missingSize) const {
                    if (missingSize != nullptr) {
                        MARSHALLING_ASSERT(size <= length());
                        *missingSize = std::max(std::size_t(1U), length() - size);
                    }
                }

                void update_missing_size(const field_type &field, std::size_t size, std::size_t *missingSize) const {
                    if (missingSize != nullptr) {
                        auto totalLen = field.length() + nextLayer_.length();
                        MARSHALLING_ASSERT(size <= totalLen);
                        *missingSize = std::max(std::size_t(1U), totalLen - size);
                    }
                }

                template<std::size_t TIdx, typename TAllFields>
                static field_type &get_field(TAllFields &allFields) {
                    static_assert(nil::detail::is_tuple<TAllFields>::value,
                                  "Expected TAllFields to be a tuple");
                    static_assert(TIdx < std::tuple_size<TAllFields>::value, "Invalid tuple access index");

                    auto &field = std::get<TIdx>(allFields);

                    using field_type = typename std::decay<decltype(field)>::type;
                    static_assert(std::is_same<field_type, field_type>::value, "field_type has wrong type");

                    return field;
                }

                /// @cond SKIP_DOC
                struct fixed_length_tag { };
                struct var_length_tag { };
                using length_tag = typename std::conditional<(field_type::min_length() == field_type::max_length()),
                                                             fixed_length_tag, var_length_tag>::type;

                class next_layer_reader {
                public:
                    explicit next_layer_reader(next_layer_type &next_layer) : nextLayer_(next_layer) {
                    }

                    template<typename TMsgPtr, typename TIter>
                    status_type read(TMsgPtr &msg, TIter &iter, std::size_t size, std::size_t *missingSize) {
                        return nextLayer_.read(msg, iter, size, missingSize);
                    }

                private:
                    next_layer_type &nextLayer_;
                };

                class next_layer_until_data_reader {
                public:
                    explicit next_layer_until_data_reader(next_layer_type &next_layer) : nextLayer_(next_layer) {
                    }

                    template<typename TMsgPtr, typename TIter>
                    status_type read(TMsgPtr &msg, TIter &iter, std::size_t size, std::size_t *missingSize) {
                        return nextLayer_.read_until_data(msg, iter, size, missingSize);
                    }

                private:
                    next_layer_type &nextLayer_;
                };

                template<typename TAllFields>
                class next_layer_cached_fields_reader {
                public:
                    next_layer_cached_fields_reader(next_layer_type &next_layer, TAllFields &allFields) :
                        nextLayer_(next_layer), allFields_(allFields) {
                    }

                    template<typename TMsgPtr, typename TIter>
                    status_type read(TMsgPtr &msg, TIter &iter, std::size_t size, std::size_t *missingSize) {
                        return nextLayer_.read_fields_cached(allFields_, msg, iter, size, missingSize);
                    }

                private:
                    next_layer_type &nextLayer_;
                    TAllFields &allFields_;
                };

                template<typename TAllFields>
                class next_layer_cached_fields_until_data_reader {
                public:
                    next_layer_cached_fields_until_data_reader(next_layer_type &next_layer, TAllFields &allFields) :
                        nextLayer_(next_layer), allFields_(allFields) {
                    }

                    template<typename TMsgPtr, typename TIter>
                    status_type read(TMsgPtr &msg, TIter &iter, std::size_t size, std::size_t *missingSize) {
                        return nextLayer_.readUntilDataFieldsCache(allFields_, msg, iter, size, missingSize);
                    }

                private:
                    next_layer_type &nextLayer_;
                    TAllFields &allFields_;
                };

                class next_layer_writer {
                public:
                    explicit next_layer_writer(const next_layer_type &next_layer) : nextLayer_(next_layer) {
                    }

                    template<typename TMsg, typename TIter>
                    status_type write(const TMsg &msg, TIter &iter, std::size_t size) const {
                        return nextLayer_.write(msg, iter, size);
                    }

                private:
                    const next_layer_type &nextLayer_;
                };

                template<typename TAllFields>
                class next_layer_cached_fields_writer {
                public:
                    next_layer_cached_fields_writer(const next_layer_type next_layer, TAllFields &allFields) :
                        nextLayer_(next_layer), allFields_(allFields) {
                    }

                    template<typename TMsg, typename TIter>
                    status_type write(const TMsg &msg, TIter &iter, std::size_t size) const {
                        return nextLayer_.write_fields_cached(allFields_, msg, iter, size);
                    }

                private:
                    const next_layer_type &nextLayer_;
                    TAllFields &allFields_;
                };

                class next_layer_updater {
                public:
                    explicit next_layer_updater(const next_layer_type &next_layer) : nextLayer_(next_layer) {
                    }

                    template<typename TIter>
                    status_type update(TIter &iter, std::size_t size) const {
                        return nextLayer_.update(iter, size);
                    }

                private:
                    const next_layer_type &nextLayer_;
                };

                template<typename TAllFields>
                class next_layer_cached_fields_updater {
                public:
                    next_layer_cached_fields_updater(const next_layer_type next_layer, TAllFields &allFields) :
                        nextLayer_(next_layer), allFields_(allFields) {
                    }

                    template<typename TIter>
                    status_type update(TIter &iter, std::size_t size) const {
                        return nextLayer_.update_fields_cached(allFields_, iter, size);
                    }

                private:
                    const next_layer_type &nextLayer_;
                    TAllFields &allFields_;
                };

                next_layer_reader create_next_layer_reader() {
                    return next_layer_reader(nextLayer_);
                }

                next_layer_until_data_reader create_next_layer_until_data_reader() {
                    return next_layer_until_data_reader(nextLayer_);
                }

                template<typename TAllFields>
                next_layer_cached_fields_reader<TAllFields> create_next_layer_cached_fields_reader(TAllFields &fields) {
                    return next_layer_cached_fields_reader<TAllFields>(nextLayer_, fields);
                }

                template<typename TAllFields>
                next_layer_cached_fields_until_data_reader<TAllFields>
                    create_next_layer_cached_fields_until_data_reader(TAllFields &fields) {
                    return next_layer_cached_fields_until_data_reader<TAllFields>(nextLayer_, fields);
                }

                next_layer_writer create_next_layer_writer() const {
                    return next_layer_writer(nextLayer_);
                }

                template<typename TAllFields>
                next_layer_cached_fields_writer<TAllFields>
                    create_next_layer_cached_fields_writer(TAllFields &fields) const {
                    return next_layer_cached_fields_writer<TAllFields>(nextLayer_, fields);
                }

                next_layer_updater create_next_layer_updater() const {
                    return next_layer_updater(nextLayer_);
                }

                template<typename TAllFields>
                next_layer_cached_fields_updater<TAllFields>
                    create_next_layer_cached_fields_updater(TAllFields &fields) const {
                    return next_layer_cached_fields_updater<TAllFields>(nextLayer_, fields);
                }

                /// @endcond
            private:
                struct normal_read_tag { };
                struct split_read_tag { };
                struct message_obj_tag { };
                struct smart_ptr_tag { };

                template<typename TMsg, typename TIter>
                nil::marshalling::status_type read_internal(TMsg &msg, TIter &iter, std::size_t size,
                                                            std::size_t *missingSize, normal_read_tag) {
                    field_type field;
                    auto &derivedObj = static_cast<TDerived &>(*this);
                    return derivedObj.eval_read(field, msg, iter, size, missingSize, create_next_layer_reader());
                }

                template<typename TMsgPtr, typename TIter>
                nil::marshalling::status_type read_internal(TMsgPtr &msgPtr, TIter &iter, std::size_t size,
                                                            std::size_t *missingSize, split_read_tag) {
                    auto fromIter = iter;
                    auto es = read_until_data(msgPtr, iter, size, missingSize);
                    if (es != nil::marshalling::status_type::success) {
                        return es;
                    }

                    auto consumed = static_cast<std::size_t>(std::distance(fromIter, iter));
                    MARSHALLING_ASSERT(consumed <= size);
                    return read_from_data(msgPtr, iter, size - consumed, missingSize);
                }

                template<typename TIter, typename TNextLayerUpdater>
                nil::marshalling::status_type update_internal(field_type &field, TIter &iter, std::size_t size,
                                                              TNextLayerUpdater &&nextLayerUpdater,
                                                              fixed_length_tag) const {
                    auto len = field.length();
                    MARSHALLING_ASSERT(len <= size);
                    std::advance(iter, len);
                    return nextLayerUpdater.update(iter, size - len);
                }

                template<typename TIter, typename TNextLayerUpdater>
                nil::marshalling::status_type update_internal(field_type &field, TIter &iter, std::size_t size,
                                                              TNextLayerUpdater &&nextLayerUpdater,
                                                              var_length_tag) const {
                    auto es = field.read(iter, size);
                    if (es == nil::marshalling::status_type::success) {
                        es = nextLayerUpdater.update(iter, size - field.length());
                    }
                    return es;
                }

                template<typename TMsg>
                static void reset_msg_internal(TMsg &, message_obj_tag) {
                    // Do nothing
                }

                template<typename TMsg>
                static void reset_msg_internal(TMsg &msg, smart_ptr_tag) {
                    msg.reset();
                }

                static_assert(nil::detail::is_tuple<all_fields_type>::value, "Must be tuple");
                next_layer_type nextLayer_;
            };

            /// @brief Upcast protocol layer in order to have
            ///     access to its internal types.
            template<typename TField, typename TNextLayer, typename TDerived, typename... TOptions>
            protocol_layer_base<TField, TNextLayer, TDerived, TOptions...> &
                to_protocol_layer_base(protocol_layer_base<TField, TNextLayer, TDerived, TOptions...> &layer) {
                return layer;
            }

            /// @brief Upcast protocol layer in order to have
            ///     access to its internal types.
            template<typename TField, typename TNextLayer, typename TDerived, typename... TOptions>
            constexpr const protocol_layer_base<TField, TNextLayer, TDerived, TOptions...> &
                to_protocol_layer_base(const protocol_layer_base<TField, TNextLayer, TDerived, TOptions...> &layer) {
                return layer;
            }

        }    // namespace protocol
    }        // namespace marshalling
}    // namespace nil

/// @brief Provide names and convenience access functions to protocol
///     layers.
/// @details The first argument is a name for innermost layer
///     (@ref nil::marshalling::protocol::MsgDataLayer), while the last one
///     is the name for the outermost one.
/// @related nil::marshalling::protocol::ProtocolLayerBase
#define MARSHALLING_PROTOCOL_LAYERS_ACCESS(...) MARSHALLING_DO_ACCESS_LAYER_ACC_FUNC(__VA_ARGS__)

/// @brief Same as @ref MARSHALLING_PROTOCOL_LAYERS_ACCESS()
/// @related nil::marshalling::protocol::ProtocolLayerBase
#define MARSHALLING_PROTOCOL_LAYERS_ACCESS_INNER(...) MARSHALLING_PROTOCOL_LAYERS_ACCESS(__VA_ARGS__)

/// @brief Provide names and convenience access functions to protocol
///     layers.
/// @details Similar to @ref MARSHALLING_PROTOCOL_LAYERS_ACCESS(), but
///     the arguments are expected to be in reverse order, i.e.
///     the first argument is the name of the outermost layer, while
///     the last one is the name for the innermost one
///     (@ref nil::marshalling::protocol::MsgDataLayer)
/// @related nil::marshalling::protocol::ProtocolLayerBase
#define MARSHALLING_PROTOCOL_LAYERS_ACCESS_OUTER(...) \
    MARSHALLING_PROTOCOL_LAYERS_ACCESS(MARSHALLING_EXPAND(MARSHALLING_REVERSE_MACRO_ARGS(__VA_ARGS__)))
#endif    // MARSHALLING_PROTOCOL_LAYER_BASE_HPP
