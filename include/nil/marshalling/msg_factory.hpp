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
/// Contains definition of nil::marshalling::msg_factory class.

#ifndef MARSHALLING_MESSAGE_FACTORY_HPP
#define MARSHALLING_MESSAGE_FACTORY_HPP

#include <type_traits>
#include <algorithm>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/processing/tuple.hpp>
#include <nil/marshalling/processing/alloc.hpp>

#include <nil/marshalling/detail/msg_factory/options_parser.hpp>
#include <nil/marshalling/detail/msg_factory/selector.hpp>

namespace nil {
    namespace marshalling {

        /// @brief message factory class.
        /// @details It is responsible to create message objects given the ID of the
        ///     message. This class @b DOESN'T use dynamic memory allocation to store its
        ///     internal data structures, hence can be used in any bare-metal and other
        ///     embedded environment.@n
        ///     The types of all messages provided in @b TAllMessages are analysed at
        ///     compile time and best "id to message object" mapping strategy is chosen,
        ///     whether it is direct access array (with O(1) time complexity) or
        ///     sorted array with binary search (with O(log(n)) time complexity).
        /// @tparam TMsgBase Common base class for all the messages, smart pointer to
        ///     this type is returned when allocation of specify message is requested.
        /// @tparam TAllMessages All custom message types, that this factory is capable
        ///     of creating, bundled in std::tuple<>. The message types must be sorted
        ///     based on their IDs. Different variants of the same message (reporting
        ///     same ID, but implemented as different classes) are also supported. However
        ///     they must follow one another in this std::tuple, i.e. be sorted.
        /// @tparam TOptions Zero or more options. The supported options are:
        ///     @li nil::marshalling::option::InPlaceAllocation - Option to specify that custom
        ///         message objects are @b NOT allocated using dynamic memory, instead
        ///         an uninitialised area of memory in private members is used to contain
        ///         any type of custom message (provided with TAllMessages template parameter) and
        ///         placement "new" operator is used to initialise requested message in
        ///         this area.
        ///         The allocated message objects are returned from create_msg() function
        ///         wrapped in the smart pointer (variant of std::unique_ptr). If
        ///         nil::marshalling::option::InPlaceAllocation option is used, then the smart pointer
        ///         definition contains custom deleter, which will explicitly invoke
        ///         destructor of the message when the smart pointer is out of scope. It
        ///         means that it is @b NOT possible to create new message with this factory
        ///         if previously allocated one wasn't destructed yet.
        ///         If nil::marshalling::option::InPlaceAllocation option is NOT used, than the
        ///         requested message objects are allocated using dynamic memory and
        ///         returned wrapped in std::unique_ptr without custom deleter.
        ///     @li nil::marshalling::option::SupportGenericMessage - Option used to allow
        ///         allocation of @ref nil::marshalling::generic_message. If such option is
        ///         provided, the createGenericMsg() member function will be able
        ///         to allocate @ref nil::marshalling::generic_message object. @b NOTE, that
        ///         the base class of @ref nil::marshalling::generic_message type (first template
        ///         parameter) must be equal to @b TMsgBase (first template parameter)
        ///         of @b this class.
        /// @pre TMsgBase is a base class for all the messages in TAllMessages.
        /// @pre message type is TAllMessages must be sorted based on their IDs.
        /// @pre If nil::marshalling::option::InPlaceAllocation option is provided, only one custom
        ///     message can be allocated. The next one can be allocated only after previous
        ///     message has been destructed.
        /// @headerfile nil/marshalling/msg_factory.h
        template<typename TMsgBase, typename TAllMessages, typename... TOptions>
        class msg_factory {
            static_assert(TMsgBase::interface_options_type::has_msg_id_type,
                          "Usage of msg_factory requires message interface to provide ID type. "
                          "Use nil::marshalling::option::msg_id_type option in message interface type definition.");

            using factory_type = typename detail::msg_factory::selector<TMsgBase, TAllMessages, TOptions...>::type;

        public:
            /// @brief Parsed options
            using parsed_options_type = typename factory_type::parsed_options_type;

            /// @brief Type of the common base class of all the messages.
            using message_type = TMsgBase;

            /// @brief Type of the message ID when passed as a parameter.
            using msg_id_param_type = typename message_type::msg_id_param_type;

            /// @brief Type of the message ID.
            using msg_id_type = typename message_type::msg_id_type;

            /// @brief Smart pointer to @ref message which holds allocated message object.
            /// @details It is a variant of std::unique_ptr, based on whether
            ///     nil::marshalling::option::InPlaceAllocation option was used.
            using msg_ptr_type = typename factory_type::msg_ptr_type;

            /// @brief All messages provided as template parameter to this class.
            using all_messages_type = TAllMessages;

            /// @brief Create message object given the ID of the message.
            /// @param id ID of the message.
            /// @param idx Relative index of the message with the same ID. In case
            ///     protocol implementation contains multiple distinct message types
            ///     that report same ID value, it must be possible to choose the
            ///     relative index of such message from the first message type reporting
            ///     the same ID. This parameter provides such an ability. However,
            ///     most protocols will implement single message class for single ID.
            ///     For such implementations, use default value of this parameter.
            /// @return Smart pointer (variant of std::unique_ptr) to @ref message type,
            ///     which is a common base class of all the messages (provided as
            ///     first template parameter to this class). If nil::marshalling::option::InPlaceAllocation
            ///     option was used and previously allocated message wasn't de-allocated
            ///     yet, the empty (null) pointer will be returned.
            msg_ptr_type create_msg(msg_id_param_type id, unsigned idx = 0) const {
                return factory_.create_msg(id, idx);
            }

            /// @brief Allocate and initialise @ref nil::marshalling::generic_message object.
            /// @details If nil::marshalling::option::SupportGenericMessage option hasn't been
            ///     provided, this function will return empty @b msg_ptr_type pointer. Otherwise
            ///     the relevant allocator will be used to allocate @ref nil::marshalling::generic_message.
            /// @param[in] id ID of the message, will be passed as a parameter to the
            ///     constructor of the @ref nil::marshalling::generic_message class
            msg_ptr_type create_generic_msg(msg_id_param_type id) const {
                return factory_.create_generic_msg(id);
            }

            /// @brief Get number of message types from @ref all_messages_type, that have the specified ID.
            /// @param id ID of the message.
            /// @return Number of message classes that report same ID.
            std::size_t msg_count(msg_id_param_type id) const {
                return factory_.msg_count(id);
            }

            /// @brief Compile time knowldege inquiry whether all the message classes in the
            ///     @b TAllMessages bundle have unique IDs.
            static constexpr bool has_unique_ids() {
                return factory_type::has_unique_ids();
            }

        private:
            factory_type factory_;
        };

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MESSAGE_FACTORY_HPP
