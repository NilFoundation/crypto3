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
/// Provides implementation of @ref nil::marshalling::generic_message class

#ifndef MARSHALLING_GENERIC_MESSAGE_HPP
#define MARSHALLING_GENERIC_MESSAGE_HPP

#include <tuple>
#include <cstdint>

#include <nil/marshalling/options.hpp>
#include <nil/marshalling/message_base.hpp>

#include <nil/marshalling/types/array_list.hpp>

namespace nil {
    namespace marshalling {

        /// @brief Definition of fields for @ref nil::marshalling::generic_message message
        /// @details Defined as single variable length raw bytes sequence
        ///     (@ref nil::marshalling::types::array_list).
        /// @tparam Base class for the sequence field definition, expected to be a
        ///     variant of @ref nil::marshalling::field_type
        /// @tparam Extra option(s) (bundled as @b std::tuple if multiple) to be
        ///     passed to @ref nil::marshalling::types::array_list field definition.
        template<typename TFieldBase, typename TExtraOpts = nil::marshalling::option::empty_option>
        using generic_message_fields
            = std::tuple<nil::marshalling::types::array_list<TFieldBase, std::uint8_t, TExtraOpts>>;

        /// @brief Generic message
        /// @details Generic message is there to substitute definition of actual message
        ///     when contents of the latter are not important. It defines single @b data
        ///     field as variable length sequence of raw bytes (see @ref GenericMessageFields).
        ///     The generic_message can be useful when implementing some kind of
        ///     "bridge" or "firewall", that requires knowledge only about message
        ///     ID and doesn't care much about message contents. The
        ///     @ref nil::marshalling::protocol::MsgIdLayer support creation of the
        ///     generic_message in case the received message ID is not known (supported
        ///     by using @ref nil::marshalling::option::SupportGenericMessage option).
        /// @tparam TMessage Common message interface class, becomes one of the
        ///     base classes.
        /// @tparam TFieldOpts Extra option(s) (multiple options need to be bundled in
        ///     @b std::tuple) to be passed to the definition of the @b data
        ///     field (see @ref GenericMessageFields).
        /// @tparam TExtraOpts Extra option(s) (multple options need to be bundled in
        ///     @b std::tuple) to be passed to @ref nil::marshalling::message_base which is base
        ///     to this one.
        /// @pre Requires the common message interface (@b TMessage) to define
        ///     inner @b msg_id_type and @b msg_id_param_type types (expected to use
        ///     @ref nil::marshalling::option::msg_id_type, see @ref page_use_prot_transport_generic_msg)
        /// @headerfile nil/marshalling/generic_message.h
        template<typename TMessage, typename TFieldOpts = nil::marshalling::option::empty_option,
                 typename TExtraOpts = nil::marshalling::option::empty_option>
        class generic_message
            : public nil::marshalling::message_base<
                  TMessage,
                  nil::marshalling::option::fields_impl<
                      generic_message_fields<typename TMessage::field_type, TFieldOpts>>,
                  nil::marshalling::option::msg_type<generic_message<TMessage, TFieldOpts, TExtraOpts>>,
                  nil::marshalling::option::has_do_get_id, nil::marshalling::option::has_name, TExtraOpts> {
            using Base = nil::marshalling::message_base<
                TMessage,
                nil::marshalling::option::fields_impl<
                    generic_message_fields<typename TMessage::field_type, TFieldOpts>>,
                nil::marshalling::option::msg_type<generic_message<TMessage, TFieldOpts, TExtraOpts>>,
                nil::marshalling::option::has_do_get_id, nil::marshalling::option::has_name, TExtraOpts>;

        public:
            /// @brief Type of the message ID
            /// @details The same as nil::marshalling::message::msg_id_type;
            using msg_id_type = typename Base::msg_id_type;

            /// @brief Type of the message ID passed as parameter
            /// @details The same as nil::marshalling::message::msg_id_param_type;
            using msg_id_param_type = typename Base::msg_id_param_type;

            /// @brief Default constructor is deleted
            generic_message() = delete;

            /// @brief Constructor
            /// @param[in] id ID of the message
            explicit generic_message(msg_id_param_type id) : m_id(id) {
            }

            /// @brief Copy constructor
            generic_message(const generic_message &) = default;

            /// @brief Move constructor
            generic_message(generic_message &&) = default;

            /// @brief Destructor
            ~generic_message() noexcept = default;

            /// @brief Copy assignment
            generic_message &operator=(const generic_message &) = default;

            /// @brief Move assignment
            generic_message &operator=(generic_message &&) = default;

            /// @brief Allow access to internal fields.
            /// @details See definition of @ref MARSHALLING_MSG_FIELDS_ACCESS() macro
            ///     related to @b nil::marshalling::message_base class for details.
            ///
            MARSHALLING_MSG_FIELDS_ACCESS(data);

            /// @brief Get message ID information
            /// @details The nil::marshalling::message_base::get_id_impl() will invoke this
            ///     function.
            msg_id_param_type eval_get_id() const {
                return m_id;
            }

            /// @brief Get message name information.
            /// @details The nil::marshalling::message_base::name_impl() will invoke this
            ///     function.
            const char *eval_name() const {
                return "Generic message";
            }

        private:
            msg_id_type m_id;
        };

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_GENERIC_MESSAGE_HPP
