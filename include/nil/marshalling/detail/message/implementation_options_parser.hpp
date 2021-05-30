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

#ifndef MARSHALLING_MESSAGE_IMPL_OPTIONS_PARSER_HPP
#define MARSHALLING_MESSAGE_IMPL_OPTIONS_PARSER_HPP

#include <nil/marshalling/options.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {
            namespace message {

                template<typename... TOptions>
                class impl_options_parser;

                template<>
                class impl_options_parser<> {
                public:
                    constexpr static const bool has_static_msg_id = false;
                    constexpr static const bool has_fields_impl = false;
                    constexpr static const bool has_no_id_impl = false;
                    constexpr static const bool has_msg_type = false;
                    constexpr static const bool has_no_dispatch_impl = false;
                    constexpr static const bool has_no_read_impl = false;
                    constexpr static const bool has_no_write_impl = false;
                    constexpr static const bool has_no_length_impl = false;
                    constexpr static const bool has_no_valid_impl = false;
                    constexpr static const bool has_no_refresh_impl = false;
                    constexpr static const bool has_custom_refresh = false;
                    constexpr static const bool has_name = false;
                    constexpr static const bool has_do_get_id = false;
                };

                template<std::intmax_t TId, typename... TOptions>
                class impl_options_parser<nil::marshalling::option::static_num_id_impl<TId>, TOptions...>
                    : public impl_options_parser<TOptions...> {
                    using base_impl_type = impl_options_parser<TOptions...>;

                    static_assert(!base_impl_type::has_static_msg_id,
                                  "nil::marshalling::option::static_num_id_impl option is used more than once");
                    static_assert(
                        !base_impl_type::has_no_id_impl,
                        "nil::marshalling::option::no_id_impl and nil::marshalling::option::static_num_id_impl "
                        "options cannot "
                        "be used together");

                public:
                    constexpr static const bool has_static_msg_id = true;
                    constexpr static const auto msg_id = TId;
                };

                template<typename... TOptions>
                class impl_options_parser<nil::marshalling::option::no_dispatch_impl, TOptions...>
                    : public impl_options_parser<TOptions...> {
                public:
                    constexpr static const bool has_no_dispatch_impl = true;
                };

                template<typename TFields, typename... TOptions>
                class impl_options_parser<nil::marshalling::option::fields_impl<TFields>, TOptions...>
                    : public impl_options_parser<TOptions...> {
                    using base_impl_type = impl_options_parser<TOptions...>;

                    static_assert(!base_impl_type::has_fields_impl,
                                  "nil::marshalling::option::fields_impl option is used more than once");

                public:
                    constexpr static const bool has_fields_impl = true;
                    using fields_type = TFields;
                };

                template<typename... TOptions>
                class impl_options_parser<nil::marshalling::option::no_id_impl, TOptions...>
                    : public impl_options_parser<TOptions...> {
                    using base_impl_type = impl_options_parser<TOptions...>;

                    static_assert(!base_impl_type::has_no_id_impl,
                                  "nil::marshalling::option::no_id_impl option is used more than once");
                    static_assert(
                        !base_impl_type::has_static_msg_id,
                        "nil::marshalling::option::no_id_impl and nil::marshalling::option::static_num_id_impl "
                        "options cannot "
                        "be used together");

                public:
                    constexpr static const bool has_no_id_impl = true;
                };

                template<typename... TOptions>
                class impl_options_parser<nil::marshalling::option::no_read_impl, TOptions...>
                    : public impl_options_parser<TOptions...> {
                public:
                    constexpr static const bool has_no_read_impl = true;
                };

                template<typename... TOptions>
                class impl_options_parser<nil::marshalling::option::no_write_impl, TOptions...>
                    : public impl_options_parser<TOptions...> {
                public:
                    constexpr static const bool has_no_write_impl = true;
                };

                template<typename... TOptions>
                class impl_options_parser<nil::marshalling::option::no_length_impl, TOptions...>
                    : public impl_options_parser<TOptions...> {
                public:
                    constexpr static const bool has_no_length_impl = true;
                };

                template<typename... TOptions>
                class impl_options_parser<nil::marshalling::option::no_valid_impl, TOptions...>
                    : public impl_options_parser<TOptions...> {
                public:
                    constexpr static const bool has_no_valid_impl = true;
                };

                template<typename... TOptions>
                class impl_options_parser<nil::marshalling::option::no_refresh_impl, TOptions...>
                    : public impl_options_parser<TOptions...> {
                public:
                    constexpr static const bool has_no_refresh_impl = true;
                };

                template<typename... TOptions>
                class impl_options_parser<nil::marshalling::option::has_custom_refresh, TOptions...>
                    : public impl_options_parser<TOptions...> {
                public:
                    constexpr static const bool has_custom_refresh = true;
                };

                template<typename... TOptions>
                class impl_options_parser<nil::marshalling::option::has_name, TOptions...>
                    : public impl_options_parser<TOptions...> {
                public:
                    constexpr static const bool has_name = true;
                };

                template<typename... TOptions>
                class impl_options_parser<nil::marshalling::option::has_do_get_id, TOptions...>
                    : public impl_options_parser<TOptions...> {
                public:
                    constexpr static const bool has_do_get_id = true;
                };

                template<typename TMsgType, typename... TOptions>
                class impl_options_parser<nil::marshalling::option::msg_type<TMsgType>, TOptions...>
                    : public impl_options_parser<TOptions...> {
                    using base_impl_type = impl_options_parser<TOptions...>;

                    static_assert(!base_impl_type::has_msg_type,
                                  "nil::marshalling::option::msg_type option is used more than once");

                public:
                    constexpr static const bool has_msg_type = true;
                    using msg_type = TMsgType;
                };

                template<typename... TOptions>
                class impl_options_parser<nil::marshalling::option::empty_option, TOptions...>
                    : public impl_options_parser<TOptions...> { };

                template<typename... TBundledOptions, typename... TOptions>
                class impl_options_parser<std::tuple<TBundledOptions...>, TOptions...>
                    : public impl_options_parser<TBundledOptions..., TOptions...> { };

            }    // namespace message
        }        // namespace detail
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MESSAGE_IMPL_OPTIONS_PARSER_HPP
