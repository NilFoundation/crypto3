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

#ifndef MARSHALLING_MESSAGE_INTERFACE_OPTIONS_PARSER_HPP
#define MARSHALLING_MESSAGE_INTERFACE_OPTIONS_PARSER_HPP

#include <cstdint>
#include <tuple>

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/options.hpp>
#include <nil/marshalling/processing/tuple.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {
            namespace message {

                template<typename... TOptions>
                class interface_options_parser;

                template<>
                class interface_options_parser<> {
                public:
                    static const bool has_msg_id_type = false;
                    static const bool has_endian = false;
                    static const bool has_read_iterator = false;
                    static const bool has_write_iterator = false;
                    static const bool has_msg_id_info = false;
                    static const bool has_handler = false;
                    static const bool has_valid = false;
                    static const bool has_length = false;
                    static const bool has_refresh = false;
                    static const bool has_name = false;
                    static const bool has_no_virtual_destructor = false;
                    static const bool has_extra_transport_fields = false;
                    static const bool has_version_in_extra_transport_fields = false;
                };

                template<typename T, typename... TOptions>
                class interface_options_parser<nil::marshalling::option::msg_id_type<T>, TOptions...>
                    : public interface_options_parser<TOptions...> {
                public:
                    using msg_id_type = T;
                    static const bool has_msg_id_type = true;
                };

                template<typename... TOptions>
                class interface_options_parser<nil::marshalling::option::id_info_interface, TOptions...>
                    : public interface_options_parser<TOptions...> {
                public:
                    static const bool has_msg_id_info = true;
                };

                template<typename TEndian, typename... TOptions>
                class interface_options_parser<nil::marshalling::option::endian<TEndian>, TOptions...>
                    : public interface_options_parser<TOptions...> {
                public:
                    static const bool has_endian = true;
                    using endian_type = TEndian;
                };

                template<typename TIter, typename... TOptions>
                class interface_options_parser<nil::marshalling::option::read_iterator<TIter>, TOptions...>
                    : public interface_options_parser<TOptions...> {
                public:
                    static const bool has_read_iterator = true;
                    using read_iterator = TIter;
                };

                template<typename TIter, typename... TOptions>
                class interface_options_parser<nil::marshalling::option::write_iterator<TIter>, TOptions...>
                    : public interface_options_parser<TOptions...> {
                public:
                    static const bool has_write_iterator = true;
                    using write_iterator = TIter;
                };

                template<typename T, typename... TOptions>
                class interface_options_parser<nil::marshalling::option::handler<T>, TOptions...>
                    : public interface_options_parser<TOptions...> {
                public:
                    static const bool has_handler = true;
                    using handler_type = T;
                };

                template<typename... TOptions>
                class interface_options_parser<nil::marshalling::option::valid_check_interface, TOptions...>
                    : public interface_options_parser<TOptions...> {
                public:
                    static const bool has_valid = true;
                };

                template<typename... TOptions>
                class interface_options_parser<nil::marshalling::option::length_info_interface, TOptions...>
                    : public interface_options_parser<TOptions...> {
                public:
                    static const bool has_length = true;
                };

                template<typename... TOptions>
                class interface_options_parser<nil::marshalling::option::refresh_interface, TOptions...>
                    : public interface_options_parser<TOptions...> {
                public:
                    static const bool has_refresh = true;
                };

                template<typename... TOptions>
                class interface_options_parser<nil::marshalling::option::name_interface, TOptions...>
                    : public interface_options_parser<TOptions...> {
                public:
                    static const bool has_name = true;
                };

                template<typename... TOptions>
                class interface_options_parser<nil::marshalling::option::no_virtual_destructor, TOptions...>
                    : public interface_options_parser<TOptions...> {
                public:
                    static const bool has_no_virtual_destructor = true;
                };

                template<typename TFields, typename... TOptions>
                class interface_options_parser<nil::marshalling::option::extra_transport_fields<TFields>, TOptions...>
                    : public interface_options_parser<TOptions...> {
                    static_assert(
                        nil::detail::is_tuple<TFields>::value,
                        "Template parameter to nil::marshalling::option::extra_transport_fields is expected to "
                        "be std::tuple.");

                public:
                    static const bool has_extra_transport_fields = true;
                    using extra_transport_fields_type = TFields;
                };

                template<std::size_t TIdx, typename... TOptions>
                class interface_options_parser<nil::marshalling::option::version_in_extra_transport_fields<TIdx>,
                                               TOptions...> : public interface_options_parser<TOptions...> {
                public:
                    static const bool has_version_in_extra_transport_fields = true;
                    static const std::size_t version_in_extra_transport_fields = TIdx;
                };

                template<typename... TOptions>
                class interface_options_parser<nil::marshalling::option::empty_option, TOptions...>
                    : public interface_options_parser<TOptions...> { };

                template<typename... TBundledOptions, typename... TOptions>
                class interface_options_parser<std::tuple<TBundledOptions...>, TOptions...>
                    : public interface_options_parser<TBundledOptions..., TOptions...> { };

            }    // namespace message
        }        // namespace detail
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MESSAGE_INTERFACE_OPTIONS_PARSER_HPP
