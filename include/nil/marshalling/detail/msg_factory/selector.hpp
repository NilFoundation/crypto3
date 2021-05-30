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

#ifndef MARSHALLING_MSG_FACTORY_SELECTOR_HPP
#define MARSHALLING_MSG_FACTORY_SELECTOR_HPP

#include <type_traits>
#include <nil/marshalling/detail/msg_factory/direct.hpp>
#include <nil/marshalling/detail/msg_factory/uniq.hpp>
#include <nil/marshalling/detail/msg_factory/generic.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {
            namespace msg_factory {

                template<typename TAllMessages>
                using last_message_type =
                    typename std::tuple_element<std::tuple_size<TAllMessages>::value - 1, TAllMessages>::type;

                template<typename TAllMessages>
                constexpr bool can_direct_access() {
                    return static_cast<std::size_t>(last_message_type<TAllMessages>::impl_options_type::msg_id)
                           < (std::tuple_size<TAllMessages>::value + 10);
                }

                template<bool TStrongSorted>
                struct static_num_id_selector;

                template<>
                struct static_num_id_selector<true> {
                    template<typename TMsgBase, typename TAllMessages, typename... TOptions>
                    using type = typename std::conditional<can_direct_access<TAllMessages>(),
                                                           direct<TMsgBase, TAllMessages, TOptions...>,
                                                           uniq<TMsgBase, TAllMessages, TOptions...>>::type;
                };

                template<>
                struct static_num_id_selector<false> {
                    template<typename TMsgBase, typename TAllMessages, typename... TOptions>
                    using type = generic<TMsgBase, TAllMessages, TOptions...>;
                };

                template<typename TMsgBase, typename TAllMessages, typename... TOptions>
                using static_num_id_selector_type = typename static_num_id_selector<
                    are_all_strong_sorted<TAllMessages>()>::template type<TMsgBase, TAllMessages, TOptions...>;

                template<typename TMsgBase, typename TAllMessages, typename... TOptions>
                struct selector {
                    using type =
                        typename std::conditional<all_have_static_num_id<TAllMessages>(),
                                                  static_num_id_selector_type<TMsgBase, TAllMessages, TOptions...>,
                                                  generic<TMsgBase, TAllMessages, TOptions...>>::type;
                };

            }    // namespace msg_factory
        }        // namespace detail
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MSG_FACTORY_SELECTOR_HPP
