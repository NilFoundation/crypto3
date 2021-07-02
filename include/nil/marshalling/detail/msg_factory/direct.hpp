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

#ifndef MARSHALLING_MSG_FACTORY_DIRECT_HPP
#define MARSHALLING_MSG_FACTORY_DIRECT_HPP

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/detail/msg_factory/base.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {
            namespace msg_factory {

                template<typename TMsgBase, typename TAllMessages, typename... TOptions>
                class direct : public base<TMsgBase, TAllMessages, TOptions...> {
                    using base_impl_type = base<TMsgBase, TAllMessages, TOptions...>;

                public:
                    using all_messages_type = typename base_impl_type::all_messages_type;
                    using msg_ptr_type = typename base_impl_type::msg_ptr_type;
                    using msg_id_param_type = typename base_impl_type::msg_id_param_type;
                    using msg_id_type = typename base_impl_type::msg_id_type;

                    direct() {
                        init_registry();
                    }

                    msg_ptr_type create_msg(msg_id_param_type id, unsigned idx = 0) const {
                        if (0 < idx) {
                            return msg_ptr_type();
                        }

                        auto method = get_method(id);
                        if (method == nullptr) {
                            return msg_ptr_type();
                        }

                        return method->create(*this);
                    }

                    std::size_t msg_count(msg_id_param_type id) const {
                        auto method = get_method(id);
                        if (method == nullptr) {
                            return 0U;
                        }
                        return 1U;
                    }

                    static constexpr bool has_unique_ids() {
                        return true;
                    }

                private:
                    static_assert(nil::detail::is_tuple<all_messages_type>::value,
                                  "TAllMessages is expected to be a tuple.");

                    static_assert(0U < std::tuple_size<all_messages_type>::value,
                                  "TAllMessages is expected to be a non-empty tuple.");

                    using last_message_type = typename std::tuple_element<std::tuple_size<all_messages_type>::value - 1,
                                                                          all_messages_type>::type;

                    static const std::size_t messages_amount
                        = static_cast<std::size_t>(last_message_type::impl_options_type::msg_id) + 1U;

                    template<typename TMessage>
                    using num_id_factory_method_type =
                        typename base_impl_type::template num_id_factory_method<TMessage>;

                    using factory_method_type = typename base_impl_type::factory_method;
                    using methods_registry_type = std::array<const factory_method_type *, messages_amount>;

                    class creator {
                    public:
                        creator(methods_registry_type &registry) : registry_(registry) {
                        }

                        template<typename TMessage>
                        void operator()() {
                            static const std::size_t Idx
                                = static_cast<std::size_t>(TMessage::impl_options_type::msg_id);

                            static_assert(Idx < messages_amount, "Invalid message id");

                            static const num_id_factory_method_type<TMessage> Factory;
                            MARSHALLING_ASSERT(registry_[Idx] == nullptr);
                            registry_[Idx] = &Factory;
                        }

                    private:
                        methods_registry_type &registry_;
                    };

                    void init_registry() {
                        std::fill(registry_.begin(), registry_.end(), nullptr);
                        processing::tuple_for_each_type<all_messages_type>(creator(registry_));
                    }

                    const factory_method_type *get_method(msg_id_param_type id) const {
                        auto elemIdx = static_cast<std::size_t>(id);
                        if (registry_.size() <= elemIdx) {
                            return nullptr;
                        }

                        return registry_[elemIdx];
                    }

                    methods_registry_type registry_;
                };

            }    // namespace msg_factory
        }        // namespace detail
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MSG_FACTORY_DIRECT_HPP
