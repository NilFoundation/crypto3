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

#ifndef MARSHALLING_MSG_FACTORY_UNIQ_HPP
#define MARSHALLING_MSG_FACTORY_UNIQ_HPP

#include <nil/marshalling/detail/msg_factory/bin_search_base.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {
            namespace msg_factory {

                template<typename TMsgBase, typename TAllMessages, typename... TOptions>
                class uniq : public bin_search_base<TMsgBase, TAllMessages, TOptions...> {
                    using base_impl_type = bin_search_base<TMsgBase, TAllMessages, TOptions...>;

                public:
                    using all_messages_type = typename base_impl_type::all_messages_type;
                    using msg_ptr_type = typename base_impl_type::msg_ptr_type;
                    using msg_id_param_type = typename base_impl_type::msg_id_param_type;
                    using msg_id_type = typename base_impl_type::msg_id_type;

                    msg_ptr_type create_msg(msg_id_param_type id, unsigned idx = 0) const {
                        if (0 < idx) {
                            return msg_ptr_type();
                        }

                        auto iter = find_method(id);
                        if (iter == base_impl_type::registry().end()) {
                            return msg_ptr_type();
                        }

                        MARSHALLING_ASSERT(*iter != nullptr);
                        if ((*iter)->get_id() != id) {
                            return msg_ptr_type();
                        }

                        return (*iter)->create(*this);
                    }

                    std::size_t msg_count(msg_id_param_type id) const {
                        auto iter = find_method(id);

                        if (iter == base_impl_type::registry().end()) {
                            return 0U;
                        }

                        MARSHALLING_ASSERT(*iter != nullptr);
                        if ((*iter)->get_id() != id) {
                            return 0U;
                        }

                        return 1U;
                    }

                    static constexpr bool has_unique_ids() {
                        return true;
                    }

                private:
                    using factory_method_type = typename base_impl_type::factory_method_type;
                    using methods_registry_type = typename base_impl_type::methods_registry_type;

                    typename methods_registry_type::const_iterator find_method(msg_id_param_type id) const {
                        return std::lower_bound(
                            base_impl_type::registry().begin(), base_impl_type::registry().end(), id,
                            [](const factory_method_type *method, msg_id_param_type idParam) -> bool {
                                return method->get_id() < idParam;
                            });
                    }
                };

            }    // namespace msg_factory
        }        // namespace detail
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MSG_FACTORY_UNIQ_HPP
