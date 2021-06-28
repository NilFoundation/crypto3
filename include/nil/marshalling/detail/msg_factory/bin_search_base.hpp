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

#ifndef MARSHALLING_MSG_FACTORY_BIN_SEARCH_BASE_HPP
#define MARSHALLING_MSG_FACTORY_BIN_SEARCH_BASE_HPP

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/detail/msg_factory/base.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {
            namespace msg_factory {

                template<bool TStrong, typename... TMessages>
                struct bin_search_sorted_check_helper;

                template<bool TStrong, typename TMessage1, typename TMessage2, typename TMessage3, typename... TRest>
                struct bin_search_sorted_check_helper<TStrong, TMessage1, TMessage2, TMessage3, TRest...> {
                    static const bool value
                        = bin_search_sorted_check_helper<TStrong, TMessage1, TMessage2>::value
                          && bin_search_sorted_check_helper<TStrong, TMessage2, TMessage3, TRest...>::value;
                };

                template<bool TStrong, typename TMessage1, typename TMessage2>
                struct bin_search_sorted_check_helper<TStrong, TMessage1, TMessage2> {
                private:
                    struct strong_tag { };
                    struct weak_tag { };
                    using tag_type = typename std::conditional<TStrong, strong_tag, weak_tag>::type;

                    template<typename T1, typename T2>
                    static constexpr bool is_less(strong_tag) {
                        return T1::impl_options_type::msg_id < T2::impl_options_type::msg_id;
                    }

                    template<typename T1, typename T2>
                    static constexpr bool is_less(weak_tag) {
                        return T1::impl_options_type::msg_id <= T2::impl_options_type::msg_id;
                    }

                    template<typename T1, typename T2>
                    static constexpr bool is_less() {
                        return is_less<T1, T2>(tag_type());
                    }

                    static_assert(TMessage1::impl_options_type::has_static_msg_id,
                                  "message is expected to provide status numeric ID");
                    static_assert(TMessage2::impl_options_type::has_static_msg_id,
                                  "message is expected to provide status numeric ID");

                public:
                    ~bin_search_sorted_check_helper() noexcept = default;

                    static const bool value = is_less<TMessage1, TMessage2>();
                };

                template<bool TStrong, typename TMessage1>
                struct bin_search_sorted_check_helper<TStrong, TMessage1> {
                    static_assert(!nil::detail::is_tuple<TMessage1>::value,
                                  "TMessage1 mustn't be tuple");
                    static const bool value = true;
                };

                template<bool TStrong>
                struct bin_search_sorted_check_helper<TStrong> {
                    static const bool value = true;
                };

                template<bool TStrong, typename... TMessages>
                struct bin_search_sorted_check_helper<TStrong, std::tuple<TMessages...>> {
                    static const bool value = bin_search_sorted_check_helper<TStrong, TMessages...>::value;
                };

                template<typename TAllMessages>
                constexpr bool are_all_strong_sorted() {
                    return bin_search_sorted_check_helper<true, TAllMessages>::value;
                }

                template<typename TAllMessages>
                constexpr bool are_all_weak_sorted() {
                    return bin_search_sorted_check_helper<false, TAllMessages>::value;
                }

                template<typename TMsgBase, typename TAllMessages, typename... TOptions>
                class bin_search_base : public base<TMsgBase, TAllMessages, TOptions...> {
                    using base_impl_type = base<TMsgBase, TAllMessages, TOptions...>;

                public:
                    using all_messages_type = typename base_impl_type::all_messages_type;
                    using msg_ptr_type = typename base_impl_type::msg_ptr_type;
                    using msg_id_param_type = typename base_impl_type::msg_id_param_type;
                    using msg_id_type = typename base_impl_type::msg_id_type;

                    bin_search_base() {
                        init_registry();
                        check_sorted(sorted_check_tag_type());
                    }

                protected:
                    static_assert(nil::detail::is_tuple<all_messages_type>::value,
                                  "TAllMessages is expected to be a tuple.");

                    static const std::size_t messages_amount = std::tuple_size<all_messages_type>::value;

                    using factory_method_type = typename base_impl_type::factory_method;
                    using methods_registry_type = std::array<const factory_method_type *, messages_amount>;

                    methods_registry_type &registry() {
                        return registry_;
                    }

                    const methods_registry_type &registry() const {
                        return registry_;
                    }

                private:
                    struct compile_time_sorted { };
                    struct run_time_sorted { };

                    using sorted_check_tag_type = typename std::conditional<all_have_static_num_id<all_messages_type>(),
                                                                            compile_time_sorted,
                                                                            run_time_sorted>::type;

                    template<typename TMessage>
                    using num_id_factory_method_type =
                        typename base_impl_type::template num_id_factory_method<TMessage>;

                    template<typename TMessage>
                    using generic_factory_method_type =
                        typename base_impl_type::template generic_factory_method<TMessage>;

                    class creator {
                    public:
                        creator(methods_registry_type &registry) : registry_(registry) {
                        }

                        template<typename TMessage>
                        void operator()() {
                            using tag = typename std::conditional<TMessage::impl_options_type::has_static_msg_id,
                                                                  static_numeric_id_tag,
                                                                  other_id_tag>::type;

                            registry_[idx_] = create_factory<TMessage>(tag());
                            ++idx_;
                        }

                    private:
                        struct static_numeric_id_tag { };
                        struct other_id_tag { };

                        template<typename TMessage>
                        static const factory_method_type *create_factory(static_numeric_id_tag) {
                            static const num_id_factory_method_type<TMessage> Factory;
                            return &Factory;
                        }

                        template<typename TMessage>
                        const factory_method_type *create_factory(other_id_tag) {
                            static const generic_factory_method_type<TMessage> Factory;
                            return &Factory;
                        }

                        methods_registry_type &registry_;
                        unsigned idx_ = 0;
                    };

                    void init_registry() {
                        processing::tuple_for_each_type<all_messages_type>(creator(registry_));
                    }

                    void check_sorted(compile_time_sorted) {
                        static_assert(are_all_weak_sorted<all_messages_type>(),
                                      "The messages in all_messages_type tuple are expected to be sorted");
                    }

                    void check_sorted(run_time_sorted) {
                        MARSHALLING_ASSERT(std::is_sorted(
                            registry_.begin(),
                            registry_.end(),
                            [](const factory_method_type *methodPtr1, const factory_method_type *methodPtr2) -> bool {
                                MARSHALLING_ASSERT(methodPtr1 != nullptr);
                                MARSHALLING_ASSERT(methodPtr2 != nullptr);
                                return methodPtr1->get_id() < methodPtr2->get_id();
                            }));
                    }

                    methods_registry_type registry_;
                };

            }    // namespace msg_factory
        }        // namespace detail
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MSG_FACTORY_BIN_SEARCH_BASE_HPP
