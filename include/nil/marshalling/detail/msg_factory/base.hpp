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

#ifndef MARSHALLING_MSG_FACTORY_BASE_HPP
#define MARSHALLING_MSG_FACTORY_BASE_HPP

#include <type_traits>
#include <memory>

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/processing/tuple.hpp>
#include <nil/marshalling/processing/alloc.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {
            namespace msg_factory {
                struct static_num_id_check_helper {
                    template<typename TMessage>
                    constexpr bool operator()(bool value) const {
                        return value && TMessage::impl_options_type::has_static_msg_id;
                    }
                };

                template<typename TAllMessages>
                constexpr bool all_have_static_num_id() {
                    return nil::marshalling::processing::tuple_type_accumulate<TAllMessages>(
                        true, static_num_id_check_helper());
                }

                template<bool TMustCat>
                struct all_messages_retrieve_helper;

                template<>
                struct all_messages_retrieve_helper<true> {
                    template<typename TAll, typename TOpt>
                    using type = typename std::decay<decltype(std::tuple_cat(
                        std::declval<TAll>(),
                        std::declval<std::tuple<typename TOpt::generic_message>>()))>::type;
                };

                template<>
                struct all_messages_retrieve_helper<false> {
                    template<typename TAll, typename TOpt>
                    using type = TAll;
                };

                template<typename TAll, typename TOpt>
                using all_messages_bundle_type = typename all_messages_retrieve_helper<
                    TOpt::has_in_place_allocation && TOpt::has_support_generic_message>::template type<TAll, TOpt>;

                template<typename TMsgBase, typename TAllMessages, typename... TOptions>
                class base {
                    static_assert(
                        TMsgBase::interface_options_type::has_msg_id_type,
                        "Usage of base requires message interface to provide ID type. "
                        "Use nil::marshalling::option::msg_id_type option in message interface type definition.");
                    using parsed_options_internal_type = options_parser<TOptions...>;

                    using all_messages_internal_type
                        = all_messages_bundle_type<TAllMessages, parsed_options_internal_type>;
                    using allocator_type = typename std::conditional<
                        parsed_options_internal_type::has_in_place_allocation,
                        processing::alloc::in_place_single<TMsgBase, all_messages_internal_type>,
                        processing::alloc::dyn_memory<TMsgBase>>::type;

                public:
                    using parsed_options_type = parsed_options_internal_type;
                    using message_type = TMsgBase;
                    using msg_id_param_type = typename message_type::msg_id_param_type;
                    using msg_id_type = typename message_type::msg_id_type;
                    using msg_ptr_type = typename allocator_type::ptr_type;
                    using all_messages_type = TAllMessages;

                    msg_ptr_type create_generic_msg(msg_id_param_type id) const {
                        static_cast<void>(this);
                        using tag = typename std::conditional<parsed_options_type::has_support_generic_message,
                                                              AllocGenericTag,
                                                              NoAllocTag>::type;

                        return create_generic_msg_internal(id, tag());
                    }

                protected:
                    base() = default;

                    base(const base &) = default;

                    base(base &&) = default;

                    base &operator=(const base &) = default;

                    base &operator=(base &&) = default;

                    class factory_method {
                    public:
                        msg_id_param_type get_id() const {
                            return get_id_impl();
                        }

                        msg_ptr_type create(const base &factory) const {
                            return create_impl(factory);
                        }

                    protected:
                        factory_method() = default;

                        virtual msg_id_param_type get_id_impl() const = 0;

                        virtual msg_ptr_type create_impl(const base &factory) const = 0;
                    };

                    template<typename TMessage>
                    class num_id_factory_method : public factory_method {
                    public:
                        using message_type = TMessage;
                        static const decltype(message_type::msg_id) msg_id = message_type::msg_id;

                        num_id_factory_method() {
                        }

                    protected:
                        virtual msg_id_param_type get_id_impl() const {
                            return static_cast<msg_id_param_type>(msg_id);
                        }

                        virtual msg_ptr_type create_impl(const base &factory) const {
                            return factory.template alloc_msg<message_type>();
                        }
                    };

                    template<typename TMessage>
                    friend class num_id_factory_method;

                    template<typename TMessage>
                    class generic_factory_method : public factory_method {
                    public:
                        using message_type = TMessage;

                        generic_factory_method() : id_(message_type().get_id()) {
                        }

                    protected:
                        virtual msg_id_param_type get_id_impl() const {
                            return id_;
                        }

                        virtual msg_ptr_type create_impl(const base &factory) const {
                            return factory.template alloc_msg<message_type>();
                        }

                    private:
                        typename message_type::msg_id_type id_;
                    };

                    template<typename TMessage>
                    friend class generic_factory_method;

                    template<typename TObj, typename... TArgs>
                    msg_ptr_type alloc_msg(TArgs &&...args) const {
                        static_assert(std::is_base_of<message_type, TObj>::value, "TObj is not a proper message type");

                        static_assert(
                            (!parsed_options_internal_type::has_in_place_allocation)
                                || nil::detail::is_in_tuple<TObj, all_messages_internal_type>::value,
                            "TObj must be in provided tuple of supported messages");

                        return alloc_.template alloc<TObj>(std::forward<TArgs>(args)...);
                    }

                private:
                    struct AllocGenericTag { };
                    struct NoAllocTag { };

                    msg_ptr_type create_generic_msg_internal(msg_id_param_type id, AllocGenericTag) const {
                        static_assert(
                            std::is_base_of<message_type, typename parsed_options_type::generic_message>::value,
                            "The requested generic_message class must have the same interface class as all other "
                            "messages");
                        return alloc_msg<typename parsed_options_type::generic_message>(id);
                    }

                    static msg_ptr_type create_generic_msg_internal(msg_id_param_type, NoAllocTag) {
                        return msg_ptr_type();
                    }

                    mutable allocator_type alloc_;
                };

            }    // namespace msg_factory
        }        // namespace detail
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MSG_FACTORY_BASE_HPP
