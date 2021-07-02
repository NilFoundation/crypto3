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

#ifndef MARSHALLING_MESSAGE_INTERFACE_BUILDER_HPP
#define MARSHALLING_MESSAGE_INTERFACE_BUILDER_HPP

#include <type_traits>
#include <cstddef>

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/processing/access.hpp>
#include <nil/marshalling/processing/tuple.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/detail/message/interface_options_parser.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {
            namespace message {

                template<class T, class R = void>
                struct interface_if_has_ret_type {
                    using type = R;
                };

                template<class T, class Enable = void>
                struct interface_dispatch_ret_type_helper {
                    using type = void;
                };

                template<class T>
                struct interface_dispatch_ret_type_helper<
                    T,
                    typename interface_if_has_ret_type<typename T::RetType>::type> {
                    using type = typename T::RetType;
                };

                template<class T>
                using interface_dispatch_ret_type = typename interface_dispatch_ret_type_helper<T>::type;

                class interface_empty_base { };

                //----------------------------------------------------

                template<typename TEndian>
                class interface_endian_base {
                public:
                    using endian_type = TEndian;

                    using field_type = nil::marshalling::field_type<nil::marshalling::option::endian<endian_type>>;

                protected:
                    ~interface_endian_base() noexcept = default;

                    template<typename T, typename TIter>
                    static void write_data(T value, TIter &iter) {
                        write_data<sizeof(T), T>(value, iter);
                    }

                    template<std::size_t TSize, typename T, typename TIter>
                    static void write_data(T value, TIter &iter) {
                        static_assert(TSize <= sizeof(T), "Cannot put more bytes than type contains");
                        return processing::write_data<TSize, T>(value, iter, endian_type());
                    }

                    template<typename T, typename TIter>
                    static T read_data(TIter &iter) {
                        return read_data<T, sizeof(T)>(iter);
                    }

                    template<typename T, std::size_t TSize, typename TIter>
                    static T read_data(TIter &iter) {
                        static_assert(TSize <= sizeof(T), "Cannot get more bytes than type contains");
                        return processing::read_data<T, TSize>(iter, endian_type());
                    }
                };

                template<bool THasEndian>
                struct interface_process_endian_base;

                template<>
                struct interface_process_endian_base<true> {
                    template<typename TOpt>
                    using type = interface_endian_base<typename TOpt::endian_type>;
                };

                template<>
                struct interface_process_endian_base<false> {
                    template<typename TOpt>
                    using type = interface_empty_base;
                };

                template<typename TOpt>
                using interface_endian_base_type =
                    typename interface_process_endian_base<TOpt::has_endian>::template type<TOpt>;

                //----------------------------------------------------

                template<typename TBase, typename TId>
                class interface_id_type_base : public TBase {
                public:
                    using msg_id_type = TId;
                    using msg_id_param_type = typename std::conditional<std::is_integral<msg_id_type>::value
                                                                            || std::is_enum<msg_id_type>::value,
                                                                        msg_id_type,
                                                                        const msg_id_type &>::type;

                protected:
                    ~interface_id_type_base() noexcept = default;
                };

                template<bool THasIdType>
                struct interface_process_id_type_base;

                template<>
                struct interface_process_id_type_base<true> {
                    template<typename TBase, typename TOpt>
                    using type = interface_id_type_base<TBase, typename TOpt::msg_id_type>;
                };

                template<>
                struct interface_process_id_type_base<false> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TOpt>
                using interface_id_type_base_type =
                    typename interface_process_id_type_base<TOpt::has_msg_id_type>::template type<TBase, TOpt>;

                //----------------------------------------------------

                template<typename TBase, typename TFields>
                class interface_extra_transport_fields_base : public TBase {
                public:
                    using transport_fields_type = TFields;

                    static_assert(nil::detail::is_tuple<transport_fields_type>::value,
                                  "transport_fields_type is expected to be tuple");

                    transport_fields_type &transport_fields() {
                        return transportFields_;
                    }

                    const transport_fields_type &transport_fields() const {
                        return transportFields_;
                    }

                protected:
                    ~interface_extra_transport_fields_base() noexcept = default;

                private:
                    transport_fields_type transportFields_;
                };

                template<bool THasExtraTransportFields>
                struct interface_process_extra_transport_fields_base;

                template<>
                struct interface_process_extra_transport_fields_base<true> {
                    template<typename TBase, typename TOpt>
                    using type
                        = interface_extra_transport_fields_base<TBase, typename TOpt::extra_transport_fields_type>;
                };

                template<>
                struct interface_process_extra_transport_fields_base<false> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TOpt>
                using interface_extra_transport_fields_base_type =
                    typename interface_process_extra_transport_fields_base<
                        TOpt::has_extra_transport_fields>::template type<TBase, TOpt>;

                //----------------------------------------------------

                template<typename TBase, std::size_t TIdx>
                class interface_version_in_extra_transport_fields_base : public TBase {
                public:
                    using transport_fields_type = typename TBase::transport_fields_type;

                    static_assert(nil::detail::is_tuple<transport_fields_type>::value,
                                  "transport_fields_type is expected to be tuple");

                    static_assert(
                        TIdx < std::tuple_size<transport_fields_type>::value,
                        "Index provided to nil::marshalling::option::version_in_extra_transport_fields exceeds "
                        "size of the tuple");

                    using version_type = typename std::tuple_element<TIdx, transport_fields_type>::type::value_type;

                    version_type &version() {
                        return std::get<TIdx>(TBase::transport_fields()).value();
                    }

                    const version_type &version() const {
                        return std::get<TIdx>(TBase::transport_fields()).value();
                    }

                protected:
                    ~interface_version_in_extra_transport_fields_base() noexcept = default;
                };

                template<bool THasVersionInExtraTransportFields>
                struct interface_process_version_in_extra_transport_fields_base;

                template<>
                struct interface_process_version_in_extra_transport_fields_base<true> {
                    template<typename TBase, typename TOpt>
                    using type
                        = interface_version_in_extra_transport_fields_base<TBase,
                                                                           TOpt::version_in_extra_transport_fields>;
                };

                template<>
                struct interface_process_version_in_extra_transport_fields_base<false> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TOpt>
                using interface_version_in_extra_transport_fields_base_type =
                    typename interface_process_version_in_extra_transport_fields_base<
                        TOpt::has_version_in_extra_transport_fields>::template type<TBase, TOpt>;

                //----------------------------------------------------

                template<typename TBase>
                class interface_id_info_base : public TBase {
                public:
                    using msg_id_param_type = typename TBase::msg_id_param_type;

                    msg_id_param_type get_id() const {
                        return get_id_impl();
                    }

                protected:
                    ~interface_id_info_base() noexcept = default;

                    virtual msg_id_param_type get_id_impl() const = 0;
                };

                template<bool THasIdInfo>
                struct interface_process_id_info_base;

                template<>
                struct interface_process_id_info_base<true> {
                    template<typename TBase>
                    using type = interface_id_info_base<TBase>;
                };

                template<>
                struct interface_process_id_info_base<false> {
                    template<typename TBase>
                    using type = TBase;
                };

                template<typename TBase, typename TOpt>
                using interface_id_info_base_type =
                    typename interface_process_id_info_base<TOpt::has_msg_id_type
                                                            && TOpt::has_msg_id_info>::template type<TBase>;

                //----------------------------------------------------

                template<typename TBase, typename TReadIter>
                class interface_read_only_base : public TBase {
                public:
                    using read_iterator = TReadIter;

                    nil::marshalling::status_type read(read_iterator &iter, std::size_t size) {
                        return this->read_impl(iter, size);
                    }

                    template<typename TIter>
                    static nil::marshalling::status_type eval_read(TIter &iter, std::size_t size) {
                        static_cast<void>(iter);
                        static_cast<void>(size);
                        return nil::marshalling::status_type::not_supported;
                    }

                protected:
                    ~interface_read_only_base() noexcept = default;

                    virtual nil::marshalling::status_type read_impl(read_iterator &iter, std::size_t size) {
                        return eval_read(iter, size);
                    }
                };

                template<typename TBase, typename TWriteIter>
                class interface_write_only_base : public TBase {
                public:
                    using write_iterator = TWriteIter;

                    nil::marshalling::status_type write(write_iterator &iter, std::size_t size) const {
                        return this->write_impl(iter, size);
                    }

                    template<typename TIter>
                    static nil::marshalling::status_type eval_write(TIter &iter, std::size_t size) {
                        static_cast<void>(iter);
                        static_cast<void>(size);
                        return nil::marshalling::status_type::not_supported;
                    }

                protected:
                    ~interface_write_only_base() noexcept = default;

                    virtual nil::marshalling::status_type write_impl(write_iterator &iter, std::size_t size) const {
                        return eval_write(iter, size);
                    }
                };

                template<typename TBase, typename TReadIter, typename TWriteIter>
                class interface_read_write_base : public TBase {
                public:
                    using read_iterator = TReadIter;

                    nil::marshalling::status_type read(read_iterator &iter, std::size_t size) {
                        return this->read_impl(iter, size);
                    }

                    using write_iterator = TWriteIter;

                    nil::marshalling::status_type write(write_iterator &iter, std::size_t size) const {
                        return this->write_impl(iter, size);
                    }

                protected:
                    ~interface_read_write_base() noexcept = default;

                    virtual nil::marshalling::status_type read_impl(read_iterator &iter, std::size_t size) {
                        static_cast<void>(iter);
                        static_cast<void>(size);
                        return nil::marshalling::status_type::not_supported;
                    }

                    virtual nil::marshalling::status_type write_impl(write_iterator &iter, std::size_t size) const {
                        static_cast<void>(iter);
                        static_cast<void>(size);
                        return nil::marshalling::status_type::not_supported;
                    }
                };

                template<bool THasReadIterator, bool THasWriteIterator>
                struct interface_process_read_write_base;

                template<>
                struct interface_process_read_write_base<false, false> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<>
                struct interface_process_read_write_base<false, true> {
                    template<typename TBase, typename TOpt>
                    using type = interface_write_only_base<TBase, typename TOpt::write_iterator>;
                };

                template<>
                struct interface_process_read_write_base<true, false> {
                    template<typename TBase, typename TOpt>
                    using type = interface_read_only_base<TBase, typename TOpt::read_iterator>;
                };

                template<>
                struct interface_process_read_write_base<true, true> {
                    template<typename TBase, typename TOpt>
                    using type
                        = interface_read_write_base<TBase, typename TOpt::read_iterator, typename TOpt::write_iterator>;
                };

                template<typename TBase, typename TOpt>
                using interface_read_write_base_type =
                    typename interface_process_read_write_base<TOpt::has_read_iterator,
                                                               TOpt::has_write_iterator>::template type<TBase, TOpt>;

                //----------------------------------------------------

                template<typename TBase, typename THandler>
                class interface_handler_base : public TBase {
                public:
                    using handler_type = THandler;
                    using DispatchRetType = interface_dispatch_ret_type<handler_type>;

                    DispatchRetType dispatch(handler_type &handler) {
                        return dispatch_impl(handler);
                    }

                protected:
                    ~interface_handler_base() noexcept = default;

                    virtual DispatchRetType dispatch_impl(handler_type &handler) = 0;
                };

                template<bool THasHandler>
                struct interface_process_handler_base;

                template<>
                struct interface_process_handler_base<true> {
                    template<typename TBase, typename TOpt>
                    using type = interface_handler_base<TBase, typename TOpt::handler_type>;
                };

                template<>
                struct interface_process_handler_base<false> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TOpt>
                using interface_handler_base_type =
                    typename interface_process_handler_base<TOpt::has_handler>::template type<TBase, TOpt>;

                //----------------------------------------------------

                template<typename TBase>
                class interface_valid_base : public TBase {
                public:
                    bool valid() const {
                        return valid_impl();
                    }

                    static constexpr bool eval_valid() {
                        return true;
                    }

                protected:
                    ~interface_valid_base() noexcept = default;

                    virtual bool valid_impl() const {
                        return eval_valid();
                    }
                };

                template<bool THasValid>
                struct interface_process_valid_base;

                template<>
                struct interface_process_valid_base<true> {
                    template<typename TBase>
                    using type = interface_valid_base<TBase>;
                };

                template<>
                struct interface_process_valid_base<false> {
                    template<typename TBase>
                    using type = TBase;
                };

                template<typename TBase, typename TOpts>
                using interface_valid_base_type =
                    typename interface_process_valid_base<TOpts::has_valid>::template type<TBase>;

                //----------------------------------------------------

                template<typename TBase>
                class interface_length_base : public TBase {
                public:
                    std::size_t length() const {
                        return length_impl();
                    }

                    static std::size_t eval_length() {
                        MARSHALLING_ASSERT(!"Not overridden");
                        return 0;
                    }

                protected:
                    ~interface_length_base() noexcept = default;

                    virtual std::size_t length_impl() const {
                        return eval_length();
                    }
                };

                template<bool THasLength>
                struct interface_process_length_base;

                template<>
                struct interface_process_length_base<true> {
                    template<typename TBase>
                    using type = interface_length_base<TBase>;
                };

                template<>
                struct interface_process_length_base<false> {
                    template<typename TBase>
                    using type = TBase;
                };

                template<typename TBase, typename TOpts>
                using interface_length_base_type =
                    typename interface_process_length_base<TOpts::has_length>::template type<TBase>;

                //----------------------------------------------------

                template<typename TBase>
                class interface_refresh_base : public TBase {
                public:
                    bool refresh() {
                        return refresh_impl();
                    }

                protected:
                    ~interface_refresh_base() noexcept = default;

                    virtual bool refresh_impl() {
                        return false;
                    }
                };

                template<bool THasRefresh>
                struct interface_process_refresh_base;

                template<>
                struct interface_process_refresh_base<true> {
                    template<typename TBase>
                    using type = interface_refresh_base<TBase>;
                };

                template<>
                struct interface_process_refresh_base<false> {
                    template<typename TBase>
                    using type = TBase;
                };

                template<typename TBase, typename TOpts>
                using interface_refresh_base_type =
                    typename interface_process_refresh_base<TOpts::has_refresh>::template type<TBase>;

                //----------------------------------------------------

                template<typename TBase>
                class interface_name_base : public TBase {
                public:
                    const char *name() const {
                        return name_impl();
                    }

                protected:
                    ~interface_name_base() noexcept = default;

                    virtual const char *name_impl() const = 0;
                };

                template<bool THasName>
                struct interface_process_name_base;

                template<>
                struct interface_process_name_base<true> {
                    template<typename TBase>
                    using type = interface_name_base<TBase>;
                };

                template<>
                struct interface_process_name_base<false> {
                    template<typename TBase>
                    using type = TBase;
                };

                template<typename TBase, typename TOpts>
                using interface_name_base_type =
                    typename interface_process_name_base<TOpts::has_name>::template type<TBase>;

                //----------------------------------------------------

                template<typename TOpts>
                constexpr bool interface_has_virtual_functions() {
                    return TOpts::has_read_iterator || TOpts::has_write_iterator || TOpts::has_msg_id_info
                           || TOpts::has_handler || TOpts::has_valid || TOpts::has_length || TOpts::has_refresh
                           || TOpts::has_name;
                }

                template<typename TBase>
                class interface_virt_destructor_base : public TBase {
                protected:
                    virtual ~interface_virt_destructor_base() noexcept = default;
                };

                template<bool THasVirtDestructor>
                struct interface_process_virt_destructor_base;

                template<>
                struct interface_process_virt_destructor_base<true> {
                    template<typename TBase>
                    using type = interface_virt_destructor_base<TBase>;
                };

                template<>
                struct interface_process_virt_destructor_base<false> {
                    template<typename TBase>
                    using type = TBase;
                };

                template<typename TBase, typename TOpts>
                using interface_virt_destructor_base_type = typename interface_process_virt_destructor_base<
                    (!TOpts::has_no_virtual_destructor)
                    && interface_has_virtual_functions<TOpts>()>::template type<TBase>;

                //----------------------------------------------------

                template<typename... TOptions>
                class interface_builder {
                    using parsed_options_type = interface_options_parser<TOptions...>;

                    static_assert(
                        (!parsed_options_type::has_version_in_extra_transport_fields)
                            || parsed_options_type::has_extra_transport_fields,
                        "nil::marshalling::option::version_in_extra_transport_fields option should not be used "
                        "without nil::marshalling::option::extra_transport_fields.");

                    using endian_base_type = interface_endian_base_type<parsed_options_type>;
                    using id_type_base_type = interface_id_type_base_type<endian_base_type, parsed_options_type>;
                    using transport_fields_base_type
                        = interface_extra_transport_fields_base_type<id_type_base_type, parsed_options_type>;
                    using version_in_transport_fields_base_type
                        = interface_version_in_extra_transport_fields_base_type<transport_fields_base_type,
                                                                                parsed_options_type>;
                    using id_info_base_type
                        = interface_id_info_base_type<version_in_transport_fields_base_type, parsed_options_type>;
                    using read_write_base_type = interface_read_write_base_type<id_info_base_type, parsed_options_type>;
                    using valid_base_type = interface_valid_base_type<read_write_base_type, parsed_options_type>;
                    using length_base_type = interface_length_base_type<valid_base_type, parsed_options_type>;
                    using handler_base_type = interface_handler_base_type<length_base_type, parsed_options_type>;
                    using refresh_base_type = interface_refresh_base_type<handler_base_type, parsed_options_type>;
                    using name_base_type = interface_name_base_type<refresh_base_type, parsed_options_type>;
                    using virt_destructor_base_type
                        = interface_virt_destructor_base_type<name_base_type, parsed_options_type>;

                public:
                    using options_type = parsed_options_type;
                    using type = virt_destructor_base_type;
                };

                template<typename... TOptions>
                using interface_builder_type = typename interface_builder<TOptions...>::type;

            }    // namespace message
        }        // namespace detail
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MESSAGE_INTERFACE_BUILDER_HPP
