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

#ifndef MARSHALLING_MESSAGE_IMPL_BUILDER_HPP
#define MARSHALLING_MESSAGE_IMPL_BUILDER_HPP

#include <type_traits>
#include <cstddef>
#include <tuple>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/processing/access.hpp>
#include <nil/marshalling/processing/tuple.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/detail/message/implementation_options_parser.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {
            namespace message {

                template<typename TBase, std::intmax_t TId>
                class impl_static_num_id_base : public TBase {
                public:
                    constexpr static const typename TBase::msg_id_type msg_id
                        = static_cast<typename TBase::msg_id_type>(TId);

                    static constexpr typename TBase::msg_id_param_type eval_get_id() {
                        return msg_id;
                    }

                protected:
                    ~impl_static_num_id_base() noexcept = default;
                };

                template<bool THasStaticMsgId>
                struct impl_process_static_num_id_base;

                template<>
                struct impl_process_static_num_id_base<true> {
                    template<typename TBase, typename TOpt>
                    using type = impl_static_num_id_base<TBase, TOpt::msg_id>;
                };

                template<>
                struct impl_process_static_num_id_base<false> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TOpt>
                using impl_static_num_id_base_type =
                    typename impl_process_static_num_id_base<TBase::interface_options_type::has_msg_id_type
                                                             && TOpt::has_static_msg_id>::template type<TBase, TOpt>;

                template<typename TBase, typename TOpt>
                class impl_polymorhpic_static_num_id_base : public TBase {
                protected:
                    ~impl_polymorhpic_static_num_id_base() noexcept = default;

                    virtual typename TBase::msg_id_param_type get_id_impl() const override {
                        using tag = typename std::conditional<TOpt::has_msg_type, downcast_tag, no_downcast_tag>::type;
                        return get_id_internal(tag());
                    }

                private:
                    struct downcast_tag { };
                    struct no_downcast_tag { };

                    typename TBase::msg_id_param_type get_id_internal(no_downcast_tag) const {
                        return TBase::eval_get_id();
                    }

                    typename TBase::msg_id_param_type get_id_internal(downcast_tag) const {
                        using Derived = typename TOpt::msg_type;
                        return static_cast<const Derived *>(this)->eval_get_id();
                    }
                };

                template<bool THasStaticMsgId>
                struct impl_process_polymorhpic_static_num_id_base;

                template<>
                struct impl_process_polymorhpic_static_num_id_base<true> {
                    template<typename TBase, typename TOpt>
                    using type = impl_polymorhpic_static_num_id_base<TBase, TOpt>;
                };

                template<>
                struct impl_process_polymorhpic_static_num_id_base<false> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TOpt>
                using impl_polymorhpic_static_num_id_base_type = typename impl_process_polymorhpic_static_num_id_base<
                    TBase::interface_options_type::has_msg_id_type && TBase::interface_options_type::has_msg_id_info
                    && (TOpt::has_static_msg_id || (TOpt::has_msg_type && TOpt::has_do_get_id))>::template type<TBase,
                                                                                                                TOpt>;

                //----------------------------------------------------

                template<typename TBase>
                class impl_no_id_base : public TBase {
                protected:
                    ~impl_no_id_base() noexcept = default;

                    virtual typename TBase::msg_id_param_type get_id_impl() const override {
                        static const typename TBase::msg_id_type msg_id = typename TBase::msg_id_type();
                        MARSHALLING_ASSERT(!"The message id is not supposed to be retrieved");
                        return msg_id;
                    }
                };

                template<bool THasNoId>
                struct impl_process_no_id_base;

                template<>
                struct impl_process_no_id_base<true> {
                    template<typename TBase>
                    using type = impl_no_id_base<TBase>;
                };

                template<>
                struct impl_process_no_id_base<false> {
                    template<typename TBase>
                    using type = TBase;
                };

                template<typename TBase, typename TOpt>
                using impl_no_id_base_type =
                    typename impl_process_no_id_base<TBase::interface_options_type::has_msg_id_type
                                                     && TBase::interface_options_type::has_msg_id_info
                                                     && TOpt::has_no_id_impl>::template type<TBase>;

                //----------------------------------------------------

                template<typename TAllFields>
                class impl_fields_container {
                public:
                    using all_fields_type = TAllFields;

                    all_fields_type &fields() {
                        return fields_;
                    }

                    const all_fields_type &fields() const {
                        return fields_;
                    }

                    constexpr static bool are_fields_version_dependent() {
                        return nil::marshalling::processing::tuple_type_is_any_of<all_fields_type>(
                            version_dep_checker());
                    }

                    template<typename TIter>
                    nil::marshalling::status_type eval_read(TIter &iter, std::size_t size) {
#ifdef _MSC_VER
                        // For some reason VS2015 32 bit compiler may generate "integral constant overflow"
                        // warning on the code below
#pragma warning(push)
#pragma warning(disable : 4307)
#endif

                        using tag_type =
                            typename std::conditional<nil::marshalling::processing::tuple_type_accumulate<
                                                          all_fields_type>(true, read_no_status_detector()),
                                                      no_status_tag, use_status_tag>::type;

#ifdef _MSC_VER
#pragma warning(pop)
#endif
                        return eval_read_internal(iter, size, tag_type());
                    }

                    template<typename TIter>
                    nil::marshalling::status_type eval_write(TIter &iter, std::size_t size) const {
                        if (size < eval_length()) {
                            return nil::marshalling::status_type::buffer_overflow;
                        }

                        eval_write_fields_no_status_from<0>(iter);
                        return nil::marshalling::status_type::success;
                    }

                    bool eval_valid() const {
                        return processing::tuple_accumulate(fields(), true, field_validity_retriever());
                    }

                    std::size_t eval_length() const {
                        return processing::tuple_accumulate(fields(), 0U, field_length_retriever());
                    }

                    template<std::size_t TFromIdx>
                    std::size_t eval_length_from() const {
                        return processing::tuple_accumulate_from_until<TFromIdx,
                                                                       std::tuple_size<all_fields_type>::value>(
                            fields(), 0U, field_length_retriever());
                    }

                    template<std::size_t TUntilIdx>
                    std::size_t eval_length_until() const {
                        return processing::tuple_accumulate_from_until<0, TUntilIdx>(fields(), 0U,
                                                                                     field_length_retriever());
                    }

                    template<std::size_t TFromIdx, std::size_t TUntilIdx>
                    std::size_t eval_length_from_until() const {
                        return processing::tuple_accumulate_from_until<TFromIdx, TUntilIdx>(fields(), 0U,
                                                                                            field_length_retriever());
                    }

                    static constexpr std::size_t eval_min_length() {
                        return processing::tuple_type_accumulate<all_fields_type>(0U, field_min_length_retriever());
                    }

                    template<std::size_t TFromIdx>
                    static constexpr std::size_t eval_min_length_from() {
                        return processing::tuple_type_accumulate_from_until<
                            TFromIdx, std::tuple_size<all_fields_type>::value, all_fields_type>(
                            0U, field_min_length_retriever());
                    }

                    template<std::size_t TUntilIdx>
                    static constexpr std::size_t eval_min_length_until() {
                        return processing::tuple_type_accumulate_from_until<0, TUntilIdx, all_fields_type>(
                            0U, field_min_length_retriever());
                    }

                    template<std::size_t TFromIdx, std::size_t TUntilIdx>
                    static constexpr std::size_t eval_min_length_from_until() {
                        return processing::tuple_type_accumulate_from_until<TFromIdx, TUntilIdx, all_fields_type>(
                            0U, field_min_length_retriever());
                    }

                    static constexpr std::size_t eval_max_length() {
                        return processing::tuple_type_accumulate<all_fields_type>(0U, field_max_length_retriever());
                    }

                    template<std::size_t TFromIdx>
                    static constexpr std::size_t eval_max_length_from() {
                        return processing::tuple_type_accumulate_from_until<
                            TFromIdx, std::tuple_size<all_fields_type>::value, all_fields_type>(
                            0U, field_max_length_retriever());
                    }

                    template<std::size_t TUntilIdx>
                    static constexpr std::size_t eval_max_length_until() {
                        return processing::tuple_type_accumulate_from_until<0, TUntilIdx, all_fields_type>(
                            0U, field_max_length_retriever());
                    }

                    template<std::size_t TFromIdx, std::size_t TUntilIdx>
                    static constexpr std::size_t eval_max_length_from_until() {
                        return processing::tuple_type_accumulate_from_until<TFromIdx, TUntilIdx, all_fields_type>(
                            0U, field_max_length_retriever());
                    }

                    bool eval_refresh() {
                        return processing::tuple_accumulate(fields(), false, field_refresher());
                    }

                protected:
                    ~impl_fields_container() noexcept = default;

                    template<std::size_t TIdx, typename TIter>
                    nil::marshalling::status_type eval_read_fields_until(TIter &iter, std::size_t &size) {
                        auto status = nil::marshalling::status_type::success;
                        processing::tuple_for_each_until<TIdx>(fields(), makeFieldReader(iter, status, size));
                        return status;
                    }

                    template<std::size_t TIdx, typename TIter>
                    nil::marshalling::status_type read_fields_until(TIter &iter, std::size_t &size) {
                        return eval_read_fields_until<TIdx, TIter>(iter, size);
                    }

                    template<std::size_t TIdx, typename TIter>
                    void eval_read_fields_no_status_until(TIter &iter) {
                        processing::tuple_for_each_until<TIdx>(fields(), makeFieldNoStatusReader(iter));
                    }

                    template<std::size_t TIdx, typename TIter>
                    void read_fields_no_status_until(TIter &iter) {
                        eval_read_fields_no_status_until<TIdx, TIter>(iter);
                    }

                    template<std::size_t TIdx, typename TIter>
                    nil::marshalling::status_type eval_read_fields_from(TIter &iter, std::size_t &size) {
                        auto status = nil::marshalling::status_type::success;
                        processing::tuple_for_each_from<TIdx>(fields(), makeFieldReader(iter, status, size));
                        return status;
                    }

                    template<std::size_t TIdx, typename TIter>
                    nil::marshalling::status_type read_fields_from(TIter &iter, std::size_t &size) {
                        return eval_read_fields_from<TIdx, TIter>(iter, size);
                    }

                    template<std::size_t TIdx, typename TIter>
                    void eval_read_fields_no_status_from(TIter &iter) {
                        processing::tuple_for_each_from<TIdx>(fields(), makeFieldNoStatusReader(iter));
                    }

                    template<std::size_t TIdx, typename TIter>
                    void read_fields_no_status_from(TIter &iter) {
                        eval_read_fields_no_status_from<TIdx, TIter>(iter);
                    }

                    template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
                    nil::marshalling::status_type eval_read_fields_from_until(TIter &iter, std::size_t &size) {
                        auto status = nil::marshalling::status_type::success;
                        processing::tuple_for_each_from_until<TFromIdx, TUntilIdx>(fields(),
                                                                                   makeFieldReader(iter, status, size));
                        return status;
                    }

                    template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
                    nil::marshalling::status_type read_fields_from_until(TIter &iter, std::size_t &size) {
                        return eval_read_fields_from_until<TFromIdx, TUntilIdx, TIter>(iter, size);
                    }

                    template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
                    void eval_read_fields_no_status_from_until(TIter &iter) {
                        processing::tuple_for_each_from_until<TFromIdx, TUntilIdx>(fields(),
                                                                                   makeFieldNoStatusReader(iter));
                    }

                    template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
                    void read_fields_no_status_from_until(TIter &iter) {
                        eval_read_fields_no_status_from_until<TFromIdx, TUntilIdx, TIter>(iter);
                    }

                    template<std::size_t TIdx, typename TIter>
                    nil::marshalling::status_type eval_write_fields_until(TIter &iter, std::size_t size) const {
                        auto status = nil::marshalling::status_type::success;
                        std::size_t remainingSize = size;
                        processing::tuple_for_each_until<TIdx>(fields(), makeFieldWriter(iter, status, remainingSize));
                        return status;
                    }

                    template<std::size_t TIdx, typename TIter>
                    nil::marshalling::status_type write_fields_until(TIter &iter, std::size_t size) const {
                        return eval_write_fields_until<TIdx, TIter>(iter, size);
                    }

                    template<std::size_t TIdx, typename TIter>
                    void eval_write_fields_no_status_until(TIter &iter) const {
                        processing::tuple_for_each_until<TIdx>(fields(), makeFieldNoStatusWriter(iter));
                    }

                    template<std::size_t TIdx, typename TIter>
                    void write_fields_no_status_until(TIter &iter) const {
                        eval_write_fields_no_status_until<TIdx, TIter>(iter);
                    }

                    template<std::size_t TIdx, typename TIter>
                    nil::marshalling::status_type eval_write_fields_from(TIter &iter, std::size_t size) const {
                        auto status = nil::marshalling::status_type::success;
                        std::size_t remainingSize = size;
                        processing::tuple_for_each_from<TIdx>(fields(), makeFieldWriter(iter, status, remainingSize));
                        return status;
                    }

                    template<std::size_t TIdx, typename TIter>
                    nil::marshalling::status_type write_fields_from(TIter &iter, std::size_t size) const {
                        return eval_write_fields_from<TIdx, TIter>(iter, size);
                    }

                    template<std::size_t TIdx, typename TIter>
                    void eval_write_fields_no_status_from(TIter &iter) const {
                        processing::tuple_for_each_from<TIdx>(fields(), makeFieldNoStatusWriter(iter));
                    }

                    template<std::size_t TIdx, typename TIter>
                    void write_fields_no_status_from(TIter &iter) const {
                        eval_write_fields_no_status_from<TIdx, TIter>(iter);
                    }

                    template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
                    nil::marshalling::status_type eval_write_fields_from_until(TIter &iter, std::size_t size) const {
                        auto status = nil::marshalling::status_type::success;
                        std::size_t remainingSize = size;
                        processing::tuple_for_each_from_until<TFromIdx, TUntilIdx>(
                            fields(), makeFieldWriter(iter, status, remainingSize));
                        return status;
                    }

                    template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
                    nil::marshalling::status_type write_fields_from_until(TIter &iter, std::size_t size) const {
                        return eval_write_fields_from_until<TFromIdx, TUntilIdx, TIter>(iter, size);
                    }

                    template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
                    void eval_write_fields_no_status_from_until(TIter &iter) const {
                        processing::tuple_for_each_from_until<TFromIdx, TUntilIdx>(fields(),
                                                                                   makeFieldNoStatusWriter(iter));
                    }

                    template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
                    void write_fields_no_status_from_until(TIter &iter) const {
                        eval_write_fields_no_status_from_until<TFromIdx, TUntilIdx, TIter>(iter);
                    }

                private:
                    struct no_status_tag { };
                    struct use_status_tag { };

                    struct read_no_status_detector {
                        constexpr read_no_status_detector() = default;

                        template<typename TField>
                        constexpr bool operator()(bool soFar) const {
                            return (TField::min_length() == TField::max_length())
                                   && (!TField::parsed_options_type::has_custom_value_reader)
                                   && (!TField::parsed_options_type::has_custom_read)
                                   && (!TField::parsed_options_type::has_fail_on_invalid)
                                   && (!TField::parsed_options_type::has_sequence_elem_length_forcing)
                                   && (!TField::parsed_options_type::has_sequence_size_forcing)
                                   && (!TField::parsed_options_type::has_sequence_size_field_prefix)
                                   && (!TField::parsed_options_type::has_sequence_ser_length_field_prefix)
                                   && (!TField::parsed_options_type::has_sequence_elem_ser_length_field_prefix)
                                   && (!TField::parsed_options_type::has_sequence_elem_fixed_ser_length_field_prefix)
                                   && (!TField::parsed_options_type::has_sequence_trailing_field_suffix)
                                   && (!TField::parsed_options_type::has_sequence_termination_field_suffix) && soFar;
                            ;
                        }
                    };

                    template<typename TIter>
                    nil::marshalling::status_type eval_read_internal(TIter &iter, std::size_t size, use_status_tag) {
                        return eval_read_fields_from<0>(iter, size);
                    }

                    template<typename TIter>
                    nil::marshalling::status_type eval_read_internal(TIter &iter, std::size_t size, no_status_tag) {
                        if (size < eval_length()) {
                            return nil::marshalling::status_type::not_enough_data;
                        }

                        eval_read_fields_no_status_from<0>(iter);
                        return nil::marshalling::status_type::success;
                    }

                    template<typename TIter>
                    class field_reader {
                    public:
                        field_reader(TIter &iter, nil::marshalling::status_type &status, std::size_t &size) :
                            iter_(iter), status_(status), size_(size) {
                        }

                        template<typename TField>
                        void operator()(TField &field) {
                            if (status_ == nil::marshalling::status_type::success) {
                                status_ = field.read(iter_, size_);
                                if (status_ == nil::marshalling::status_type::success) {
                                    MARSHALLING_ASSERT(field.length() <= size_);
                                    size_ -= field.length();
                                }
                            }
                        }

                    private:
                        TIter &iter_;
                        nil::marshalling::status_type &status_;
                        std::size_t &size_;
                    };

                    template<typename TIter>
                    static field_reader<TIter> makeFieldReader(TIter &iter, nil::marshalling::status_type &status,
                                                               std::size_t &size) {
                        return field_reader<TIter>(iter, status, size);
                    }

                    template<typename TIter>
                    class field_no_status_reader {
                    public:
                        field_no_status_reader(TIter &iter) : iter_(iter) {
                        }

                        template<typename TField>
                        void operator()(TField &field) {
                            field.read_no_status(iter_);
                        }

                    private:
                        TIter &iter_;
                    };

                    template<typename TIter>
                    static field_no_status_reader<TIter> makeFieldNoStatusReader(TIter &iter) {
                        return field_no_status_reader<TIter>(iter);
                    }

                    template<typename TIter>
                    class field_writer {
                    public:
                        field_writer(TIter &iter, nil::marshalling::status_type &status, std::size_t &size) :
                            iter_(iter), status_(status), size_(size) {
                        }

                        template<typename TField>
                        void operator()(const TField &field) {
                            if (status_ == nil::marshalling::status_type::success) {
                                status_ = field.write(iter_, size_);
                                if (status_ == nil::marshalling::status_type::success) {
                                    MARSHALLING_ASSERT(field.length() <= size_);
                                    size_ -= field.length();
                                }
                            }
                        }

                    private:
                        TIter &iter_;
                        nil::marshalling::status_type &status_;
                        std::size_t &size_;
                    };

                    template<typename TIter>
                    static field_writer<TIter> makeFieldWriter(TIter &iter, nil::marshalling::status_type &status,
                                                               std::size_t &size) {
                        return field_writer<TIter>(iter, status, size);
                    }

                    template<typename TIter>
                    class field_no_status_writer {
                    public:
                        field_no_status_writer(TIter &iter) : iter_(iter) {
                        }

                        template<typename TField>
                        void operator()(const TField &field) {
                            field.write_no_status(iter_);
                        }

                    private:
                        TIter &iter_;
                    };

                    template<typename TIter>
                    static field_no_status_writer<TIter> makeFieldNoStatusWriter(TIter &iter) {
                        return field_no_status_writer<TIter>(iter);
                    }

                    struct field_validity_retriever {
                        template<typename TField>
                        bool operator()(bool valid, const TField &field) const {
                            return valid && field.valid();
                        }
                    };

                    struct field_refresher {
                        template<typename TField>
                        bool operator()(bool refreshed, TField &field) const {
                            return field.refresh() || refreshed;
                        }
                    };

                    struct field_length_retriever {
                        template<typename TField>
                        std::size_t operator()(std::size_t size, const TField &field) const {
                            return size + field.length();
                        }
                    };

                    struct field_min_length_retriever {
                        template<typename TField>
                        constexpr std::size_t operator()(std::size_t size) const {
                            return size + TField::min_length();
                        }
                    };

                    struct field_max_length_retriever {
                        template<typename TField>
                        constexpr std::size_t operator()(std::size_t size) const {
                            return size + TField::max_length();
                        }
                    };

                    struct version_dep_checker {
                        template<typename TField>
                        constexpr bool operator()() const {
                            return TField::is_version_dependent();
                        }
                    };

                    all_fields_type fields_;
                };

                //----------------------------------------------------

                template<typename TBase, typename TAllFields>
                class impl_fields_base : public TBase, public impl_fields_container<TAllFields> {
                    using container_base_type = impl_fields_container<TAllFields>;

                public:
                    using container_base_type::are_fields_version_dependent;
                    using container_base_type::eval_length;
                    using container_base_type::eval_length_from;
                    using container_base_type::eval_length_from_until;
                    using container_base_type::eval_length_until;
                    using container_base_type::eval_max_length;
                    using container_base_type::eval_max_length_from;
                    using container_base_type::eval_max_length_from_until;
                    using container_base_type::eval_max_length_until;
                    using container_base_type::eval_min_length;
                    using container_base_type::eval_min_length_from;
                    using container_base_type::eval_min_length_from_until;
                    using container_base_type::eval_min_length_until;
                    using container_base_type::eval_read;
                    using container_base_type::eval_refresh;
                    using container_base_type::eval_valid;
                    using container_base_type::eval_write;

                protected:
                    ~impl_fields_base() noexcept = default;

                    using container_base_type::eval_read_fields_from;
                    using container_base_type::eval_read_fields_from_until;
                    using container_base_type::eval_read_fields_no_status_from;
                    using container_base_type::eval_read_fields_no_status_from_until;
                    using container_base_type::eval_read_fields_no_status_until;
                    using container_base_type::eval_read_fields_until;
                    using container_base_type::eval_write_fields_from;
                    using container_base_type::eval_write_fields_from_until;
                    using container_base_type::eval_write_fields_no_status_from;
                    using container_base_type::eval_write_fields_no_status_from_until;
                    using container_base_type::eval_write_fields_no_status_until;
                    using container_base_type::eval_write_fields_until;
                    using container_base_type::read_fields_from;
                    using container_base_type::read_fields_from_until;
                    using container_base_type::read_fields_no_status_from;
                    using container_base_type::read_fields_no_status_from_until;
                    using container_base_type::read_fields_no_status_until;
                    using container_base_type::read_fields_until;
                    using container_base_type::write_fields_from;
                    using container_base_type::write_fields_from_until;
                    using container_base_type::write_fields_no_status_from;
                    using container_base_type::write_fields_no_status_from_until;
                    using container_base_type::write_fields_no_status_until;
                    using container_base_type::write_fields_until;
                };

                template<bool THasFieldsImpl>
                struct impl_process_fields_base;

                template<>
                struct impl_process_fields_base<true> {
                    template<typename TBase, typename TOpt>
                    using type = impl_fields_base<TBase, typename TOpt::fields_type>;
                };

                template<>
                struct impl_process_fields_base<false> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TOpt>
                using impl_fields_base_type =
                    typename impl_process_fields_base<TOpt::has_fields_impl>::template type<TBase, TOpt>;

                //----------------------------------------------------

                template<typename TBase>
                class impl_version_base : public TBase {
                public:
                    using version_type = typename TBase::version_type;

                    bool eval_fields_version_update() {
                        return processing::tuple_accumulate(TBase::fields(), false,
                                                            field_version_updater(TBase::version()));
                    }

                    template<typename TIter>
                    nil::marshalling::status_type eval_read(TIter &iter, std::size_t len) {
                        eval_fields_version_update();
                        return TBase::eval_read(iter, len);
                    }

                    bool eval_refresh() {
                        bool updated = eval_fields_version_update();
                        return TBase::eval_refresh() || updated;
                    }

                protected:
                    impl_version_base() {
                        eval_fields_version_update();
                    }

                    impl_version_base(const impl_version_base &) = default;

                    impl_version_base(impl_version_base &&) = default;

                    ~impl_version_base() noexcept = default;

                    impl_version_base &operator=(const impl_version_base &) = default;

                    impl_version_base &operator=(impl_version_base &&) = default;

                private:
                    struct field_version_updater {
                        field_version_updater(version_type version) : version_(version) {
                        }

                        template<typename TField>
                        bool operator()(bool updated, TField &field) const {
                            using field_version_type = typename std::decay<decltype(field)>::type::version_type;
                            return field.set_version(static_cast<field_version_type>(version_)) || updated;
                        }

                    private:
                        const version_type version_ = static_cast<version_type>(0);
                    };
                };

                template<bool THasVersion>
                struct impl_process_version_base;

                template<>
                struct impl_process_version_base<true> {
                    template<typename TBase>
                    using type = impl_version_base<TBase>;
                };

                template<>
                struct impl_process_version_base<false> {
                    template<typename TBase>
                    using type = TBase;
                };

                template<typename TBase, typename TOpt>
                using impl_version_base_type = typename impl_process_version_base<
                    TOpt::has_fields_impl
                    && TBase::interface_options_type::has_version_in_extra_transport_fields>::template type<TBase>;

                //----------------------------------------------------

                template<typename TBase, bool THasFields>
                class any_fields_has_custom_refresh;

                template<typename TBase>
                class any_fields_has_custom_refresh<TBase, true> {
                    struct refresh_checker {
                        template<typename TField>
                        constexpr bool operator()() const {
                            return TField::parsed_options_type::has_custom_refresh
                                   || TField::parsed_options_type::has_contents_refresher;
                        }
                    };

                public:
                    constexpr static const bool value
                        = processing::tuple_type_is_any_of<typename TBase::all_fields_type>(refresh_checker());
                };

                template<typename TBase>
                class any_fields_has_custom_refresh<TBase, false> {
                public:
                    constexpr static const bool value = false;
                };

                template<typename TBase, typename TImplOpt>
                constexpr bool any_field_has_custom_refresh() {
                    return any_fields_has_custom_refresh<TBase, TImplOpt::has_fields_impl>::value;
                }

                //----------------------------------------------------

                template<typename TBase, bool THasFields>
                struct any_fields_is_version_dependent;

                template<typename TBase>
                struct any_fields_is_version_dependent<TBase, true> {
                    constexpr static const bool value = TBase::are_fields_version_dependent();
                };

                template<typename TBase>
                struct any_fields_is_version_dependent<TBase, false> {
                    constexpr static const bool value = false;
                };

                template<typename TBase, typename TImplOpt>
                constexpr bool any_field_is_version_dependent() {
                    return any_fields_is_version_dependent<TBase, TImplOpt::has_fields_impl>::value;
                }

                //----------------------------------------------------

                template<typename TBase, typename TActual = void>
                class impl_fields_read_impl_base : public TBase {
                    using base_impl_type = TBase;

                protected:
                    ~impl_fields_read_impl_base() noexcept = default;

                    virtual nil::marshalling::status_type read_impl(typename base_impl_type::read_iterator &iter,
                                                                    std::size_t size) override {
                        return read_impl_internal(iter, size, tag());
                    }

                private:
                    struct has_actual { };
                    struct no_actual { };

                    using tag =
                        typename std::conditional<std::is_same<TActual, void>::value, no_actual, has_actual>::type;

                    nil::marshalling::status_type read_impl_internal(typename base_impl_type::read_iterator &iter,
                                                                     std::size_t size, no_actual) {
                        return base_impl_type::eval_read(iter, size);
                    }

                    nil::marshalling::status_type read_impl_internal(typename base_impl_type::read_iterator &iter,
                                                                     std::size_t size, has_actual) {
                        return static_cast<TActual *>(this)->eval_read(iter, size);
                    }
                };

                template<bool THasFieldsReadImpl, bool THasMsgType>
                struct impl_process_fields_read_impl_base;

                template<>
                struct impl_process_fields_read_impl_base<true, true> {
                    template<typename TBase, typename TOpt>
                    using type = impl_fields_read_impl_base<TBase, typename TOpt::msg_type>;
                };

                template<>
                struct impl_process_fields_read_impl_base<true, false> {
                    template<typename TBase, typename TOpt>
                    using type = impl_fields_read_impl_base<TBase>;
                };

                template<bool THasMsgType>
                struct impl_process_fields_read_impl_base<false, THasMsgType> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TImplOpt>
                using impl_fields_read_impl_base_type =
                    typename impl_process_fields_read_impl_base<TBase::interface_options_type::has_read_iterator
                                                                    && (!TImplOpt::has_no_read_impl),
                                                                TImplOpt::has_msg_type>::template type<TBase, TImplOpt>;

                //----------------------------------------------------

                template<typename TBase, typename TActual = void>
                class impl_fields_write_impl_base : public TBase {
                    using base_impl_type = TBase;

                protected:
                    ~impl_fields_write_impl_base() noexcept = default;

                    virtual nil::marshalling::status_type write_impl(typename base_impl_type::write_iterator &iter,
                                                                     std::size_t size) const override {
                        return write_impl_internal(iter, size, tag());
                    }

                private:
                    struct has_actual { };
                    struct no_actual { };

                    using tag =
                        typename std::conditional<std::is_same<TActual, void>::value, no_actual, has_actual>::type;

                    nil::marshalling::status_type write_impl_internal(typename base_impl_type::write_iterator &iter,
                                                                      std::size_t size, no_actual) const {
                        return base_impl_type::eval_write(iter, size);
                    }

                    nil::marshalling::status_type write_impl_internal(typename base_impl_type::write_iterator &iter,
                                                                      std::size_t size, has_actual) const {
                        return static_cast<const TActual *>(this)->eval_write(iter, size);
                    }
                };

                template<bool THasFieldsWriteImpl, bool THasMsgType>
                struct impl_process_fields_write_impl_base;

                template<>
                struct impl_process_fields_write_impl_base<true, true> {
                    template<typename TBase, typename TOpt>
                    using type = impl_fields_write_impl_base<TBase, typename TOpt::msg_type>;
                };

                template<>
                struct impl_process_fields_write_impl_base<true, false> {
                    template<typename TBase, typename TOpt>
                    using type = impl_fields_write_impl_base<TBase>;
                };

                template<bool THasMsgType>
                struct impl_process_fields_write_impl_base<false, THasMsgType> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TImplOpt>
                using impl_fields_write_impl_base_type = typename impl_process_fields_write_impl_base<
                    TBase::interface_options_type::has_write_iterator && (!TImplOpt::has_no_write_impl),
                    TImplOpt::has_msg_type>::template type<TBase, TImplOpt>;

                //----------------------------------------------------

                template<typename TBase, typename TActual = void>
                class impl_fields_valid_base : public TBase {
                    using base_impl_type = TBase;

                protected:
                    ~impl_fields_valid_base() noexcept = default;

                    virtual bool valid_impl() const override {
                        return validImplInternal(tag());
                    }

                private:
                    struct has_actual { };
                    struct no_actual { };

                    using tag =
                        typename std::conditional<std::is_same<TActual, void>::value, no_actual, has_actual>::type;

                    bool validImplInternal(no_actual) const {
                        return base_impl_type::eval_valid();
                    }

                    bool validImplInternal(has_actual) const {
                        return static_cast<const TActual *>(this)->eval_valid();
                    }
                };

                template<bool THasFieldsValidImpl, bool THasMsgType>
                struct impl_process_fields_valid_base;

                template<>
                struct impl_process_fields_valid_base<true, true> {
                    template<typename TBase, typename TOpt>
                    using type = impl_fields_valid_base<TBase, typename TOpt::msg_type>;
                };

                template<>
                struct impl_process_fields_valid_base<true, false> {
                    template<typename TBase, typename TOpt>
                    using type = impl_fields_valid_base<TBase>;
                };

                template<bool THasMsgType>
                struct impl_process_fields_valid_base<false, THasMsgType> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TImplOpt>
                using impl_fields_valid_base_type =
                    typename impl_process_fields_valid_base<TBase::interface_options_type::has_valid
                                                                && (!TImplOpt::has_no_valid_impl),
                                                            TImplOpt::has_msg_type>::template type<TBase, TImplOpt>;

                //----------------------------------------------------

                template<typename TBase, typename TActual = void>
                class impl_fields_length_base : public TBase {
                    using base_impl_type = TBase;

                protected:
                    ~impl_fields_length_base() noexcept = default;

                    virtual std::size_t length_impl() const override {
                        return length_impl_internal(tag());
                    }

                private:
                    struct has_actual { };
                    struct no_actual { };

                    using tag =
                        typename std::conditional<std::is_same<TActual, void>::value, no_actual, has_actual>::type;

                    std::size_t length_impl_internal(no_actual) const {
                        return base_impl_type::eval_length();
                    }

                    std::size_t length_impl_internal(has_actual) const {
                        return static_cast<const TActual *>(this)->eval_length();
                    }
                };

                template<bool THasFieldsLengthImpl, bool THasMsgType>
                struct impl_process_fields_length_base;

                template<>
                struct impl_process_fields_length_base<true, true> {
                    template<typename TBase, typename TOpt>
                    using type = impl_fields_length_base<TBase, typename TOpt::msg_type>;
                };

                template<>
                struct impl_process_fields_length_base<true, false> {
                    template<typename TBase, typename TOpt>
                    using type = impl_fields_length_base<TBase>;
                };

                template<bool THasMsgType>
                struct impl_process_fields_length_base<false, THasMsgType> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TImplOpt>
                using impl_fields_length_base_type =
                    typename impl_process_fields_length_base<TBase::interface_options_type::has_length
                                                                 && (!TImplOpt::has_no_length_impl),
                                                             TImplOpt::has_msg_type>::template type<TBase, TImplOpt>;

                //----------------------------------------------------

                template<typename TBase, typename TOpt>
                class impl_refresh_base : public TBase {
                protected:
                    ~impl_refresh_base() noexcept = default;

                    virtual bool refresh_impl() override {
                        using tag = typename std::conditional<TOpt::has_msg_type, downcast, no_downcast>::type;
                        return refresh_internal(tag());
                    }

                private:
                    struct downcast { };
                    struct no_downcast { };

                    bool refresh_internal(downcast) {
                        using Actual = typename TOpt::msg_type;
                        return static_cast<Actual *>(this)->eval_refresh();
                    }

                    bool refresh_internal(no_downcast) {
                        static_assert(TOpt::has_fields_impl, "Must use fields_impl option");
                        return TBase::eval_refresh();
                    }
                };

                template<bool THasCustomRefresh>
                struct impl_process_refresh_base;

                template<>
                struct impl_process_refresh_base<true> {
                    template<typename TBase, typename TOpt>
                    using type = impl_refresh_base<TBase, TOpt>;
                };

                template<>
                struct impl_process_refresh_base<false> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TImplOpt>
                using impl_refresh_base_type = typename impl_process_refresh_base<
                    TBase::interface_options_type::has_refresh && (!TImplOpt::has_no_refresh_impl)
                    && (TImplOpt::has_custom_refresh || any_field_has_custom_refresh<TBase, TImplOpt>()
                        || (TBase::interface_options_type::has_version_in_extra_transport_fields
                            && any_field_is_version_dependent<TBase, TImplOpt>()))>::template type<TBase, TImplOpt>;

                //----------------------------------------------------

                template<typename TBase, typename TOpt>
                class impl_name_base : public TBase {
                protected:
                    ~impl_name_base() noexcept = default;

                    virtual const char *name_impl() const override {
                        using Actual = typename TOpt::msg_type;
                        return static_cast<const Actual *>(this)->eval_name();
                    }
                };

                template<bool THasName>
                struct impl_process_name_base;

                template<>
                struct impl_process_name_base<true> {
                    template<typename TBase, typename TOpt>
                    using type = impl_name_base<TBase, TOpt>;
                };

                template<>
                struct impl_process_name_base<false> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TImplOpt>
                using impl_name_base_type =
                    typename impl_process_name_base<TBase::interface_options_type::has_name
                                                    && TImplOpt::has_name>::template type<TBase, TImplOpt>;

                //----------------------------------------------------

                template<typename TBase, typename TActual>
                class impl_dispatch_base : public TBase {
                    using base_impl_type = TBase;

                protected:
                    ~impl_dispatch_base() noexcept = default;

                    virtual typename TBase::DispatchRetType
                        dispatch_impl(typename TBase::handler_type &handler) override {
                        static_assert(std::is_base_of<TBase, TActual>::value, "TActual is not derived class");
                        return handler.handle(static_cast<TActual &>(*this));
                    }
                };

                template<bool THasDispatchImpl>
                struct impl_process_dispatch_base;

                template<>
                struct impl_process_dispatch_base<true> {
                    template<typename TBase, typename TOpt>
                    using type = impl_dispatch_base<TBase, typename TOpt::msg_type>;
                };

                template<>
                struct impl_process_dispatch_base<false> {
                    template<typename TBase, typename TOpt>
                    using type = TBase;
                };

                template<typename TBase, typename TImplOpt>
                using impl_dispatch_base_type = typename impl_process_dispatch_base<
                    TBase::interface_options_type::has_handler && TImplOpt::has_msg_type
                    && (!TImplOpt::has_no_dispatch_impl)>::template type<TBase, TImplOpt>;

                //----------------------------------------------------

                template<typename TMessage, typename... TOptions>
                class impl_builder {
                    using parsed_options_type = impl_options_parser<TOptions...>;
                    using interface_options_type = typename TMessage::interface_options_type;

                    using fields_base_type = impl_fields_base_type<TMessage, parsed_options_type>;
                    using version_base_type = impl_version_base_type<fields_base_type, parsed_options_type>;
                    using static_num_id_base_type
                        = impl_static_num_id_base_type<version_base_type, parsed_options_type>;
                    using polymorphic_static_num_id_base_type
                        = impl_polymorhpic_static_num_id_base_type<static_num_id_base_type, parsed_options_type>;
                    using no_id_base_type
                        = impl_no_id_base_type<polymorphic_static_num_id_base_type, parsed_options_type>;
                    using fields_read_impl_base_type
                        = impl_fields_read_impl_base_type<no_id_base_type, parsed_options_type>;
                    using fields_write_impl_base_type
                        = impl_fields_write_impl_base_type<fields_read_impl_base_type, parsed_options_type>;
                    using fields_valid_base_type
                        = impl_fields_valid_base_type<fields_write_impl_base_type, parsed_options_type>;
                    using fields_length_base_type
                        = impl_fields_length_base_type<fields_valid_base_type, parsed_options_type>;
                    using refresh_base_type = impl_refresh_base_type<fields_length_base_type, parsed_options_type>;
                    using name_base_type = impl_name_base_type<refresh_base_type, parsed_options_type>;
                    using dispatch_base_type = impl_dispatch_base_type<name_base_type, parsed_options_type>;

                public:
                    using options_type = parsed_options_type;
                    using type = dispatch_base_type;
                };

                template<typename TMessage, typename... TOptions>
                using impl_builder_type = typename impl_builder<TMessage, TOptions...>::type;

            }    // namespace message
        }        // namespace detail
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_MESSAGE_IMPL_BUILDER_HPP
