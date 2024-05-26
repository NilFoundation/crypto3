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

#ifndef MARSHALLING_BASIC_VARIANT_HPP
#define MARSHALLING_BASIC_VARIANT_HPP

#include <type_traits>
#include <algorithm>

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/processing/tuple.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<typename TFieldBase, typename TMembers>
                class basic_variant : public TFieldBase {
                public:
                    using members_type = TMembers;
                    using value_type = processing::tuple_as_aligned_union_type<members_type>;

                    basic_variant() = default;

                    basic_variant(const value_type &val) : storage_(val) {
                    }

                    basic_variant(value_type &&val) : storage_(std::move(val)) {
                    }

                    basic_variant(const basic_variant &other) {
                        if (!other.current_field_valid()) {
                            return;
                        }

                        processing::tuple_for_selected_type<members_type>(
                            other.memIdx_, copy_construct_helper(&storage_, &other.storage_));

                        memIdx_ = other.memIdx_;
                    }

                    basic_variant(basic_variant &&other) {
                        if (!other.current_field_valid()) {
                            return;
                        }

                        processing::tuple_for_selected_type<members_type>(
                            other.memIdx_, move_construct_helper(&storage_, &other.storage_));

                        memIdx_ = other.memIdx_;
                    }

                    ~basic_variant() noexcept {
                        check_destruct();
                    }

                    basic_variant &operator=(const basic_variant &other) {
                        if (this == &other) {
                            return *this;
                        }

                        check_destruct();
                        if (!other.current_field_valid()) {
                            return *this;
                        }

                        processing::tuple_for_selected_type<members_type>(
                            other.memIdx_, copy_construct_helper(&storage_, &other.storage_));

                        memIdx_ = other.memIdx_;
                        return *this;
                    }

                    basic_variant &operator=(basic_variant &&other) {
                        if (this == &other) {
                            return *this;
                        }

                        check_destruct();

                        if (!other.current_field_valid()) {
                            return *this;
                        }

                        processing::tuple_for_selected_type<members_type>(
                            other.memIdx_, move_construct_helper(&storage_, &other.storage_));

                        memIdx_ = other.memIdx_;
                        return *this;
                    }

                    const value_type &value() const {
                        return storage_;
                    }

                    value_type &value() {
                        return storage_;
                    }

                    std::size_t length() const {
                        if (!current_field_valid()) {
                            return 0U;
                        }

                        std::size_t len = std::numeric_limits<std::size_t>::max();
                        processing::tuple_for_selected_type<members_type>(
                            memIdx_, length_calc_helper(len, &storage_));
                        return len;
                    }

                    static constexpr std::size_t min_length() {
                        return 0U;
                    }

                    static constexpr std::size_t max_length() {
                        return processing::tuple_type_accumulate<members_type>(
                            std::size_t(0), max_length_calc_helper());
                    }

                    bool valid() const {
                        if (!current_field_valid()) {
                            return false;
                        }

                        bool val = false;
                        processing::tuple_for_selected_type<members_type>(
                            memIdx_, valid_check_helper(val, &storage_));
                        return val;
                    }

                    bool refresh() {
                        if (!current_field_valid()) {
                            return false;
                        }

                        bool val = false;
                        processing::tuple_for_selected_type<members_type>(
                            memIdx_, refresh_helper(val, &storage_));
                        return val;
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        check_destruct();
                        status_type es = status_type::error_status_amount;
                        processing::tuple_for_each_type<members_type>(
                            make_read_helper(es, iter, len, &storage_));
                        MARSHALLING_ASSERT((es == status_type::success)
                                           || (members_count <= memIdx_));
                        MARSHALLING_ASSERT((es != status_type::success) || (memIdx_ < members_count));

                        return es;
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) = delete;

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t len) const {
                        if (!current_field_valid()) {
                            return status_type::success;
                        }

                        status_type es = status_type::error_status_amount;
                        processing::tuple_for_selected_type<members_type>(
                            memIdx_, make_write_helper(es, iter, len, &storage_));
                        return es;
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        if (!current_field_valid()) {
                            return;
                        }

                        processing::tuple_for_selected_type<members_type>(
                            memIdx_, make_write_no_status_helper(iter, &storage_));
                    }

                    std::size_t current_field() const {
                        return memIdx_;
                    }

                    void select_field(std::size_t idx) {
                        if (idx == memIdx_) {
                            return;
                        }

                        check_destruct();
                        if (!is_idx_valid(idx)) {
                            return;
                        }

                        processing::tuple_for_selected_type<members_type>(
                            idx, construct_helper(&storage_));
                        memIdx_ = idx;
                    }

                    template<typename TFunc>
                    void current_field_exec(TFunc &&func) {
                        if (!current_field_valid()) {
                            MARSHALLING_ASSERT(!"Invalid field execution");
                            return;
                        }

                        processing::tuple_for_selected_type<members_type>(
                            memIdx_, make_exec_helper(std::forward<TFunc>(func)));
                    }

                    template<typename TFunc>
                    void current_field_exec(TFunc &&func) const {
                        if (!current_field_valid()) {
                            MARSHALLING_ASSERT(!"Invalid field execution");
                            return;
                        }

                        processing::tuple_for_selected_type<members_type>(
                            memIdx_, make_const_exec_helper(std::forward<TFunc>(func)));
                    }

                    template<std::size_t TIdx, typename... TArgs>
                    typename std::tuple_element<TIdx, members_type>::type &init_field(TArgs &&...args) {
                        static_assert(is_idx_valid(TIdx), "Only valid field index can be used");
                        check_destruct();

                        using field_type = typename std::tuple_element<TIdx, members_type>::type;
                        new (&storage_) field_type(std::forward<TArgs>(args)...);
                        memIdx_ = TIdx;
                        return reinterpret_cast<field_type &>(storage_);
                    }

                    template<std::size_t TIdx>
                    typename std::tuple_element<TIdx, members_type>::type &access_field() {
                        static_assert(is_idx_valid(TIdx), "Only valid field index can be used");
                        MARSHALLING_ASSERT(TIdx == memIdx_);    // Accessing non initialised field

                        using field_type = typename std::tuple_element<TIdx, members_type>::type;
                        return reinterpret_cast<field_type &>(storage_);
                    }

                    template<std::size_t TIdx>
                    const typename std::tuple_element<TIdx, members_type>::type &access_field() const {
                        static_assert(is_idx_valid(TIdx), "Something is wrong");
                        MARSHALLING_ASSERT(TIdx == memIdx_);    // Accessing non initialised field

                        using field_type = typename std::tuple_element<TIdx, members_type>::type;
                        return reinterpret_cast<const field_type &>(storage_);
                    }

                    bool current_field_valid() const {
                        return is_idx_valid(memIdx_);
                    }

                    void reset() {
                        check_destruct();
                        MARSHALLING_ASSERT(!current_field_valid());
                    }

                private:
                    class construct_helper {
                    public:
                        construct_helper(void *storage) : storage_(storage) {
                        }

                        template<std::size_t TIdx, typename TField>
                        void operator()() const {
                            new (storage_) TField;
                        }

                    private:
                        void *storage_ = nullptr;
                    };

                    class copy_construct_helper {
                    public:
                        copy_construct_helper(void *storage, const void *other) : storage_(storage), other_(other) {
                        }

                        template<std::size_t TIdx, typename TField>
                        void operator()() const {
                            new (storage_) TField(*(reinterpret_cast<const TField *>(other_)));
                        }

                    private:
                        void *storage_ = nullptr;
                        const void *other_ = nullptr;
                    };

                    class move_construct_helper {
                    public:
                        move_construct_helper(void *storage, void *other) : storage_(storage), other_(other) {
                        }

                        template<std::size_t TIdx, typename TField>
                        void operator()() const {
                            new (storage_) TField(std::move(*(reinterpret_cast<const TField *>(other_))));
                        }

                    private:
                        void *storage_ = nullptr;
                        void *other_ = nullptr;
                    };

                    class destruct_helper {
                    public:
                        destruct_helper(void *storage) : storage_(storage) {
                        }

                        template<std::size_t TIdx, typename TField>
                        void operator()() const {
                            reinterpret_cast<TField *>(storage_)->~TField();
                        }

                    private:
                        void *storage_ = nullptr;
                    };

                    class length_calc_helper {
                    public:
                        length_calc_helper(std::size_t &len, const void *storage) : len_(len), storage_(storage) {
                        }

                        template<std::size_t TIdx, typename TField>
                        void operator()() {
                            len_ = reinterpret_cast<const TField *>(storage_)->length();
                        }

                    private:
                        std::size_t &len_;
                        const void *storage_;
                    };

                    struct max_length_calc_helper {
                        template<typename TField>
                        constexpr std::size_t operator()(std::size_t val) const {
                            return val >= TField::max_length() ? val : TField::max_length();
                        }
                    };

                    class valid_check_helper {
                    public:
                        valid_check_helper(bool &result, const void *storage) : result_(result), storage_(storage) {
                        }

                        template<std::size_t TIdx, typename TField>
                        void operator()() {
                            result_ = reinterpret_cast<const TField *>(storage_)->valid();
                        }

                    private:
                        bool &result_;
                        const void *storage_;
                    };

                    class refresh_helper {
                    public:
                        refresh_helper(bool &result, void *storage) : result_(result), storage_(storage) {
                        }

                        template<std::size_t TIdx, typename TField>
                        void operator()() {
                            result_ = reinterpret_cast<TField *>(storage_)->refresh();
                        }

                    private:
                        bool &result_;
                        void *storage_ = nullptr;
                    };

                    template<typename TFunc>
                    class exec_helper {
                        static_assert(std::is_lvalue_reference<TFunc>::value || std::is_rvalue_reference<TFunc>::value,
                                      "Wrong type of template parameter");

                    public:
                        template<typename U>
                        exec_helper(void *storage, U &&func) : storage_(storage), func_(std::forward<U>(func)) {
                        }

                        template<std::size_t TIdx, typename TField>
                        void operator()() {
#ifdef _MSC_VER
                            // VS compiler
                            func_.operator()<TIdx>(*(reinterpret_cast<TField *>(storage_)));
#else     // #ifdef _MSC_VER
                            func_.template operator()<TIdx>(*(reinterpret_cast<TField *>(storage_)));
#endif    // #ifdef _MSC_VER
                        }

                    private:
                        void *storage_ = nullptr;
                        TFunc func_;
                    };

                    template<typename TFunc>
                    auto make_exec_helper(TFunc &&func) -> exec_helper<decltype(std::forward<TFunc>(func))> {
                        using FuncType = decltype(std::forward<TFunc>(func));
                        return exec_helper<FuncType>(&storage_, std::forward<TFunc>(func));
                    }

                    template<typename TFunc>
                    class const_exec_helper {
                        static_assert(std::is_lvalue_reference<TFunc>::value || std::is_rvalue_reference<TFunc>::value,
                                      "Wrong type of template parameter");

                    public:
                        template<typename U>
                        const_exec_helper(const void *storage, U &&func) :
                            storage_(storage), func_(std::forward<U>(func)) {
                        }

                        template<std::size_t TIdx, typename TField>
                        void operator()() {
#ifdef _MSC_VER
                            // VS compiler
                            func_.operator()<TIdx>(*(reinterpret_cast<const TField *>(storage_)));
#else     // #ifdef _MSC_VER
                            func_.template operator()<TIdx>(*(reinterpret_cast<const TField *>(storage_)));
#endif    // #ifdef _MSC_VER
                        }

                    private:
                        const void *storage_ = nullptr;
                        TFunc func_;
                    };

                    template<typename TFunc>
                    auto make_const_exec_helper(TFunc &&func) const
                        -> const_exec_helper<decltype(std::forward<TFunc>(func))> {
                        using FuncType = decltype(std::forward<TFunc>(func));
                        return const_exec_helper<FuncType>(&storage_, std::forward<TFunc>(func));
                    }

                    template<typename TIter>
                    class read_helper {
                    public:
                        read_helper(std::size_t &idx, status_type &es, TIter &iter, std::size_t len,
                                    void *storage) :
                            idx_(idx),
                            es_(es), iter_(iter), len_(len), storage_(storage) {
                            using IterType = typename std::decay<decltype(iter)>::type;
                            using IterCategory = typename std::iterator_traits<IterType>::iterator_category;
                            static_assert(std::is_base_of<std::random_access_iterator_tag, IterCategory>::value,
                                          "basic_variant field only supports read with random access iterators");

                            es_ = status_type::error_status_amount;
                        }

                        template<typename TField>
                        void operator()() {
                            if (readComplete_) {
                                return;
                            }

                            auto *field = new (storage_) TField;

                            auto iterTmp = iter_;
                            status_type es = field->read(iterTmp, len_);
                            if (es == status_type::success) {
                                iter_ = iterTmp;
                                es_ = es;
                                readComplete_ = true;
                                return;
                            }

                            field->~TField();

                            if ((es_ == status_type::error_status_amount)
                                || (es == status_type::not_enough_data)) {
                                es_ = es;
                            }

                            ++idx_;
                        }

                    private:
                        std::size_t &idx_;
                        status_type &es_;
                        TIter &iter_;
                        std::size_t len_ = 0;
                        void *storage_ = nullptr;
                        bool readComplete_ = false;
                    };

                    template<typename TIter>
                    read_helper<TIter> make_read_helper(status_type &es, TIter &iter, std::size_t len,
                                                        void *storage) {
                        memIdx_ = 0;
                        return read_helper<TIter>(memIdx_, es, iter, len, storage);
                    }

                    template<typename TIter>
                    class write_helper {
                    public:
                        write_helper(status_type &es, TIter &iter, std::size_t len, const void *storage) :
                            es_(es), iter_(iter), len_(len), storage_(storage) {
                        }

                        template<std::size_t TIdx, typename TField>
                        void operator()() {
                            es_ = reinterpret_cast<const TField *>(storage_)->write(iter_, len_);
                        }

                    private:
                        status_type &es_;
                        TIter &iter_;
                        std::size_t len_ = 0U;
                        const void *storage_ = nullptr;
                    };

                    template<typename TIter>
                    static write_helper<TIter> make_write_helper(status_type &es, TIter &iter,
                                                                 std::size_t len, const void *storage) {
                        return write_helper<TIter>(es, iter, len, storage);
                    }

                    template<typename TIter>
                    class write_no_status_helper {
                    public:
                        write_no_status_helper(TIter &iter, const void *storage) : iter_(iter), storage_(storage) {
                        }

                        template<std::size_t TIdx, typename TField>
                        void operator()() {
                            reinterpret_cast<const TField *>(storage_)->write_no_status(iter_);
                        }

                    private:
                        TIter &iter_;
                        const void *storage_ = nullptr;
                    };

                    template<typename TIter>
                    static write_no_status_helper<TIter> make_write_no_status_helper(TIter &iter, const void *storage) {
                        return write_no_status_helper<TIter>(iter, storage);
                    }

                    void check_destruct() {
                        if (current_field_valid()) {
                            processing::tuple_for_selected_type<members_type>(
                                memIdx_, destruct_helper(&storage_));
                            memIdx_ = members_count;
                        }
                    }

                    static constexpr bool is_idx_valid(std::size_t idx) {
                        return idx < members_count;
                    }

                    value_type storage_;
                    std::size_t memIdx_ = members_count;

                    static const std::size_t members_count = std::tuple_size<members_type>::value;
                    static_assert(nil::detail::is_tuple<members_type>::value,
                                  "value_type must be tuple");
                    static_assert(0U < members_count, "value_type must be non-empty tuple");
                };

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BASIC_VARIANT_HPP
