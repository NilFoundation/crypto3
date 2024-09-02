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

#ifndef MARSHALLING_BASIC_STRING_HPP
#define MARSHALLING_BASIC_STRING_HPP

#include <type_traits>
#include <algorithm>
#include <limits>
#include <numeric>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/processing/access.hpp>
#include <nil/marshalling/container/static_string.hpp>

#include <nil/marshalling/types/string/type_traits.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<typename TFieldBase, typename TStorage>
                class basic_string : public TFieldBase {
                    using base_impl_type = TFieldBase;

                public:
                    using endian_type = typename base_impl_type::endian_type;

                    using value_type = TStorage;
                    using element_type = typename TStorage::value_type;

                    static_assert(std::is_integral<element_type>::value, "basic_string of characters only supported");
                    static_assert(sizeof(element_type) == sizeof(char), "Single byte charactes only supported");

                    basic_string() = default;

                    explicit basic_string(const value_type &val) : value_(val) {
                    }

                    explicit basic_string(value_type &&val) : value_(std::move(val)) {
                    }

                    basic_string(const basic_string &) = default;

                    basic_string(basic_string &&) = default;

                    basic_string &operator=(const basic_string &) = default;

                    basic_string &operator=(basic_string &&) = default;

                    ~basic_string() noexcept = default;

                    const value_type &value() const {
                        return value_;
                    }

                    value_type &value() {
                        return value_;
                    }

                    template<typename U>
                    void push_back(U &&val) {
                        static_assert(detail::string_has_push_back<value_type>::value,
                                      "The basic_string type must have push_back() member function");
                        value_.push_back(static_cast<typename value_type::value_type>(val));
                    }

                    value_type &create_back() {
                        value_.push_back(value_type());
                        return value_.back();
                    }

                    void clear() {
                        static_assert(has_member_function_clear<value_type>::value,
                                      "The basic_string type must have clear() member function");
                        value_.clear();
                    }

                    constexpr std::size_t length() const {
                        return value_.size() * sizeof(element_type);
                    }

                    static constexpr std::size_t min_length() {
                        return 0U;
                    }

                    static constexpr std::size_t max_length() {
                        return detail::string_max_length_retrieve_helper<TStorage>::value * sizeof(element_type);
                    }

                    static constexpr bool valid() {
                        return true;
                    }

                    static constexpr std::size_t min_element_length() {
                        return sizeof(element_type);
                    }

                    static constexpr std::size_t max_element_length() {
                        return min_element_length();
                    }

                    static constexpr std::size_t element_length(const element_type &elem) {
                        return sizeof(elem);
                    }

                    template<typename TIter>
                    static status_type read_element(element_type &elem, TIter &iter, std::size_t &len) {
                        if (len < sizeof(element_type)) {
                            return status_type::not_enough_data;
                        }

                        elem = processing::read_data<element_type>(iter, endian_type());
                        len -= sizeof(element_type);
                        return status_type::success;
                    }

                    template<typename TIter>
                    static void read_element_no_status(element_type &elem, TIter &iter) {
                        elem = processing::read_data<element_type>(iter, endian_type());
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        using IterType = typename std::decay<decltype(iter)>::type;
                        using IterCategory = typename std::iterator_traits<IterType>::iterator_category;
                        static_assert(std::is_base_of<std::random_access_iterator_tag, IterCategory>::value,
                                      "iterator for reading is expected to be random access one");

                        using ConstPointer = typename value_type::const_pointer;
                        auto *str = reinterpret_cast<ConstPointer>(&(*iter));
                        eval_advance(iter, len);
                        auto *endStr = reinterpret_cast<ConstPointer>(&(*iter));
                        if (static_cast<std::size_t>(std::distance(str, endStr)) == len) {
                            using tag = typename std::conditional<detail::string_has_assign<value_type>::value,
                                                                  assign_exists_tag,
                                                                  assign_missing_tag>::type;
                            eval_assign(str, len, tag());
                        } else {
                            using tag = typename std::conditional<detail::string_has_push_back<value_type>::value,
                                                                  push_back_exists_tag,
                                                                  push_back_missing_tag>::type;

                            eval_push_dack(str, len, tag());
                        }

                        return status_type::success;
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) = delete;

                    template<typename TIter>
                    status_type read_n(std::size_t count, TIter &iter, std::size_t &len) {
                        if (len < count) {
                            return status_type::not_enough_data;
                        }

                        return read(iter, count);
                    }

                    template<typename TIter>
                    void read_no_status_n(std::size_t count, TIter &iter) {
                        read(iter, count);
                    }

                    template<typename TIter>
                    static status_type write_element(const element_type &elem, TIter &iter, std::size_t &len) {
                        if (len < sizeof(element_type)) {
                            return status_type::buffer_overflow;
                        }

                        processing::write_data(elem, iter, endian_type());
                        len -= sizeof(element_type);
                        return status_type::success;
                    }

                    template<typename TIter>
                    static void write_element_no_status(const element_type &elem, TIter &iter) {
                        processing::write_data(elem, iter, endian_type());
                    }

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t len) const {
                        if (len < length()) {
                            return status_type::buffer_overflow;
                        }

                        write_no_status(iter);
                        return status_type::success;
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        std::copy_n(value_.begin(), value_.size(), iter);
                        eval_advance(iter, value_.size());
                    }

                    template<typename TIter>
                    status_type write_n(std::size_t count, TIter &iter, std::size_t &len) const {
                        count = std::min(count, value_.size());

                        if (len < count) {
                            return status_type::buffer_overflow;
                        }

                        write_no_status_n(count, iter);
                        return status_type::success;
                    }

                    template<typename TIter>
                    void write_no_status_n(std::size_t count, TIter &iter) const {
                        count = std::min(count, value_.size());
                        std::copy_n(value_.begin(), count, iter);
                        eval_advance(iter, count);
                    }

                private:
                    struct assign_exists_tag { };
                    struct assign_missing_tag { };
                    struct push_back_exists_tag { };
                    struct push_back_missing_tag { };
                    struct reserve_exists_tag { };
                    struct reserve_missing_tag { };
                    struct advancable_tag { };
                    struct not_advancable_tag { };

                    void eval_assign(typename value_type::const_pointer str, std::size_t len, assign_exists_tag) {
                        value_.assign(str, len);
                    }

                    void eval_assign(typename value_type::const_pointer str, std::size_t len, assign_missing_tag) {
                        value_ = value_type(str, len);
                    }

                    void eval_push_dack(typename value_type::const_pointer str, std::size_t len, push_back_exists_tag) {
                        clear();
                        eval_reserve(len);
                        for (std::size_t idx = 0; idx < len; ++idx) {
                            value_.push_back(str[idx]);
                        }
                    }

                    void
                        eval_push_dack(typename value_type::const_pointer str, std::size_t len, push_back_missing_tag) {
                        value_ = value_type(str, len);
                    }

                    void eval_reserve(std::size_t len) {
                        using tag =
                            typename std::conditional<has_member_function_reserve<value_type>::value,
                                                      reserve_exists_tag,
                                                      reserve_missing_tag>::type;
                        eval_reserve(len, tag());
                    }

                    void eval_reserve(std::size_t len, reserve_exists_tag) {
                        value_.reserve(len);
                    }

                    static void eval_reserve(std::size_t, reserve_missing_tag) {
                    }

                    template<typename TIter>
                    static void eval_advance(TIter &iter, std::size_t len) {
                        using IterType = typename std::decay<decltype(iter)>::type;
                        using IterCategory = typename std::iterator_traits<IterType>::iterator_category;
                        static const bool InputIter = std::is_base_of<std::input_iterator_tag, IterCategory>::value;
                        using tag = typename std::conditional<InputIter, advancable_tag, not_advancable_tag>::type;
                        eval_advance(iter, len, tag());
                    }

                    template<typename TIter>
                    static void eval_advance(TIter &iter, std::size_t len, advancable_tag) {
                        std::advance(iter, len);
                    }

                    template<typename TIter>
                    static void eval_advance(TIter &, std::size_t, not_advancable_tag) {
                    }

                    value_type value_;
                };

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BASIC_STRING_HPP
