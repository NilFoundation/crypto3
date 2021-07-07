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

#ifndef MARSHALLING_BASIC_ARRAY_LIST_HPP
#define MARSHALLING_BASIC_ARRAY_LIST_HPP

#include <type_traits>
#include <algorithm>
#include <limits>
#include <numeric>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/processing/access.hpp>
#include <nil/marshalling/types/detail/common_funcs.hpp>
#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/types/array_list/type_traits.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<typename TFieldBase, typename TStorage>
                class basic_array_list
                    : public TFieldBase,
                      public detail::version_storage<
                          typename TFieldBase::version_type,
                          detail::array_list_element_is_version_dependent<typename TStorage::value_type>()> {
                    using base_impl_type = TFieldBase;
                    using version_base_impl = detail::version_storage<
                        typename TFieldBase::version_type,
                        detail::array_list_element_is_version_dependent<typename TStorage::value_type>()>;

                public:
                    using endian_type = typename base_impl_type::endian_type;
                    using version_type = typename base_impl_type::version_type;

                    using element_type = typename TStorage::value_type;
                    using value_type = TStorage;

                    basic_array_list() = default;

                    explicit basic_array_list(const value_type &val) : value_(val) {
                    }

                    explicit basic_array_list(value_type &&val) : value_(std::move(val)) {
                    }

                    basic_array_list(const basic_array_list &) = default;

                    basic_array_list(basic_array_list &&) = default;

                    basic_array_list &operator=(const basic_array_list &) = default;

                    basic_array_list &operator=(basic_array_list &&) = default;

                    ~basic_array_list() noexcept = default;

                    const value_type &value() const {
                        return value_;
                    }

                    value_type &value() {
                        return value_;
                    }

                    template<typename U>
                    void push_back(U &&val) {
                        value_.push_back(std::forward<U>(val));
                    }

                    element_type &create_back() {
                        value_.emplace_back();
                        update_elem_version(value_.back(), version_tag());
                        return value_.back();
                    }

                    void clear() {
                        static_assert(has_member_function_clear<value_type>::value,
                                      "The used storage type for basic_array_list must have clear() member function");

                        value_.clear();
                    }

                    constexpr std::size_t length() const {
                        return length_internal(elem_tag());
                    }

                    static constexpr std::size_t min_length() {
                        return 0U;
                    }

                    static constexpr std::size_t max_length() {
                        return detail::array_list_max_length_retrieve_helper<TStorage>::value
                               * max_length_internal(elem_tag());
                    }

                    constexpr bool valid() const {
                        return valid_internal(elem_tag());
                    }

                    bool refresh() {
                        return refresh_internal(elem_tag());
                    }

                    static constexpr std::size_t min_element_length() {
                        return min_elem_length_internal(elem_tag());
                    }

                    static constexpr std::size_t max_element_length() {
                        return max_elem_length_internal(elem_tag());
                    }

                    static constexpr std::size_t element_length(const element_type &elem) {
                        return element_length_internal(elem, elem_tag());
                    }

                    template<typename TIter>
                    static status_type read_element(element_type &elem, TIter &iter, std::size_t &len) {
                        return read_element_internal(elem, iter, len, elem_tag());
                    }

                    template<typename TIter>
                    static void read_element_no_status(element_type &elem, TIter &iter) {
                        return read_element_no_status_internal(elem, iter, elem_tag());
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        using IterType = typename std::decay<decltype(iter)>::type;
                        using IterCategory = typename std::iterator_traits<IterType>::iterator_category;
                        static const bool IsRandomAccessIter
                            = std::is_base_of<std::random_access_iterator_tag, IterCategory>::value;
                        static const bool IsRawData
                            = std::is_integral<element_type>::value && (sizeof(element_type) == sizeof(std::uint8_t));

                        using tag = typename std::conditional<IsRandomAccessIter && IsRawData, raw_data_tag,
                                                              field_elem_tag>::type;

                        return read_internal(iter, len, tag());
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) = delete;

                    template<typename TIter>
                    status_type read_n(std::size_t count, TIter &iter, std::size_t &len) {
                        using IterType = typename std::decay<decltype(iter)>::type;
                        using IterCategory = typename std::iterator_traits<IterType>::iterator_category;
                        static const bool IsRandomAccessIter
                            = std::is_base_of<std::random_access_iterator_tag, IterCategory>::value;
                        static const bool IsRawData
                            = std::is_integral<element_type>::value && (sizeof(element_type) == sizeof(std::uint8_t));

                        using tag = typename std::conditional<IsRandomAccessIter && IsRawData, raw_data_tag,
                                                              field_elem_tag>::type;

                        return read_internal_n(count, iter, len, tag());
                    }

                    template<typename TIter>
                    void read_no_status_n(std::size_t count, TIter &iter) {
                        using IterType = typename std::decay<decltype(iter)>::type;
                        using IterCategory = typename std::iterator_traits<IterType>::iterator_category;
                        static const bool IsRandomAccessIter
                            = std::is_base_of<std::random_access_iterator_tag, IterCategory>::value;
                        static const bool IsRawData
                            = std::is_integral<element_type>::value && (sizeof(element_type) == sizeof(std::uint8_t));

                        using tag = typename std::conditional<IsRandomAccessIter && IsRawData, raw_data_tag,
                                                              field_elem_tag>::type;

                        return read_no_status_internal_n(count, iter, tag());
                    }

                    template<typename TIter>
                    static status_type write_element(const element_type &elem, TIter &iter, std::size_t &len) {
                        return write_element_internal(elem, iter, len, elem_tag());
                    }

                    template<typename TIter>
                    static void write_element_no_status(const element_type &elem, TIter &iter) {
                        return write_element_no_status_internal(elem, iter, elem_tag());
                    }

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t len) const {
                        return common_funcs::write_sequence(*this, iter, len);
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        common_funcs::write_sequence_no_status(*this, iter);
                    }

                    template<typename TIter>
                    status_type write_n(std::size_t count, TIter &iter, std::size_t &len) const {
                        return common_funcs::write_sequence_n(*this, count, iter, len);
                    }

                    template<typename TIter>
                    void write_no_status_n(std::size_t count, TIter &iter) const {
                        common_funcs::write_sequence_no_status_n(*this, count, iter);
                    }

                    static constexpr bool is_version_dependent() {
                        return detail::array_list_element_is_version_dependent<element_type>();
                    }

                    bool set_version(version_type version) {
                        return set_version_internal(version, version_tag());
                    }

                private:
                    struct field_elem_tag { };
                    struct integral_elem_tag { };
                    struct fixed_length_tag { };
                    struct var_length_tag { };
                    struct raw_data_tag { };
                    struct assign_exists_tag { };
                    struct assign_missing_tag { };
                    struct version_dependent_tag { };
                    struct no_version_dependency_tag { };

                    using elem_tag = typename std::conditional<std::is_integral<element_type>::value, integral_elem_tag,
                                                               field_elem_tag>::type;

                    using field_length_tag =
                        typename std::conditional<detail::array_list_field_has_var_length<element_type>::value,
                                                  var_length_tag, fixed_length_tag>::type;

                    using version_tag =
                        typename std::conditional<detail::array_list_element_is_version_dependent<element_type>(),
                                                  version_dependent_tag, no_version_dependency_tag>::type;

                    constexpr std::size_t length_internal(field_elem_tag) const {
                        return field_length(field_length_tag());
                    }

                    constexpr std::size_t length_internal(integral_elem_tag) const {
                        return value_.size() * sizeof(element_type);
                    }

                    constexpr std::size_t field_length(fixed_length_tag) const {
                        return element_type().length() * value_.size();
                    }

                    std::size_t field_length(var_length_tag) const {
                        return std::accumulate(
                            value_.begin(), value_.end(), std::size_t(0),
                            [](std::size_t sum, typename value_type::const_reference e) -> std::size_t {
                                return sum + e.length();
                            });
                    }

                    static constexpr std::size_t max_length_internal(field_elem_tag) {
                        return element_type::max_length();
                    }

                    static constexpr std::size_t max_length_internal(integral_elem_tag) {
                        return sizeof(element_type);
                    }

                    template<typename TIter>
                    static status_type read_field_element(element_type &elem, TIter &iter, std::size_t &len) {
                        status_type es = elem.read(iter, len);
                        if (es == status_type::success) {
                            MARSHALLING_ASSERT(elem.length() <= len);
                            len -= elem.length();
                        }
                        return es;
                    }

                    template<typename TIter>
                    static status_type read_integral_element(element_type &elem, TIter &iter, std::size_t &len) {
                        if (len < sizeof(element_type)) {
                            return status_type::not_enough_data;
                        }

                        elem = processing::read_data<element_type>(iter, endian_type());
                        len -= sizeof(element_type);
                        return status_type::success;
                    }

                    template<typename TIter>
                    static status_type read_element_internal(element_type &elem, TIter &iter, std::size_t &len,
                                                             field_elem_tag) {
                        return read_field_element(elem, iter, len);
                    }

                    template<typename TIter>
                    static status_type read_element_internal(element_type &elem, TIter &iter, std::size_t &len,
                                                             integral_elem_tag) {
                        return read_integral_element(elem, iter, len);
                    }

                    template<typename TIter>
                    static void read_no_status_field_element(element_type &elem, TIter &iter) {
                        elem.read_no_status(iter);
                    }

                    template<typename TIter>
                    static void read_no_status_integral_element(element_type &elem, TIter &iter) {
                        elem = processing::read_data<element_type>(iter, endian_type());
                    }

                    template<typename TIter>
                    static void read_element_no_status_internal(element_type &elem, TIter &iter, field_elem_tag) {
                        read_no_status_field_element(elem, iter);
                    }

                    template<typename TIter>
                    static void read_element_no_status_internal(element_type &elem, TIter &iter, integral_elem_tag) {
                        read_element_no_status_internal(elem, iter);
                    }

                    template<typename TIter>
                    static status_type write_field_element(const element_type &elem, TIter &iter, std::size_t &len) {
                        status_type es = elem.write(iter, len);
                        if (es == status_type::success) {
                            len -= elem.length();
                        }
                        return es;
                    }

                    template<typename TIter>
                    static status_type write_integral_element(const element_type &elem, TIter &iter, std::size_t &len) {
                        if (len < sizeof(element_type)) {
                            return status_type::buffer_overflow;
                        }

                        base_impl_type::write_data(elem, iter);
                        len -= sizeof(element_type);
                        return status_type::success;
                    }

                    template<typename TIter>
                    static status_type write_element_internal(const element_type &elem, TIter &iter, std::size_t &len,
                                                              field_elem_tag) {
                        return write_field_element(elem, iter, len);
                    }

                    template<typename TIter>
                    static status_type write_element_internal(const element_type &elem, TIter &iter, std::size_t &len,
                                                              integral_elem_tag) {
                        return write_integral_element(elem, iter, len);
                    }

                    template<typename TIter>
                    static void write_no_status_field_element(const element_type &elem, TIter &iter) {
                        elem.write_no_status(iter);
                    }

                    template<typename TIter>
                    static void write_no_status_integral_element(const element_type &elem, TIter &iter) {
                        base_impl_type::write_data(elem, iter);
                    }

                    template<typename TIter>
                    static void write_element_no_status_internal(const element_type &elem, TIter &iter,
                                                                 field_elem_tag) {
                        return write_no_status_field_element(elem, iter);
                    }

                    template<typename TIter>
                    static void write_element_no_status_internal(const element_type &elem, TIter &iter,
                                                                 integral_elem_tag) {
                        return write_no_status_integral_element(elem, iter);
                    }

                    constexpr bool valid_internal(field_elem_tag) const {
                        return std::all_of(value_.begin(), value_.end(),
                                           [](const element_type &e) -> bool { return e.valid(); });
                    }

                    static constexpr bool valid_internal(integral_elem_tag) {
                        return true;
                    }

                    bool refresh_internal(field_elem_tag) {
                        return std::accumulate(value_.begin(), value_.end(), false,
                                               [](bool prev, typename value_type::reference elem) -> bool {
                                                   return elem.refresh() || prev;
                                               });
                    }

                    static constexpr bool refresh_internal(integral_elem_tag) {
                        return false;
                    }

                    static constexpr std::size_t min_elem_length_internal(integral_elem_tag) {
                        return sizeof(element_type);
                    }

                    static constexpr std::size_t min_elem_length_internal(field_elem_tag) {
                        return element_type::min_length();
                    }

                    static constexpr std::size_t max_elem_length_internal(integral_elem_tag) {
                        return sizeof(element_type);
                    }

                    static constexpr std::size_t max_elem_length_internal(field_elem_tag) {
                        return element_type::max_length();
                    }

                    static constexpr std::size_t element_length_internal(const element_type &, integral_elem_tag) {
                        return sizeof(element_type);
                    }

                    static constexpr std::size_t element_length_internal(const element_type &elem, field_elem_tag) {
                        return elem.length();
                    }

                    template<typename TIter>
                    status_type read_internal(TIter &iter, std::size_t len, field_elem_tag) {
                        static_assert(has_member_function_clear<value_type>::value,
                                      "The used storage type for basic_array_list must have clear() member function");
                        value_.clear();
                        auto remLen = len;
                        while (0 < remLen) {
                            element_type &elem = create_back();
                            status_type es = read_element(elem, iter, remLen);
                            if (es != status_type::success) {
                                value_.pop_back();
                                return es;
                            }
                        }

                        return status_type::success;
                    }

                    template<typename TIter>
                    status_type read_internal(TIter &iter, std::size_t len, raw_data_tag) {
                        using tag = typename std::conditional<detail::vector_has_assign<value_type>::value,
                                                              assign_exists_tag, assign_missing_tag>::type;
                        eval_assign(iter, len, tag());
                        std::advance(iter, len);
                        return status_type::success;
                    }

                    template<typename TIter>
                    void eval_assign(TIter &iter, std::size_t len, assign_exists_tag) {
                        value_.assign(iter, iter + len);
                    }

                    template<typename TIter>
                    void eval_assign(TIter &iter, std::size_t len, assign_missing_tag) {
                        typename value_type::const_pointer data = 
                            reinterpret_cast<typename value_type::const_pointer>(&(*iter));
                        value_ = value_type(data, len);
                    }

                    template<typename TIter>
                    status_type read_internal_n(std::size_t count, TIter &iter, std::size_t len, field_elem_tag) {
                        clear();
                        while (0 < count) {
                            auto &elem = create_back();
                            status_type es = read_element(elem, iter, len);
                            if (es != status_type::success) {
                                value_.pop_back();
                                return es;
                            }

                            --count;
                        }

                        return status_type::success;
                    }

                    template<typename TIter>
                    status_type read_internal_n(std::size_t count, TIter &iter, std::size_t len, raw_data_tag) {
                        if (len < count) {
                            return status_type::not_enough_data;
                        }

                        return read_internal(iter, count, raw_data_tag());
                    }

                    template<typename TIter>
                    void read_no_status_internal_n(std::size_t count, TIter &iter, field_elem_tag) {
                        clear();
                        while (0 < count) {
                            auto &elem = create_back();
                            read_element_no_status(elem, iter);
                            --count;
                        }
                    }

                    template<typename TIter>
                    void read_no_status_internal_n(std::size_t count, TIter &iter, raw_data_tag) {
                        read_internal(iter, count, raw_data_tag());
                    }

                    bool update_elem_version(element_type &elem, version_dependent_tag) {
                        return elem.set_version(version_base_impl::version_);
                    }

                    static constexpr bool update_elem_version(element_type &, no_version_dependency_tag) {
                        return false;
                    }

                    bool set_version_internal(version_type version, version_dependent_tag) {
                        version_base_impl::version_ = version;
                        bool updated = false;
                        for (auto &elem : value()) {
                            updated = elem.set_version(version) || updated;
                        }

                        return updated;
                    }

                    static constexpr bool set_version_internal(version_type, no_version_dependency_tag) {
                        return false;
                    }

                    value_type value_;
                };
            }        // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BASIC_ARRAY_LIST_HPP
