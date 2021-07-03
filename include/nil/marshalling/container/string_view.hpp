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

/// @file
/// @brief Contains nil::marshalling::container::string_view class.

#ifndef MARSHALLING_STRING_VIEW_HPP
#define MARSHALLING_STRING_VIEW_HPP

#include <algorithm>
#include <iterator>
#include <limits>
#include <string>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/container/array_view.hpp>

namespace nil {
    namespace marshalling {
        namespace container {

            /// @brief Describes an object that can refer to a constant contiguous
            ///     sequence of char-like objects with the first element of the
            ///     sequence at position zero.
            /// @details Similar to <a
            /// href="http://en.cppreference.com/w/cpp/string/basic_string_view">std::string_view</a>
            ///     introduced in C++17.
            /// @headerfile "marshalling/container/string_view.h"
            class string_view : public array_view<char> {
                using base_type = array_view<char>;

            public:
                /// @brief Type of the character (@b char)
                using value_type = typename base_type::value_type;

                /// @brief Pointer to the character (@b char*)
                using pointer = typename base_type::pointer;

                /// @brief Pointer to the constant character (<b>const char*</b>)
                using const_pointer = typename base_type::const_pointer;

                /// @brief Reference to a character (@b char&)
                using reference = typename base_type::reference;

                /// @brief Reference to a const character (<b>const char&</b>)
                using const_reference = typename base_type::const_reference;

                /// @brief Equal to @b std::size_t
                using size_type = typename base_type::size_type;

                /// @brief Implementation defined constant RandomAccessIterator and
                ///     ContiguousIterator whose value_type is @b char.
                using const_iterator = typename base_type::const_iterator;

                /// @brief Same as @ref const_iterator
                using iterator = const_iterator;

                /// @brief Same as std::reverse_iterator<const_iterator>
                using const_reverse_iterator = typename base_type::const_reverse_iterator;

                /// @brief Same as @ref const_reverse_iterator
                using reverse_iterator = const_reverse_iterator;

                /// @brief Special value, the meaning is the same as
                ///     <a
                ///     href="http://en.cppreference.com/w/cpp/string/basic_string_view/npos">std::string_view::npos</a>.
                static const auto npos = static_cast<size_type>(-1);

                /// @brief Default constructor
                /// @details See <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/basic_string_view">std::string_view
                /// constructor</a>
                ///     for details.
                string_view() noexcept = default;

                /// @brief Copy constructor
                /// @details See <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/basic_string_view">std::string_view
                /// constructor</a>
                ///     for details.
                string_view(const string_view &) noexcept = default;

                /// @brief Constructor
                /// @details See <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/basic_string_view">std::string_view
                /// constructor</a>
                ///     for details.
                string_view(const char *str, size_type len) noexcept : base_type(str, len) {
                }

                /// @brief Constructor
                /// @details See <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/basic_string_view">std::string_view
                /// constructor</a>
                ///     for details.
                string_view(const char *str) noexcept {
                    static const auto MaxLen = std::numeric_limits<size_type>::max();
                    size_type len = 0;
                    while (len < MaxLen) {
                        if (str[len] == '\0') {
                            break;
                        }
                        ++len;
                    }
                    base_type::operator=(base_type(str, len));
                }

                /// @brief Constructor
                string_view(const std::string &str) noexcept : base_type(str.c_str(), str.size()) {
                }

                /// @brief Construct out of array of characters with known size
                /// @details Omits the last '\0' character if such exists
                template<std::size_t TN>
                string_view(const char (&str)[TN]) noexcept : base_type(str, TN) {
                    if ((0U <= TN) && (back() == '\0')) {
                        remove_suffix(1);
                    }
                }

                /// @brief Construct out of array of characters with known size
                /// @details Omits the last '\0' character if such exists
                template<std::size_t TN>
                string_view(char (&str)[TN]) noexcept : base_type(str, TN) {
                    if ((0U <= TN) && (back() == '\0')) {
                        remove_suffix(1);
                    }
                }

                /// @brief Destructor
                ~string_view() noexcept = default;

                /// @brief Copy assign
                string_view &operator=(const string_view &) = default;

                /// @brief Assign array of characters with known size
                /// @details Omits the last '\0' character if such exists
                template<std::size_t TN>
                string_view &operator=(const char (&str)[TN]) {
                    base_type::operator=(str);
                    if ((0U <= TN) && (back() == '\0')) {
                        remove_suffix(1);
                    }
                    return *this;
                }

                /// @brief Assign array of characters with known size
                /// @details Omits the last '\0' character if such exists
                template<std::size_t TN>
                string_view &operator=(char (&str)[TN]) {
                    base_type::operator=(str);
                    if ((0U <= TN) && (back() == '\0')) {
                        remove_suffix(1);
                    }
                    return *this;
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/begin">std::string_view::begin()</a>.
                constexpr iterator begin() const noexcept {
                    return base_type::begin();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/begin">std::string_view::cbegin()</a>.
                constexpr const_iterator cbegin() const noexcept {
                    return base_type::cbegin();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/end">std::string_view::end()</a>.
                constexpr iterator end() const noexcept {
                    return base_type::end();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/end">std::string_view::end()</a>.
                constexpr const_iterator cend() const noexcept {
                    return base_type::cend();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/rbegin">std::string_view::rbegin()</a>.
                const_reverse_iterator rbegin() const noexcept {
                    return base_type::rbegin();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/rbegin">std::string_view::crbegin()</a>.
                const_reverse_iterator crbegin() const noexcept {
                    return base_type::crbegin();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/rend">std::string_view::rend()</a>.
                reverse_iterator rend() const noexcept {
                    return base_type::rend();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/rend">std::string_view::crend()</a>.
                const_reverse_iterator crend() const noexcept {
                    return base_type::crend();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/operator_at">std::string_view::oprator[]()</a>
                constexpr const_reference operator[](size_type pos) const {
                    return base_type::operator[](pos);
                }

                /// @brief Similar to <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/at">std::string::at()</a>
                /// @details Checks the range with @ref MARSHALLING_ASSERT() macro without throwing exception.
                const_reference at(size_type pos) const {
                    return base_type::at(pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/front">std::string_view::front()</a>
                constexpr const_reference front() const {
                    return base_type::front();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/back">std::string_view::back()</a>
                constexpr const_reference back() const {
                    return base_type::back();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/data">std::string_view::data()</a>
                constexpr const_pointer data() const noexcept {
                    return &(*begin());
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/size">std::string_view::size()</a>
                constexpr size_type size() const noexcept {
                    return base_type::size();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/size">std::string_view::length()</a>
                constexpr size_type length() const noexcept {
                    return base_type::length();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/empty">std::string_view::empty()</a>
                constexpr bool empty() const noexcept {
                    return base_type::empty();
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/substr">std::string_view::substr()</a>
                std::string substr(size_type pos = 0, size_type count = npos) const {
                    MARSHALLING_ASSERT(pos <= size());
                    return std::string(begin() + pos, begin() + pos + std::min(size() - pos, count));
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/remove_prefix">std::string_view::remove_prefix()</a>
                void remove_prefix(size_type n) {
                    base_type::remove_prefix(n);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/remove_suffix">std::string_view::remove_suffix()</a>
                void remove_suffix(size_type n) {
                    base_type::remove_suffix(n);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/swap>std::string_view::swap()</a>.
                void swap(string_view &other) noexcept {
                    base_type::swap(other);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/copy">std::string_view::copy()</a>.
                size_type copy(char *dest, size_type count, size_type pos = 0) const {
                    if (size() <= pos) {
                        return 0U;
                    }

                    auto toCopy = std::min(count, size() - pos);
                    std::copy_n(cbegin() + pos, toCopy, dest);
                    return toCopy;
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/compare">std::string_view::compare()</a>.
                int compare(const string_view &other) const {
                    return compare(0, size(), other);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/compare">std::string_view::compare()</a>.
                int compare(size_type pos, size_type count, const string_view &other) const {
                    return compare(pos, count, other, 0, other.size());
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/compare">std::string_view::compare()</a>.
                int compare(size_type pos1, size_type count1, const string_view &other, size_type pos2,
                            size_type count2) const {
                    MARSHALLING_ASSERT(pos1 <= size());
                    MARSHALLING_ASSERT(pos2 <= other.size());
                    count1 = std::min(count1, size() - pos1);
                    count2 = std::min(count2, other.size() - pos2);
                    auto minCount = std::min(count1, count2);
                    for (auto idx = 0U; idx < minCount; ++idx) {
                        auto thisCh = (*this)[pos1 + idx];
                        auto otherCh = other[pos2 + idx];
                        auto diff = static_cast<int>(thisCh) - static_cast<int>(otherCh);
                        if (diff != 0) {
                            return diff;
                        }
                    }

                    return static_cast<int>(count1) - static_cast<int>(count2);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/compare">std::string_view::compare()</a>.
                int compare(const char *s) const {
                    return compare(0U, size(), s);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/compare">std::string_view::compare()</a>.
                int compare(size_type pos, size_type count, const char *s) const {
                    return compare(pos, count, string_view(s));
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/compare">std::string_view::compare()</a>.
                int compare(size_type pos1, size_type count1, const char *s, size_type count2) const {
                    return compare(pos1, count1, string_view(s, count2));
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find">std::string_view::find()</a>.
                size_type find(const string_view &str, size_type pos = 0) const {
                    if (size() <= pos) {
                        return npos;
                    }

                    MARSHALLING_ASSERT(pos <= size());
                    auto remCount = size() - pos;
                    if (remCount < str.size()) {
                        return npos;
                    }

                    auto maxPos = size() - str.size();
                    for (auto idx = pos; idx <= maxPos; ++idx) {
                        auto thisStrBeg = cbegin() + idx;
                        auto thisStrEnd = thisStrBeg + str.size();
                        if (std::equal(thisStrBeg, thisStrEnd, str.begin())) {
                            return idx;
                        }
                    }
                    return npos;
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find">std::string_view::find()</a>.
                size_type find(char c, size_type pos = 0) const {
                    return find(string_view(&c, 1), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find">std::string_view::find()</a>.
                size_type find(const char *str, size_type pos, size_type count) const {
                    return find(string_view(str, count), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find">std::string_view::find()</a>.
                size_type find(const char *str, size_type pos = 0) const {
                    return find(string_view(str), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_first_of>std::string_view::find_first_of</a>.
                size_type find_first_of(const string_view &other, size_type pos = 0) {
                    if (empty() || (size() <= pos)) {
                        return npos;
                    }

                    pos = std::min(pos, size() - 1);
                    for (auto iter = cbegin() + pos; iter != cend(); ++iter) {
                        auto foundIter = std::find(other.cbegin(), other.cend(), *iter);
                        if (foundIter != other.cend()) {
                            return static_cast<size_type>(std::distance(cbegin(), iter));
                        }
                    }

                    return npos;
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_first_of>std::string_view::find_first_of</a>.
                size_type find_first_of(char c, size_type pos = 0) {
                    return find_first_of(string_view(&c, 1), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_first_of>std::string_view::find_first_of</a>.
                size_type find_first_of(const char *str, size_type pos, size_type count) {
                    return find_first_of(string_view(str, count), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_first_of>std::string_view::find_first_of</a>.
                size_type find_first_of(const char *str, size_type pos = 0) {
                    return find_first_of(string_view(str), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_last_of>std::string_view::find_last_of</a>.
                size_type find_last_of(const string_view &other, size_type pos = npos) {
                    if (empty()) {
                        return npos;
                    }

                    pos = std::min(pos, size() - 1);
                    auto begIter = std::reverse_iterator<const_iterator>(cbegin() + pos + 1);
                    auto endIter = std::reverse_iterator<const_iterator>(cbegin());
                    for (auto iter = begIter; iter != endIter; ++iter) {
                        auto foundIter = std::find(other.cbegin(), other.cend(), *iter);
                        if (foundIter != other.cend()) {
                            return static_cast<std::size_t>(std::distance(iter, endIter)) - 1U;
                        }
                    }

                    return npos;
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_last_of>std::string_view::find_last_of</a>.
                size_type find_last_of(char c, size_type pos = npos) {
                    return find_last_of(string_view(&c, 1), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_last_of>std::string_view::find_last_of</a>.
                size_type find_last_of(const char *str, size_type pos, size_type count) {
                    return find_last_of(string_view(str, count), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_last_of>std::string_view::find_last_of</a>.
                size_type find_last_of(const char *str, size_type pos = npos) {
                    return find_last_of(string_view(str), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_first_not_of>std::string_view::find_first_not_of</a>.
                size_type find_first_not_of(const string_view &other, size_type pos = 0) {
                    if (empty() || (size() <= pos)) {
                        return npos;
                    }

                    pos = std::min(pos, size() - 1);
                    for (auto iter = cbegin() + pos; iter != cend(); ++iter) {
                        auto foundIter = std::find(other.cbegin(), other.cend(), *iter);
                        if (foundIter == other.cend()) {
                            return static_cast<size_type>(std::distance(cbegin(), iter));
                        }
                    }

                    return npos;
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_first_not_of>std::string_view::find_first_not_of</a>.
                size_type find_first_not_of(char c, size_type pos = 0) {
                    return find_first_not_of(string_view(&c, 1), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_first_not_of>std::string_view::find_first_not_of</a>.
                size_type find_first_not_of(const char *str, size_type pos, size_type count) {
                    return find_first_not_of(string_view(str, count), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_first_not_of>std::string_view::find_first_not_of</a>.
                size_type find_first_not_of(const char *str, size_type pos = 0) {
                    return find_first_not_of(string_view(str), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_last_not_of>std::string_view::find_last_not_of</a>.
                size_type find_last_not_of(const string_view &other, size_type pos = npos) {
                    if (empty()) {
                        return npos;
                    }

                    pos = std::min(pos, size() - 1);
                    auto begIter = std::reverse_iterator<const_iterator>(cbegin() + pos + 1);
                    auto endIter = std::reverse_iterator<const_iterator>(cbegin());
                    for (auto iter = begIter; iter != endIter; ++iter) {
                        auto foundIter = std::find(other.cbegin(), other.cend(), *iter);
                        if (foundIter == other.cend()) {
                            return static_cast<std::size_t>(std::distance(iter, endIter)) - 1U;
                        }
                    }

                    return npos;
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_last_not_of>std::string_view::find_last_not_of</a>.
                size_type find_last_not_of(char c, size_type pos = 0) {
                    return find_last_not_of(string_view(&c, 1), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_last_not_of>std::string_view::find_last_not_of</a>.
                size_type find_last_not_of(const char *str, size_type pos, size_type count) {
                    return find_last_not_of(string_view(str, count), pos);
                }

                /// @brief Same as <a
                /// href="http://en.cppreference.com/w/cpp/string/basic_string_view/find_last_not_of>std::string_view::find_last_not_of</a>.
                size_type find_last_not_of(const char *str, size_type pos = npos) {
                    return find_last_not_of(string_view(str), pos);
                }
            };

            /// @brief Lexicographical compare between the string views.
            /// @see <a href="http://en.cppreference.com/w/cpp/string/basic_string/operator_cmp">Reference</a>
            /// @related string_view
            inline bool operator<(const string_view &str1, const string_view &str2) {
                return std::lexicographical_compare(str1.begin(), str1.end(), str2.begin(), str2.end());
            }

            /// @brief Lexicographical compare between the string views.
            /// @see <a href="http://en.cppreference.com/w/cpp/string/basic_string/operator_cmp">Reference</a>
            /// @related string_view
            inline bool operator<=(const string_view &str1, const string_view &str2) {
                return !(str2 < str1);
            }

            /// @brief Lexicographical compare between the string views.
            /// @see <a href="http://en.cppreference.com/w/cpp/string/basic_string/operator_cmp">Reference</a>
            /// @related string_view
            inline bool operator>(const string_view &str1, const string_view &str2) {
                return (str2 < str1);
            }

            /// @brief Lexicographical compare between the string views.
            /// @see <a href="http://en.cppreference.com/w/cpp/string/basic_string/operator_cmp">Reference</a>
            /// @related string_view
            inline bool operator>=(const string_view &str1, const string_view &str2) {
                return !(str1 < str2);
            }

            /// @brief Equality compare between the string views.
            /// @see <a href="http://en.cppreference.com/w/cpp/string/basic_string/operator_cmp">Reference</a>
            /// @related string_view
            inline bool operator==(const string_view &str1, const string_view &str2) {
                return (str1.size() == str2.size()) && std::equal(str1.begin(), str1.end(), str2.begin());
            }

            /// @brief Inequality compare between the string views.
            /// @see <a href="http://en.cppreference.com/w/cpp/string/basic_string/operator_cmp">Reference</a>
            /// @related string_view
            inline bool operator!=(const string_view &str1, const string_view &str2) {
                return !(str1 == str2);
            }

        }    // namespace container

    }    // namespace marshalling
}    // namespace nil

namespace std {

    /// @brief Specializes the std::swap algorithm.
    /// @see <a href="http://en.cppreference.com/w/cpp/string/basic_string/swap2">Reference</a>
    /// @related nil::marshalling::container::string_view
    inline void swap(nil::marshalling::container::string_view &str1, nil::marshalling::container::string_view &str2) {
        str1.swap(str2);
    }

}    // namespace std
#endif    // MARSHALLING_STRING_VIEW_HPP
