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
/// @brief Contains nil::marshalling::container::array_view class.

#ifndef MARSHALLING_ARRAY_VIEW_HPP
#define MARSHALLING_ARRAY_VIEW_HPP

#include <algorithm>
#include <iterator>

#include <nil/marshalling/assert_type.hpp>

namespace nil {
    namespace marshalling {
        namespace container {

            /// @brief Describes an object that can refer to a constant contiguous
            ///     sequence of other objects.
            /// @details Provides "view" on the original data.
            /// @headerfile "marshalling/container/array_view.h"
            template<typename T>
            class array_view {
            public:
                /// @brief Type of the single element
                using value_type = T;

                /// @brief Pointer to the single element (@b T*)
                using pointer = T *;

                /// @brief Pointer to the constant element (<b>const T*</b>)
                using const_pointer = const T *;

                /// @brief Reference to an element (@b T&)
                using reference = T &;

                /// @brief Reference to a const element (<b>const T&</b>)
                using const_reference = const T &;

                /// @brief Equal to @b std::size_t
                using size_type = std::size_t;

                /// @brief Implementation defined constant RandomAccessIterator and
                ///     ContiguousIterator whose value_type is @b T.
                using const_iterator = const_pointer;

                /// @brief Same as @ref const_iterator
                using iterator = const_iterator;

                /// @brief Same as std::reverse_iterator<const_iterator>
                using const_reverse_iterator = std::reverse_iterator<const_iterator>;

                /// @brief Same as @ref const_reverse_iterator
                using reverse_iterator = const_reverse_iterator;

                /// @brief Default constructor
                array_view() noexcept = default;

                /// @brief Copy constructor
                array_view(const array_view &) noexcept = default;

                /// @brief Constructor
                array_view(const_pointer data, size_type len) noexcept : data_(data), len_(len) {
                }

                /// @brief Construct out of array of elements with known size
                template<std::size_t TN>
                array_view(const T (&data)[TN]) noexcept : data_(data), len_(TN) {
                }

                /// @brief Construct out of array of elements with known size
                template<std::size_t TN>
                array_view(T (&data)[TN]) noexcept : data_(data), len_(TN) {
                }

                /// @brief Destructor
                ~array_view() noexcept = default;

                /// @brief Copy assign
                array_view &operator=(const array_view &) = default;

                /// @brief Assign array of elements with known size
                template<std::size_t TN>
                array_view &operator=(const T (&data)[TN]) {
                    data_ = data;
                    len_ = TN;
                    return *this;
                }

                /// @brief Assign array of elements with known size
                template<std::size_t TN>
                array_view &operator=(T (&data)[TN]) {
                    data_ = data;
                    len_ = TN;
                    return *this;
                }

                /// @brief Iterator to begining of the sequence.
                constexpr const_iterator begin() const noexcept {
                    return data_;
                }

                /// @brief Iterator to begining of the sequence.
                constexpr const_iterator cbegin() const noexcept {
                    return begin();
                }

                /// @brief Iterator to the end of the sequence
                constexpr const_iterator end() const noexcept {
                    return begin() + len_;
                }

                /// @brief Iterator to the end of the sequence
                constexpr const_iterator cend() const noexcept {
                    return end();
                }

                /// @brief Reverse iterator to the end of the sequence.
                const_reverse_iterator rbegin() const noexcept {
                    return std::reverse_iterator<const_iterator>(end());
                }

                /// @brief Reverse iterator to the end of the sequence.
                const_reverse_iterator crbegin() const noexcept {
                    return rbegin();
                }

                /// @brief Reverse iterator to the beginning of the sequence.
                reverse_iterator rend() const noexcept {
                    return std::reverse_iterator<const_iterator>(begin());
                }

                /// @brief Reverse iterator to the beginning of the sequence.
                const_reverse_iterator crend() const noexcept {
                    return rend();
                }

                /// @brief Element access operator
                constexpr const_reference operator[](size_type pos) const {
                    return data_[pos];
                }

                /// @brief Element access with range check
                /// @details Checks the range with @ref MARSHALLING_ASSERT() macro without throwing exception.
                const_reference at(size_type pos) const {
                    MARSHALLING_ASSERT(pos < len_);
                    return data_[pos];
                }

                /// @brief Access the first element
                /// @pre The view is not empty
                constexpr const_reference front() const {
                    return data_[0];
                }

                /// @brief Access the last element
                /// @pre The view is not empty
                constexpr const_reference back() const {
                    return data_[len_ - 1U];
                }

                /// @brief Get number of element in the view.
                constexpr size_type size() const noexcept {
                    return len_;
                }

                /// @brief Same as ref size()
                constexpr size_type length() const noexcept {
                    return size();
                }

                /// @brief Check the view is empty
                /// @return @b true if and only if call to @ref size() returns @b 0.
                constexpr bool empty() const noexcept {
                    return size() == 0U;
                }

                /// @brief Narrow the view by skipping number of elements at the beginning.
                /// @pre @b n is less or equal to value returned by @ref size().
                void remove_prefix(size_type n) {
                    std::advance(data_, n);
                    len_ -= n;
                }

                /// @brief Narrow the view by dropping number of elements at the end.
                /// @pre @b n is less or equal to value returned by @ref size().
                void remove_suffix(size_type n) {
                    len_ -= n;
                }

                /// @brief Swap contents of two views
                void swap(array_view &other) noexcept {
                    std::swap(data_, other.data_);
                    std::swap(len_, other.len_);
                }

            private:
                const_pointer data_ = nullptr;
                size_type len_ = 0;
            };

            /// @brief Lexicographical compare between the views.
            /// @related ArrayView
            template<typename T>
            bool operator<(const array_view<T> &view1, const array_view<T> &view2) {
                return std::lexicographical_compare(view1.begin(), view1.end(), view2.begin(), view2.end());
            }

            /// @brief Lexicographical compare between the views.
            /// @related ArrayView
            template<typename T>
            bool operator<=(const array_view<T> &view1, const array_view<T> &view2) {
                return !(view2 < view1);
            }

            /// @brief Lexicographical compare between the views.
            /// @related ArrayView
            template<typename T>
            bool operator>(const array_view<T> &view1, const array_view<T> &view2) {
                return (view2 < view1);
            }

            /// @brief Lexicographical compare between the views.
            /// @related ArrayView
            template<typename T>
            bool operator>=(const array_view<T> &view1, const array_view<T> &view2) {
                return !(view1 < view2);
            }

            /// @brief Equality compare between the views.
            /// @related ArrayView
            template<typename T>
            bool operator==(const array_view<T> &view1, const array_view<T> &view2) {
                return (view1.size() == view2.size()) && std::equal(view1.begin(), view1.end(), view2.begin());
            }

            /// @brief Inequality compare between the views.
            /// @related ArrayView
            template<typename T>
            bool operator!=(const array_view<T> &view1, const array_view<T> &view2) {
                return !(view1 == view2);
            }

        }    // namespace container
    }    // namespace marshalling
}    // namespace nil

namespace std {

    /// @brief Specializes the std::swap algorithm.
    /// @related nil::marshalling::container::ArrayView
    template<typename T>
    void swap(nil::marshalling::container::array_view<T> &view1, nil::marshalling::container::array_view<T> &view2) {
        view1.swap(view2);
    }

}    // namespace std
#endif    // MARSHALLING_ARRAY_VIEW_HPP
