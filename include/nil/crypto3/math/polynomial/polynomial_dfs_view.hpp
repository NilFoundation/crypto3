//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef CRYPTO3_MATH_POLYNOMIAL_POLYNOM_DFS_VIEW_HPP
#define CRYPTO3_MATH_POLYNOMIAL_POLYNOM_DFS_VIEW_HPP

#include <algorithm>
#include <vector>

#include <nil/crypto3/math/polynomial/basic_operations.hpp>
#include <string_view>

namespace nil {
    namespace crypto3 {
        namespace math {

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
            class polynomial_dfs_view {
            public:
                // constants and types
                using element_type = FieldValueType;

                typedef std::vector<element_type, Allocator> container_type;
                typedef typename container_type::value_type value_type;
                typedef typename container_type::allocator_type allocator_type;
                typedef typename container_type::reference reference;
                typedef typename container_type::const_reference const_reference;
                typedef typename container_type::size_type size_type;
                typedef typename container_type::difference_type difference_type;
                typedef typename container_type::pointer pointer;
                typedef typename container_type::const_pointer const_pointer;
                typedef typename container_type::iterator iterator;
                typedef typename container_type::const_iterator const_iterator;
                typedef typename container_type::reverse_iterator reverse_iterator;
                typedef typename container_type::const_reverse_iterator const_reverse_iterator;

                std::vector<element_type> &it;
                size_t _d;

                polynomial_dfs_view(size_t d, std::vector<element_type>& vec) : it(vec), _d(d) {
                }

                polynomial_dfs_view(polynomial_dfs_view&& x)
                    BOOST_NOEXCEPT(std::is_nothrow_move_constructible<allocator_type>::value) :
                    it(x.it),
                    _d(x._d) {
                }

                ~polynomial_dfs_view() = default;

                polynomial_dfs_view(const polynomial_dfs_view& x) : it(x.it), _d(x._d) {
                }

                polynomial_dfs_view& operator=(const polynomial_dfs_view& x) {
                    it = x.it;
                    _d = x._d;
                    return *this;
                }

                polynomial_dfs_view& operator=(polynomial_dfs_view&& x) {
                    it == x.it;
                    _d = x._d;
                    return *this;
                }

                //                polynomial_dfs& operator=(const container_type& x) {
                //                    val = x;
                //                    return *this;
                //                }
                //
                //                polynomial_dfs& operator=(container_type&& x) {
                //                    val = x;
                //                    return *this;
                //                }

                //                polynomial_dfs& operator=(std::initializer_list<value_type> il) {
                //                    val.assign(il.begin(), il.end());
                //                    return *this;
                //                }

                bool operator==(const polynomial_dfs_view& rhs) const {
                    return (*it) == (*(rhs.it)) && _d == rhs.d;
                }
                bool operator!=(const polynomial_dfs_view& rhs) const {
                    return !(rhs == *this);
                }

                template<typename InputIterator>
                void assign(InputIterator first, InputIterator last) {
                    it.assign(first, last);
                }

                void assign(size_type n, const_reference u) {
                    it.assign(n, u);
                }

                void assign(std::initializer_list<value_type> il) {
                    assign(il.begin(), il.end());
                }

                iterator begin() BOOST_NOEXCEPT {
                    return it.begin();
                }

                const_iterator begin() const BOOST_NOEXCEPT {
                    return it.begin();
                }
                iterator end() BOOST_NOEXCEPT {
                    return it.end();
                }
                const_iterator end() const BOOST_NOEXCEPT {
                    return it.end();
                }

                reverse_iterator rbegin() BOOST_NOEXCEPT {
                    return it.rbegin();
                }

                const_reverse_iterator rbegin() const BOOST_NOEXCEPT {
                    return it.rbegin();
                }

                reverse_iterator rend() BOOST_NOEXCEPT {
                    return reverse_iterator(begin());
                }

                const_reverse_iterator rend() const BOOST_NOEXCEPT {
                    return const_reverse_iterator(begin());
                }

                const_iterator cbegin() const BOOST_NOEXCEPT {
                    return begin();
                }

                const_iterator cend() const BOOST_NOEXCEPT {
                    return end();
                }

                const_reverse_iterator crbegin() const BOOST_NOEXCEPT {
                    return rbegin();
                }

                const_reverse_iterator crend() const BOOST_NOEXCEPT {
                    return rend();
                }

                size_type size() const BOOST_NOEXCEPT {
                    return it.size();
                }

                size_type degree() const BOOST_NOEXCEPT {
                    return _d;
                }

                size_type max_degree() const BOOST_NOEXCEPT {
                    return this->size();
                }

                size_type capacity() const BOOST_NOEXCEPT {
                    return it.capacity();
                }
                bool empty() const BOOST_NOEXCEPT {
                    return it.empty();
                }
                size_type max_size() const BOOST_NOEXCEPT {
                    return it.max_size();
                }
                void reserve(size_type _n) {
                    return it.reserve(_n);
                }
                void shrink_to_fit() BOOST_NOEXCEPT {
                    return it.shrink_to_fit();
                }

                reference operator[](size_type _n) BOOST_NOEXCEPT {
                    return it[_n];
                }
                const_reference operator[](size_type _n) const BOOST_NOEXCEPT {
                    return it[_n];
                }
                reference at(size_type _n) {
                    return it.at(_n);
                }
                const_reference at(size_type _n) const {
                    return it.at(_n);
                }

                reference front() BOOST_NOEXCEPT {
                    return it.front();
                }
                const_reference front() const BOOST_NOEXCEPT {
                    return it.front();
                }
                reference back() BOOST_NOEXCEPT {
                    return it.back();
                }
                const_reference back() const BOOST_NOEXCEPT {
                    return it.back();
                }

                value_type* data() BOOST_NOEXCEPT {
                    return it.data();
                }

                const value_type* data() const BOOST_NOEXCEPT {
                    return it.data();
                }

                void push_back(const_reference _x) {
                    it.push_back(_x);
                }

                void push_back(value_type&& _x) {
                    it.push_back(_x);
                }

                template<class... Args>
                reference emplace_back(Args&&... _args) {
                    return it.template emplace_back(_args...);
                }

                void pop_back() {
                    it.pop_back();
                }

                iterator insert(const_iterator _position, const_reference _x) {
                    return it.insert(_position, _x);
                }

                iterator insert(const_iterator _position, value_type&& _x) {
                    return it.insert(_position, _x);
                }
                template<class... Args>
                iterator emplace(const_iterator _position, Args&&... _args) {
                    return it.template emplace(_position, _args...);
                }

                iterator insert(const_iterator _position, size_type _n, const_reference _x) {
                    return it.insert(_position, _n, _x);
                }

                template<class InputIterator>
                iterator insert(const_iterator _position, InputIterator _first, InputIterator _last) {
                    return it.insert(_position, _first, _last);
                }

                iterator insert(const_iterator _position, std::initializer_list<value_type> _il) {
                    return insert(_position, _il.begin(), _il.end());
                }

                iterator erase(const_iterator _position) {
                    return it.erase(_position);
                }

                iterator erase(const_iterator _first, const_iterator _last) {
                    return it.erase(_first, _last);
                }

                void clear() BOOST_NOEXCEPT {
                    it.clear();
                }

                void resize(size_type _sz) {
                    BOOST_ASSERT_MSG(_sz >= _d, "Can't restore polynomial in the future");
                    typedef typename value_type::field_type FieldType;

                    value_type omega = unity_root<FieldType>(this->size());

                    detail::basic_radix2_fft<FieldType>(it, omega.inversed());

                    const value_type sconst = value_type(this->size()).inversed();
                    std::transform(it.begin(),
                                   it.end(),
                                   it.begin(),
                                   std::bind(std::multiplies<value_type>(), sconst, std::placeholders::_1));

                    value_type omega_new = unity_root<FieldType>(_sz);
                    it.resize(_sz);

                    detail::basic_radix2_fft<FieldType>(it, omega_new);
                }

                //                void resize(size_type _sz, const_reference _x) {
                //                    BOOST_ASSERT_MSG(_sz >= _d, "Can't restore polynomial in the future");
                //                    return val.resize(_sz, _x);
                //                }

                void swap(polynomial_dfs_view& other) {
                    it.swap(other.val);
                    std::swap(_d, other._d);
                }

                //                std::vector<FieldValueType> evaluate(const std::vector<FieldValueType>& value) const {
                //                    typedef typename value_type::field_type FieldType;
                //                    const std::size_t n = detail::power_of_two(this->_d);
                //
                //                    std::vector<FieldValueType> c(this->begin(), this->begin() + n);
                //
                //                    detail::basic_radix2_fft<FieldType>(c, (this->_omega).inversed());
                //
                //                    std::vector<FieldValueType> result(value.size(), 0);
                //                    auto end = c.end();
                //                    while (end != c.begin()) {
                //                        for (size_t i = 0; i < value.size(); ++i) {
                //                            result[i] = result[i] * value[i] + *--end;
                //                        }
                //                    }
                //                    return result;
                //                }

                FieldValueType evaluate(const FieldValueType& value) const {

                    typedef typename value_type::field_type FieldType;

                    std::vector<FieldValueType> tmp = this->coefficients();
                    FieldValueType result = 0;
                    auto end = tmp.end();
                    while (end != tmp.begin()) {
                        result = result * value + *--end;
                    }
                    return result;
                }

                /**
                 * Returns true if polynomial is a zero polynomial.
                 */
                bool is_zero() const {
                    return _d == 0;
                }

                /**
                 * Compute the reverse polynomial up to vector size n (degree n-1).
                 * Below we make use of the reversal endomorphism definition from
                 * [Bostan, Lecerf, & Schost, 2003. Tellegen's Principle in Practice, on page 38].
                 */
                void reverse(std::size_t n) {
                    std::reverse(this->begin(), this->end());
                    this->resize(n);
                }
                /**
                 * Computes the standard polynomial addition, polynomial A + polynomial B, and stores result in
                 * polynomial C.
                 */
                polynomial_dfs_view operator+=(const polynomial_dfs_view& other) {
                    this->_d = std::max(this->_d, other._d);
                    if (other.size() > this->size()) {
                        this->resize(other.size());
                    }
                    if (this->size() > other.size()) {
                        polynomial_dfs_view tmp(other);
                        tmp.resize(this->size());
                        std::transform(tmp.begin(), tmp.end(), this->begin(), this->begin(),
                                       std::plus<FieldValueType>());
                        return *this;
                    }
                    std::transform(other.begin(), other.end(), this->begin(), this->begin(),
                                   std::plus<FieldValueType>());
                    return *this;
                }

                void neg() const {
                    std::transform(this->begin(), this->end(), this->begin(), std::negate<FieldValueType>());
                }

                /**
                 * Computes the standard polynomial subtraction, polynomial A - polynomial B, and stores result in
                 * polynomial C.
                 */
                polynomial_dfs_view operator-=(const polynomial_dfs_view& other) {
                    this->_d = std::max(this->_d, other._d);
                    if (other.size() > this->size()) {
                        this->resize(other.size());
                    }
                    if (this->size() > other.size()) {
                        polynomial_dfs_view tmp(other);
                        tmp.resize(this->size());
                        std::transform(this->begin(), this->end(), tmp.begin(), this->begin(),
                                       std::minus<FieldValueType>());
                        return *this;
                    }
                    std::transform(this->begin(), this->end(), other.begin(), this->begin(),
                                   std::minus<FieldValueType>());
                    return *this;
                }

                /**
                 * Perform the multiplication of two polynomials, polynomial A * polynomial B, and stores result in
                 * polynomial C.
                 */
                polynomial_dfs_view operator*=(const polynomial_dfs_view& other) {
                    this->_d = this->_d + other._d;
                    size_t polynomial_s =
                        detail::power_of_two(std::max({this->size(), other.size(), this->_d + other._d + 1}));
                    if (this->size() < polynomial_s) {
                        this->resize(polynomial_s);
                    }
                    if (other.size() < polynomial_s) {
                        polynomial_dfs_view tmp(other);
                        tmp.resize(polynomial_s);
                        std::transform(this->begin(), this->end(), tmp.begin(), this->begin(),
                                       std::multiplies<FieldValueType>());
                        return *this;
                    }
                    std::transform(other.begin(), other.end(), this->begin(), this->begin(),
                                   std::multiplies<FieldValueType>());
                    return *this;
                }

                /**
                 * Perform the standard Euclidean Division algorithm.
                 * Input: Polynomial A, Polynomial B, where A / B
                 * Output: Polynomial Q, such that A = (Q * B) + R.
                 */
                polynomial_dfs_view operator/=(const polynomial_dfs_view& other) {
                    std::vector<FieldValueType> x = this->coefficients();
                    std::vector<FieldValueType> y = other.coefficients();
                    std::vector<FieldValueType> r, q;
                    division(q, r, x, y);
                    std::size_t new_s = q.size();

                    typedef typename value_type::field_type FieldType;
                    size_t n = this->size();
                    value_type omega = unity_root<FieldType>(n);
                    q.resize(n);
                    detail::basic_radix2_fft<FieldType>(q, omega);
                    this->_d = new_s - 1;
                    this->assign(q.begin(), q.end());
                    return *this;
                }

                /**
                 * Perform the standard Euclidean Division algorithm.
                 * Input: Polynomial A, Polynomial B, where A / B
                 * Output: Polynomial R, such that A = (Q * B) + R.
                 */
                polynomial_dfs_view operator%=(const polynomial_dfs_view& other) {
                    std::vector<FieldValueType> x = this->coefficients();
                    std::vector<FieldValueType> y = other.coefficients();
                    std::vector<FieldValueType> r, q;
                    division(q, r, x, y);
                    std::size_t new_s = r.size();

                    typedef typename value_type::field_type FieldType;
                    size_t n = this->size();
                    value_type omega = unity_root<FieldType>(n);
                    r.resize(n);
                    detail::basic_radix2_fft<FieldType>(r, omega);
                    this->_d = new_s - 1;
                    this->assign(r.begin(), r.end());
                    return *this;
                }

                void from_coefficients(const container_type &tmp) {
                    typedef typename value_type::field_type FieldType;
                    size_t n = detail::power_of_two(tmp.size());
                    value_type omega = unity_root<FieldType>(n);
                    _d = tmp.size() - 1;
                    it.assign(tmp.begin(), tmp.end());
                    it.resize(n, FieldValueType::zero());
                    detail::basic_radix2_fft<FieldType>(it, omega);
                }

                std::vector<FieldValueType> coefficients() const {
                    typedef typename value_type::field_type FieldType;

                    value_type omega = unity_root<FieldType>(this->size());
                    std::vector<FieldValueType> tmp(this->begin(), this->end());

                    detail::basic_radix2_fft<FieldType>(tmp, omega.inversed());

                    const value_type sconst = value_type(this->size()).inversed();
                    std::transform(tmp.begin(),
                                   tmp.end(),
                                   tmp.begin(),
                                   std::bind(std::multiplies<value_type>(), sconst, std::placeholders::_1));
                    size_t r_size = tmp.size();
                    while (r_size > 0 && tmp[r_size - 1] == FieldValueType(0)) {
                        --r_size;
                    }
                    tmp.resize(r_size);
                    return tmp;
                }
            };
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_POLYNOMIAL_POLYNOM_DFS_VIEW_HPP
