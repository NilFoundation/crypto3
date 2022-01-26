//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MATH_POLYNOMIAL_POLYNOM_HPP
#define CRYPTO3_MATH_POLYNOMIAL_POLYNOM_HPP

#include <algorithm>
#include <vector>

#include <nil/crypto3/math/polynomial/basic_operations.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            namespace polynomial {

                template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
                class polynomial {
                    typedef std::vector<FieldValueType, Allocator> container_type;

                    container_type val;

                public:
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

                    polynomial() : val({0}) {
                    }

                    explicit polynomial(size_type n) : val(n) {
                    }
                    explicit polynomial(size_type n, const allocator_type& a) : val(n, a) {
                    }

                    polynomial(size_type n, const value_type& x) : val(n, x) {
                    }
                    polynomial(size_type n, const value_type& x, const allocator_type& a) : val(n, x, a) {
                    }
                    template<typename InputIterator>
                    polynomial(InputIterator first, InputIterator last) : val(first, last) {
                    }
                    template<typename InputIterator>
                    polynomial(InputIterator first, InputIterator last, const allocator_type& a) : val(first, last, a) {
                    }

                    ~polynomial() = default;

                    polynomial(const polynomial& x) : val(x.val) {
                    }
                    polynomial(const polynomial& x, const allocator_type& a) : val(x.val, a) {
                    }

                    polynomial(std::initializer_list<value_type> il) : val(il) {
                    }

                    polynomial(std::initializer_list<value_type> il, const allocator_type& a) : val(il, a) {
                    }

                    polynomial(polynomial&& x)
                        BOOST_NOEXCEPT(std::is_nothrow_move_constructible<allocator_type>::value) :
                        val(x.val) {
                    }

                    polynomial(polynomial&& x, const allocator_type& a) : val(x.val, a) {
                    }

                    polynomial(const FieldValueType& value, std::size_t power = 0) : val(power + 1, FieldValueType(0)) {
                        (*this)[power] = value;
                    }

                    polynomial& operator=(const polynomial& x) {
                        val = x.val;
                        return *this;
                    }

                    polynomial& operator=(polynomial&& x) {
                        val = x.val;
                        return *this;
                    }

                    polynomial& operator=(const container_type& x) {
                        val = x;
                        return *this;
                    }

                    polynomial& operator=(container_type&& x) {
                        val = x;
                        return *this;
                    }

                    polynomial& operator=(std::initializer_list<value_type> il) {
                        val.assign(il.begin(), il.end());
                        return *this;
                    }

                    bool operator==(const polynomial& rhs) const {
                        return val == rhs.val;
                    }
                    bool operator!=(const polynomial& rhs) const {
                        return !(rhs == *this);
                    }

                    template<typename InputIterator>
                    typename std::iterator_traits<InputIterator>::reference assign(InputIterator first,
                                                                                   InputIterator last) {
                        return val.assign(first, last);
                    }

                    void assign(size_type n, const_reference u) {
                        return val.assign(n, u);
                    }

                    void assign(std::initializer_list<value_type> il) {
                        assign(il.begin(), il.end());
                    }

                    allocator_type get_allocator() const BOOST_NOEXCEPT {
                        return this->val.__alloc();
                    }

                    iterator begin() BOOST_NOEXCEPT {
                        return val.begin();
                    }

                    const_iterator begin() const BOOST_NOEXCEPT {
                        return val.begin();
                    }
                    iterator end() BOOST_NOEXCEPT {
                        return val.end();
                    }
                    const_iterator end() const BOOST_NOEXCEPT {
                        return val.end();
                    }

                    reverse_iterator rbegin() BOOST_NOEXCEPT {
                        return val.rbegin();
                    }

                    const_reverse_iterator rbegin() const BOOST_NOEXCEPT {
                        return val.rbegin();
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
                        return val.size();
                    }

                    size_type capacity() const BOOST_NOEXCEPT {
                        return val.capacity();
                    }
                    bool empty() const BOOST_NOEXCEPT {
                        return val.empty();
                    }
                    size_type max_size() const BOOST_NOEXCEPT {
                        return val.max_size();
                    }
                    void reserve(size_type _n) {
                        return val.reserve(_n);
                    }
                    void shrink_to_fit() BOOST_NOEXCEPT {
                        return val.shrink_to_fit();
                    }

                    reference operator[](size_type _n) BOOST_NOEXCEPT {
                        return val[_n];
                    }
                    const_reference operator[](size_type _n) const BOOST_NOEXCEPT {
                        return val[_n];
                    }
                    reference at(size_type _n) {
                        return val.at(_n);
                    }
                    const_reference at(size_type _n) const {
                        return val.at(_n);
                    }

                    reference front() BOOST_NOEXCEPT {
                        return val.front();
                    }
                    const_reference front() const BOOST_NOEXCEPT {
                        return val.front();
                    }
                    reference back() BOOST_NOEXCEPT {
                        return val.back();
                    }
                    const_reference back() const BOOST_NOEXCEPT {
                        return val.back();
                    }

                    value_type* data() BOOST_NOEXCEPT {
                        return val.data();
                    }

                    const value_type* data() const BOOST_NOEXCEPT {
                        return val.data();
                    }

                    void push_back(const_reference _x) {
                        val.push_back(_x);
                    }

                    void push_back(value_type&& _x) {
                        val.push_back(_x);
                    }

                    template<class... _Args>
                    reference emplace_back(_Args&&... _args) {
                        return val.template emplace_back(_args...);
                    }

                    void pop_back() {
                        val.pop_back();
                    }

                    iterator insert(const_iterator _position, const_reference _x) {
                        return val.insert(_position, _x);
                    }

                    iterator insert(const_iterator _position, value_type&& _x) {
                        return val.insert(_position, _x);
                    }
                    template<class... _Args>
                    iterator emplace(const_iterator _position, _Args&&... _args) {
                        return val.template emplace(_position, _args...);
                    }

                    iterator insert(const_iterator _position, size_type _n, const_reference _x) {
                        return val.insert(_position, _n, _x);
                    }

                    template<class _InputIterator>
                    iterator insert(const_iterator _position, _InputIterator _first, _InputIterator _last) {
                        return val.insert(_position, _first, _last);
                    }

                    iterator insert(const_iterator _position, std::initializer_list<value_type> _il) {
                        return insert(_position, _il.begin(), _il.end());
                    }

                    iterator erase(const_iterator _position) {
                        return val.erase(_position);
                    }

                    iterator erase(const_iterator _first, const_iterator _last) {
                        return val.erase(_first, _last);
                    }

                    void clear() BOOST_NOEXCEPT {
                        val.clear();
                    }

                    void resize(size_type _sz) {
                        return val.resize(_sz);
                    }

                    void resize(size_type _sz, const_reference _x) {
                        return val.resize(_sz, _x);
                    }

                    void swap(polynomial& other) {
                        val.swap(other.val);
                    }

                    template<typename Range>
                    FieldValueType evaluate(const Range& values) const {

                        assert(values.size() + 1 == this->size());

                        FieldValueType result = (*this)[0];
                        for (std::size_t i = 0; i < values.size(); i++) {
                            result += (*this)[i + 1] * values[i];
                        }

                        return result;
                    }

                    FieldValueType evaluate(const FieldValueType& value) const {

                        FieldValueType result = 0;
                        for (std::size_t i = 0; i < this->size(); i++) {
                            result += (*this)[i] * value.pow(i);
                        }

                        return result;
                    }

                    /**
                     * Returns true if polynomial is a zero polynomial.
                     */
                    bool is_zero() const {
                        return std::all_of(this->begin(), this->end(),
                                           [](FieldValueType i) { return i == FieldValueType(0); });
                    }

                    /**
                     * Removes extraneous zero entries from in vector representation of polynomial.
                     * Example - Degree-4 Polynomial: [0, 1, 2, 3, 4, 0, 0, 0, 0] -> [0, 1, 2, 3, 4]
                     * Note: Simplest condensed form is a zero polynomial of vector form: [0]
                     */
                    void condense() {
                        while (std::distance(this->cbegin(), this->cend()) > 1 &&
                               this->back() == typename std::iterator_traits<decltype(std::begin(
                                                   std::declval<container_type>()))>::value_type()) {
                            this->pop_back();
                        }
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
                    polynomial operator+(const polynomial& other) const {
                        if (this->is_zero()) {
                            return other;
                        } else if (other.is_zero()) {
                            return *this;
                        } else {
                            polynomial result;

                            std::size_t a_size = std::distance(this->begin(), this->end());
                            std::size_t b_size = std::distance(other.begin(), other.end());

                            if (a_size > b_size) {
                                result.resize(a_size);
                                std::transform(other.begin(), other.end(), this->begin(), result.begin(),
                                               std::plus<FieldValueType>());
                                std::copy(this->begin() + b_size, this->end(), result.begin() + b_size);
                            } else {
                                result.resize(b_size);
                                std::transform(this->begin(), this->end(), other.begin(), result.begin(),
                                               std::plus<FieldValueType>());
                                std::copy(other.begin() + a_size, other.end(), result.begin() + a_size);
                            }

                            result.condense();

                            return result;
                        }
                    }

                    polynomial operator-() const {

                        polynomial result(this->size());
                        std::transform(this->begin(), this->end(), result.begin(), std::negate<FieldValueType>());

                        return result;
                    }

                    /**
                     * Computes the standard polynomial subtraction, polynomial A - polynomial B, and stores result in
                     * polynomial C.
                     */
                    polynomial operator-(const polynomial& other) const {
                        if (this->is_zero()) {
                            return -(other);
                        } else if (other.is_zero()) {
                            return *this;
                        } else {
                            polynomial result;

                            std::size_t a_size = std::distance(this->begin(), this->end());
                            std::size_t b_size = std::distance(other.begin(), other.end());

                            if (a_size > b_size) {
                                result.resize(a_size);
                                std::transform(this->begin(), this->begin() + b_size, other.begin(), result.begin(),
                                               std::minus<FieldValueType>());
                                std::copy(this->begin() + b_size, this->end(), result.begin() + b_size);
                            } else {
                                result.resize(b_size);
                                std::transform(this->begin(), this->end(), other.begin(), result.begin(),
                                               std::minus<FieldValueType>());
                                std::transform(other.begin() + a_size, other.end(), result.begin() + a_size,
                                               std::negate<FieldValueType>());
                            }

                            result.condense();

                            return result;
                        }
                    }

                    /**
                     * Perform the multiplication of two polynomials, polynomial A * polynomial B, and stores result in
                     * polynomial C.
                     */
                    polynomial operator*(const polynomial& other) const {
                        polynomial result;
                        multiplication_on_fft(result, *this, other);
                        return result;
                    }

                    /**
                     * Perform the standard Euclidean Division algorithm.
                     * Input: Polynomial A, Polynomial B, where A / B
                     * Output: Polynomial Q, such that A = (Q * B) + R.
                     */
                    polynomial operator/(const polynomial& other) const {

                        std::size_t d = other.size() - 1;           /* Degree of B */
                        FieldValueType c = other.back().inversed(); /* Inverse of Leading Coefficient of B */

                        polynomial r(*this);
                        polynomial q = polynomial(r.size(), FieldValueType::zero());

                        std::size_t r_deg = r.size() - 1;
                        std::size_t shift;

                        while (r_deg >= d && !r.is_zero()) {
                            if (r_deg >= d) {
                                shift = r_deg - d;
                            } else {
                                shift = 0;
                            }

                            FieldValueType lead_coeff = r.back() * c;

                            q[shift] += lead_coeff;

                            if (other.size() + shift + 1 > r.size()) {
                                r.resize(other.size() + shift + 1);
                            }
                            auto glambda = [=](const FieldValueType& x, const FieldValueType& y) {
                                return y - (x * lead_coeff);
                            };
                            std::transform(other.begin(), other.end(), r.begin() + shift, r.begin() + shift, glambda);
                            r.condense();

                            r_deg = r.size() - 1;
                        }
                        q.condense();

                        return q;
                    }

                    /**
                     * Perform the standard Euclidean Division algorithm.
                     * Input: Polynomial A, Polynomial B, where A / B
                     * Output: Polynomial R, such that A = (Q * B) + R.
                     */
                    polynomial operator%(const polynomial& other) const {

                        std::size_t d = other.size() - 1;           /* Degree of B */
                        FieldValueType c = other.back().inversed(); /* Inverse of Leading Coefficient of B */

                        polynomial r(*this);
                        polynomial q = polynomial(r.size(), FieldValueType::zero());

                        std::size_t r_deg = r.size() - 1;
                        std::size_t shift;

                        while (r_deg >= d && !r.is_zero()) {
                            if (r_deg >= d) {
                                shift = r_deg - d;
                            } else {
                                shift = 0;
                            }

                            FieldValueType lead_coeff = r.back() * c;

                            q[shift] += lead_coeff;

                            if (other.size() + shift + 1 > r.size()) {
                                r.resize(other.size() + shift + 1);
                            }
                            auto glambda = [=](FieldValueType x, FieldValueType y) { return y - (x * lead_coeff); };
                            std::transform(other.begin(), other.end(), r.begin() + shift, r.begin() + shift, glambda);
                            r.condense();

                            r_deg = r.size() - 1;
                        }

                        return r;
                    }
                };

                template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
                polynomial<FieldValueType, Allocator> operator+(const polynomial<FieldValueType, Allocator>& A,
                                                                const FieldValueType& B) {

                    return A + B;
                }

                template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
                polynomial<FieldValueType, Allocator> operator+(const FieldValueType& A,
                                                                const polynomial<FieldValueType, Allocator>& B) {

                    return A + B;
                }

                template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
                polynomial<FieldValueType, Allocator> operator-(const polynomial<FieldValueType, Allocator>& A,
                                                                const FieldValueType& B) {

                    return A - B;
                }

                template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
                polynomial<FieldValueType, Allocator> operator-(const FieldValueType& A,
                                                                const polynomial<FieldValueType, Allocator>& B) {

                    return A - B;
                }

                template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
                polynomial<FieldValueType, Allocator> operator*(const polynomial<FieldValueType, Allocator>& A,
                                                                const FieldValueType& B) {

                    return A * B;
                }

                template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
                polynomial<FieldValueType, Allocator> operator*(const FieldValueType& A,
                                                                const polynomial<FieldValueType, Allocator>& B) {

                    return A * B;
                }

                template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
                polynomial<FieldValueType, Allocator> operator/(const polynomial<FieldValueType, Allocator>& A,
                                                                const FieldValueType& B) {

                    return A / B;
                }

                template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
                polynomial<FieldValueType, Allocator> operator/(const FieldValueType& A,
                                                                const polynomial<FieldValueType, Allocator>& B) {

                    return A / B;
                }
            }    // namespace polynomial
        }        // namespace math
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_POLYNOMIAL_POLYNOM_HPP
