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

#ifndef CRYPTO3_MATH_POLYNOMIAL_POLYNOM_VIEW_HPP
#define CRYPTO3_MATH_POLYNOMIAL_POLYNOM_VIEW_HPP

#include <algorithm>
#include <vector>

#include <nil/crypto3/math/polynomial/basic_operations.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
            class polynomial_view {
                typedef std::vector<FieldValueType, Allocator> container_type;

                container_type &it;

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

                polynomial_view(container_type &c) : it(c) {}

                polynomial_view(const container_type &c) : it(c) {

                }

                ~polynomial_view() = default;

                polynomial_view(const polynomial_view& x) : it(x.it) {
                }

                polynomial_view(polynomial_view&& x) BOOST_NOEXCEPT(std::is_nothrow_move_constructible<allocator_type>::value) :
                    it(x.it) {
                }

                polynomial_view(container_type &&c) : it(&c) {

                }

                polynomial_view& operator=(const polynomial_view& x) {
                    it = x.it;
                    return *this;
                }

                polynomial_view& operator=(polynomial_view&& x) {
                    it = x.it;
                    return *this;
                }

                polynomial_view& operator=(const container_type& x) {
                    it = x;
                    return *this;
                }

                polynomial_view& operator=(container_type&& x) {
                    it = x;
                    return *this;
                }

                bool operator==(const polynomial_view& rhs) const {
                    return (*it) == (*rhs.it);
                }
                bool operator!=(const polynomial_view& rhs) const {
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

                allocator_type get_allocator() const BOOST_NOEXCEPT {
                    return it.__alloc();
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
                    return size() - 1;
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
                    return it.resize(_sz);
                }

                void resize(size_type _sz, const_reference _x) {
                    return it.resize(_sz, _x);
                }

                void swap(polynomial_view& other) {
                    it.swap(other.val);
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
                    auto end = this->end();
                    while (end != this->begin()) {
                        result = result * value + *--end;
                    }
                    return result;
                }

                /**
                 * Returns true if polynomial_view is a zero polynomial.
                 */
                bool is_zero() const {
                    return std::all_of(this->begin(), this->end(),
                                       [](FieldValueType i) { return i == FieldValueType::zero(); });
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
                polynomial_view operator+=(const polynomial_view& other) {
                    addition(*this, *this, other);
                    return *this;
                }

//                polynomial_view operator-() const {
                void neg() {
                    std::transform(this->begin(), this->end(), this->begin(), std::negate<FieldValueType>());
                }

                /**
                 * Computes the standard polynomial subtraction, polynomial A - polynomial B, and stores result in
                 * polynomial C.
                 */
                polynomial_view operator-=(const polynomial_view& other) {
                    subtraction(*this, *this, other);
                    return *this;
                }

                /**
                 * Perform the multiplication of two polynomials, polynomial A * polynomial B, and stores result in
                 * polynomial C.
                 */
                polynomial_view operator*=(polynomial_view other) {
                    multiplication(*this, *this, other);
                    return *this;
                }

                polynomial_view operator/=(const polynomial_view& other) {
                    std::size_t d = other.size() - 1;           /* Degree of B */
                    FieldValueType c = other.back().inversed(); /* Inverse of Leading Coefficient of B */

                    polynomial_view r(*this);
                    container_type q(r.size(), FieldValueType::zero());

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
                    nil::crypto3::math::condense(q);

                    this->template assign(q.begin(), q.end());
                    return *this;
                }

                polynomial_view operator%=(const polynomial_view& other) {
                    std::size_t d = other.size() - 1;           /* Degree of B */
                    FieldValueType c = other.back().inversed(); /* Inverse of Leading Coefficient of B */

                    std::size_t r_deg = this->size() - 1;
                    std::size_t shift;

                    while (r_deg >= d && !this->is_zero()) {
                        if (r_deg >= d) {
                            shift = r_deg - d;
                        } else {
                            shift = 0;
                        }

                        FieldValueType lead_coeff = this->back() * c;

                        if (other.size() + shift + 1 > this->size()) {
                            this->resize(other.size() + shift + 1);
                        }
                        auto glambda = [=](const FieldValueType& x, const FieldValueType& y) {
                            return y - (x * lead_coeff);
                        };
                        std::transform(other.begin(), other.end(), this->begin() + shift, this->begin() + shift, glambda);
                        this->condense();

                        r_deg = this->size() - 1;
                    }
                    return *this;
                }
            };
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_POLYNOMIAL_POLYNOM_VIEW_HPP
