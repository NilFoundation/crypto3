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

#ifndef CRYPTO3_MATH_POLYNOMIAL_POLYNOM_DFT_HPP
#define CRYPTO3_MATH_POLYNOMIAL_POLYNOM_DFT_HPP

#include <algorithm>
#include <vector>
#include <ostream>
#include <iterator>

#include <nil/crypto3/math/polynomial/basic_operations.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            //size_t __global_from_coefficients_counter_test = 0;
            //size_t __global_coefficients_counter_test = 0;
            // Optimal val.size must be power of two, if it's not true we have points that we will never use
            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>>
            class polynomial_dfs {
                typedef std::vector<FieldValueType, Allocator> container_type;

                container_type val;
                size_t _d;

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

                // Default constructor creates a zero polynomial of degree 0 and size 1.
                polynomial_dfs() : val(1, 0) {
                    _d = 0;
                }

                explicit polynomial_dfs(size_t d, size_type n) : val(n), _d(d) {
                    BOOST_ASSERT_MSG(n == detail::power_of_two(n), "DFS optimal polynomial size must be a power of two");
                }

                explicit polynomial_dfs(size_t d, size_type n, const allocator_type& a) : val(n, a), _d(d) {
                    BOOST_ASSERT_MSG(n == detail::power_of_two(n), "DFS optimal polynomial size must be a power of two");
                }

                polynomial_dfs(size_t d, size_type n, const value_type& x) : val(n, x), _d(d) {
                    BOOST_ASSERT_MSG(n == detail::power_of_two(n), "DFS optimal polynomial size must be a power of two");
                }

                polynomial_dfs(size_t d, size_type n, const value_type& x, const allocator_type& a) :
                    val(n, x, a), _d(d) {
                    BOOST_ASSERT_MSG(n == detail::power_of_two(n), "DFS optimal polynomial size must be a power of two");
                }

                template<typename InputIterator>
                polynomial_dfs(size_t d, InputIterator first, InputIterator last) : val(first, last), _d(d) {
                    BOOST_ASSERT_MSG(std::distance(first, last) == detail::power_of_two(std::distance(first, last)),
                                     "DFS optimal polynomial size must be a power of two");
                }

                template<typename InputIterator>
                polynomial_dfs(size_t d, InputIterator first, InputIterator last, const allocator_type& a) :
                    val(first, last, a), _d(d) {
                    BOOST_ASSERT_MSG(std::distance(first, last) == detail::power_of_two(std::distance(first, last)),
                                     "DFS optimal polynomial size must be a power of two");
                }

                ~polynomial_dfs() = default;

                polynomial_dfs(const polynomial_dfs& x) : val(x.val), _d(x._d) {
                }

                polynomial_dfs(const polynomial_dfs& x, const allocator_type& a) : val(x.val, a), _d(x._d) {
                }

                polynomial_dfs(size_t d, std::initializer_list<value_type> il) : val(il), _d(d) {
                }

                polynomial_dfs(size_t d, std::initializer_list<value_type> il, const allocator_type& a) :
                    val(il, a), _d(d) {
                    BOOST_ASSERT_MSG(val.size() == detail::power_of_two(val.size()),
                                     "DFS optimal polynomial size must be a power of two");
                }
                // TODO: add constructor with omega

                polynomial_dfs(polynomial_dfs&& x)
                    BOOST_NOEXCEPT(std::is_nothrow_move_constructible<allocator_type>::value)
                    : val(std::move(x.val))
                    , _d(x._d) {
                }

                polynomial_dfs(polynomial_dfs&& x, const allocator_type& a) 
                    : val(std::move(x.val), a)
                    , _d(x._d) {
                }

                polynomial_dfs(size_t d, const container_type& c) : val(c), _d(d) {
                    BOOST_ASSERT_MSG(val.size() == detail::power_of_two(val.size()),
                                     "DFS optimal polynomial size must be a power of two");
                }

                polynomial_dfs(size_t d, container_type&& c) : val(c), _d(d) {
                    BOOST_ASSERT_MSG(val.size() == detail::power_of_two(val.size()),
                                     "DFS optimal polynomial size must be a power of two");
                }

                polynomial_dfs& operator=(const polynomial_dfs& x) {
                    val = x.val;
                    _d = x._d;
                    return *this;
                }

                polynomial_dfs& operator=(polynomial_dfs&& x) {
                    val = std::move(x.val);
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

                bool operator==(const polynomial_dfs& rhs) const {
                    return val == rhs.val && _d == rhs._d;
                }
                bool operator!=(const polynomial_dfs& rhs) const {
                    return !(rhs == *this && _d == rhs._d);
                }

                //                template<typename InputIterator>
                //                typename std::iterator_traits<InputIterator>::reference assign(InputIterator first,
                //                                                                               InputIterator last) {
                //                    return val.assign(first, last);
                //                }
                //
                //                void assign(size_type n, const_reference u) {
                //                    return val.assign(n, u);
                //                }
                //
                //                void assign(std::initializer_list<value_type> il) {
                //                    assign(il.begin(), il.end());
                //                }

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

                size_type degree() const BOOST_NOEXCEPT {
                    return _d;
                }

                size_type max_degree() const BOOST_NOEXCEPT {
                    return this->size();
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
                    val.emplace_back(_x);
                }

                template<class... Args>
                reference emplace_back(Args&&... _args) {
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
                template<class... Args>
                iterator emplace(const_iterator _position, Args&&... _args) {
                    return val.template emplace(_position, _args...);
                }

                iterator insert(const_iterator _position, size_type _n, const_reference _x) {
                    return val.insert(_position, _n, _x);
                }

                template<class InputIterator>
                iterator insert(const_iterator _position, InputIterator _first, InputIterator _last) {
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
                    if (this->size() == _sz)
                        return;
                    BOOST_ASSERT_MSG(_sz >= _d, "Resizing DFS polynomial to a size less than degree is prohibited: can't restore the polynomial in the future.");
                    if (this->size() == 1) {
                        this->val.resize(_sz, this->val[0]);
                    } else {
                        typedef typename value_type::field_type FieldType;
            
                        make_evaluation_domain<FieldType>(this->size())->inverse_fft(this->val);
                        this->val.resize(_sz, FieldValueType::zero());
                        make_evaluation_domain<FieldType>(_sz)->fft(this->val);
                    }
                }

                void swap(polynomial_dfs& other) {
                    val.swap(other.val);
                    std::swap(_d, other._d);
                }

                FieldValueType evaluate(const FieldValueType& value) const {
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
                    for (const auto& v: val) {
                        if (v != FieldValueType::zero())
                            return false;
                    }
                    return true;
                }

                inline static polynomial_dfs zero() {
                    return polynomial_dfs(); 
                }

                inline static polynomial_dfs one() {
                    return polynomial_dfs(0, size_type(1), value_type(1)); 
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
                 * Computes the standard polynomial addition, polynomial A + polynomial B,
                 * and stores result in polynomial C.
                 */
                polynomial_dfs operator+(const polynomial_dfs& other) const {
                    polynomial_dfs result(std::max(this->_d, other._d), this->begin(), this->end());
                    if (other.size() > this->size()) {
                        result.resize(other.size());
                    }
                    if (this->size() > other.size()) {
                        polynomial_dfs tmp(other);
                        tmp.resize(this->size());
                        std::transform(tmp.begin(), tmp.end(), result.begin(), result.begin(),
                                       std::plus<FieldValueType>());
                        return result;
                    }
                    std::transform(other.begin(), other.end(), result.begin(), result.begin(),
                                   std::plus<FieldValueType>());
                    return result;
                }

                /**
                 * Computes the standard polynomial addition, polynomial A + polynomial B, 
                 * and stores result in polynomial A.
                 */
                polynomial_dfs operator+=(const polynomial_dfs& other) {
                    this->_d = std::max(this->_d, other._d);
                    if (other.size() > this->size()) {
                        this->resize(other.size());
                    }
                    if (this->size() > other.size()) {
                        polynomial_dfs tmp(other);
                        tmp.resize(this->size());

                        std::transform(tmp.begin(), tmp.end(), this->begin(), this->begin(), std::plus<FieldValueType>());
                        return *this;
                    }
                    std::transform(other.begin(), other.end(), this->begin(), this->begin(), std::plus<FieldValueType>());
                    return *this;
                }

                /**
                 * Computes polynomial A + constant c, 
                 * and stores result in polynomial A.
                 */
                polynomial_dfs operator+=(const FieldValueType& c) {
                    for( auto it = this->begin(); it!=this->end(); it++) *it += c;
                    return *this;
                }
                
                /**
                 * Computes polynomial A - constant c, 
                 * and stores result in polynomial A.
                 */
                polynomial_dfs operator-() const {
                    polynomial_dfs result(this->_d, this->begin(), this->end());
                    std::transform(this->begin(), this->end(), result.begin(), std::negate<FieldValueType>());
                    return result;
                }

                /**
                 * Computes the standard polynomial subtraction, polynomial A - polynomial B, 
                 * and stores result in polynomial C.
                 */
                polynomial_dfs operator-(const polynomial_dfs& other) const {
                    polynomial_dfs result(std::max(_d, other._d), this->begin(), this->end());
                    if (other.size() > this->size()) {
                        result.resize(other.size());
                    }
                    if (this->size() > other.size()) {
                        polynomial_dfs tmp(other);
                        tmp.resize(this->size());
                        std::transform(result.begin(), result.end(), tmp.begin(), result.begin(),
                                       std::minus<FieldValueType>());
                        return result;
                    }
                    std::transform(result.begin(), result.end(), other.begin(), result.begin(),
                                   std::minus<FieldValueType>());
                    return result;
                }

                /**
                 * Computes the standard polynomial subtraction, polynomial A - polynomial B, 
                 * and stores result in polynomial A.
                 */
                polynomial_dfs operator-=(const polynomial_dfs& other) {
                    this->_d = std::max(this->_d, other._d);
                    if (other.size() > this->size()) {
                        this->resize(other.size());
                    }
                    if (this->size() > other.size()) {
                        polynomial_dfs tmp(other);
                        tmp.resize(this->size());
                        std::transform(this->begin(), this->end(), tmp.begin(), this->begin(), std::minus<FieldValueType>());
                        return *this;
                    }
                    std::transform(this->begin(), this->end(), other.begin(), this->begin(), std::minus<FieldValueType>());
                    return *this;
                }

                /**
                 * Computes tpolynomial A - constant c 
                 * and stores result in polynomial A.
                 */
                polynomial_dfs operator-=(const FieldValueType& c) {
                    for( auto it = this->begin(); it!=this->end(); it++) *it -= c;
                    return *this;
                }

                /**
                 * Perform the multiplication of two polynomials, polynomial A * polynomial B, 
                 * and stores result in polynomial C.
                 */
                polynomial_dfs operator*(const polynomial_dfs& other) const {
                    polynomial_dfs result(this->degree() + other.degree(), this->begin(), this->end());

                    size_t polynomial_s =
                        detail::power_of_two(std::max({this->size(), other.size(), this->degree() + other.degree() + 1}));

                    if (result.size() < polynomial_s) {
                        result.resize(polynomial_s);
                    }
                    if (other.size() < polynomial_s) {
                        polynomial_dfs tmp(other);
                        tmp.resize(polynomial_s);
                        std::transform(tmp.begin(), tmp.end(), result.begin(), result.begin(), std::multiplies<FieldValueType>());
                        return result;
                    }
                    std::transform(other.begin(), other.end(), result.begin(), result.begin(), std::multiplies<FieldValueType>());
                    return result;
                }

                /**
                 * Perform the multiplication of two polynomials, polynomial A * polynomial B, 
                 * and stores result in polynomial A.
                 */
                polynomial_dfs operator*=(const polynomial_dfs& other) {
                    size_t polynomial_s =
                        detail::power_of_two(std::max({this->size(), other.size(), this->degree() + other.degree() + 1}));
                    this->_d += other._d;

                    if (this->size() < polynomial_s) {
                        this->resize(polynomial_s);
                    }
                    if (other.size() < polynomial_s) {
                        polynomial_dfs tmp(other);
                        tmp.resize(polynomial_s);

                        std::transform(tmp.begin(), tmp.end(), this->begin(), this->begin(), std::multiplies<FieldValueType>());
                        return *this;
                    }
                    std::transform(this->begin(), this->end(), other.begin(), this->begin(), std::multiplies<FieldValueType>());
                    return *this;
                }
                
                /**
                 * Perform the multiplication of two polynomials, polynomial A * constant alpha, 
                 * and stores result in polynomial A.
                 */
                polynomial_dfs operator*=(const FieldValueType& alpha) {
                    for( auto it = this->begin(); it!=this->end(); it++) *it *= alpha;
                    return *this;
                }
                
                /**
                 * Perform the standard Euclidean Division algorithm.
                 * Input: Polynomial A, Polynomial B, where A / B
                 * Output: Polynomial Q, such that A = (Q * B) + R.
                 */
                polynomial_dfs operator/(const polynomial_dfs& other) const {
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
                    return polynomial_dfs(new_s - 1, q);
                }

                /**
                 * Perform the standard Euclidean Division algorithm.
                 * Input: Polynomial A, Polynomial B, where A / B
                 * Output: Polynomial R, such that A = (Q * B) + R.
                 */
                polynomial_dfs operator%(const polynomial_dfs& other) const {
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
                    return polynomial_dfs(new_s - 1, r);
                }

                template<typename ContainerType>
                void from_coefficients(const ContainerType &tmp) {
                    typedef typename value_type::field_type FieldType;
                    size_t n = detail::power_of_two(tmp.size());
                    value_type omega = unity_root<FieldType>(n);
                    _d = tmp.size() - 1;
                    val.assign(tmp.begin(), tmp.end());
                    val.resize(n, FieldValueType::zero());
                    detail::basic_radix2_fft<FieldType>(val, omega);
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
                    while (r_size > 1 && tmp[r_size - 1] == FieldValueType::zero()) {
                        --r_size;
                    }
                    tmp.resize(r_size);
                    return tmp;
                }

                polynomial_dfs pow(size_t power) const {
                    if (power == 1) {
                        return *this;
                    }

                    polynomial_dfs power_of_2 = *this;
                    size_t expected_size = detail::power_of_two(
                        std::max({this->size(), this->degree() * power + 1})); 
                    power_of_2.resize(expected_size);
                    polynomial_dfs result(0, expected_size, FieldValueType::one());
                    while (power) {
                        if (power % 2 == 1) {
                            result *= power_of_2;
                        } 
                        power /= 2;
                        if (power == 0)
                            break;
                        power_of_2 *= power_of_2;
                    }
                    return result;
                }

            };

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator+(const polynomial_dfs<FieldValueType, Allocator>& A,
                                                            const FieldValueType& B) {
                polynomial_dfs<FieldValueType> result(A);
                for( auto it = result.begin(); it != result.end(); it++ ){
                    *it += B;
                }
                return result;
            }

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator+(const FieldValueType& A,
                                                            const polynomial_dfs<FieldValueType, Allocator>& B) {
                polynomial_dfs<FieldValueType> result(B);
                for( auto it = result.begin(); it != result.end(); it++ ){
                    *it += A;
                }
                return result;
            }
            

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator-(const polynomial_dfs<FieldValueType, Allocator>& A,
                                                            const FieldValueType& B) {
                polynomial_dfs<FieldValueType> result(A);
                for( auto it = result.begin(); it != result.end(); it++ ){
                    *it -=  B;
                }
                return result;
            }

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator-(const FieldValueType& A,
                                                            const polynomial_dfs<FieldValueType, Allocator>& B) {
                polynomial_dfs<FieldValueType> result(B);
                for( auto it = result.begin(); it != result.end(); it++ ){
                    *it = A - *it;
                }
                return result;
            }

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator*(const polynomial_dfs<FieldValueType, Allocator>& A,
                                                            const FieldValueType& B) {
                polynomial_dfs<FieldValueType> result(A);
                for( auto it = result.begin(); it != result.end(); it++ ){
                    *it *= B;
                }
                return result;
            }

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator*(const FieldValueType& A,
                                                            const polynomial_dfs<FieldValueType, Allocator>& B) {
                polynomial_dfs<FieldValueType> result(B);
                for( auto it = result.begin(); it != result.end(); it++ ){
                    *it *= A;
                }
                return result;
            }

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator/(const polynomial_dfs<FieldValueType, Allocator>& A,
                                                            const FieldValueType& B) {
                return A / polynomial_dfs<FieldValueType>(0, A.size(), B);
            }

            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            polynomial_dfs<FieldValueType, Allocator> operator/(const FieldValueType& A,
                                                            const polynomial_dfs<FieldValueType, Allocator>& B) {

                return polynomial_dfs<FieldValueType>(0, B.size(), A) / B;
            }

            // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
            // the values of polynomials, when the check fails.
            template<typename FieldValueType, typename Allocator = std::allocator<FieldValueType>,
                     typename = typename std::enable_if<detail::is_field_element<FieldValueType>::value>::type>
            std::ostream& operator<<(std::ostream& os,
                                     const polynomial_dfs<FieldValueType, Allocator>& poly) {
                if (poly.degree() == 0) {
                    // If all it contains is a constant, print the constant, so it's more readable.
                    os << *poly.begin();
                } else {
                    os << "[Polynomial DFS, size " << poly.size()
                       << " degree " << poly.degree() << " values ";
                    for( auto it = poly.begin(); it != poly.end(); it++ ){
                        os << "0x" << std::hex << it->data << ", ";
                    }
                    os << "]";
                }
                return os;
            }

        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

namespace std {

    // As our operator== returns false for polynomials with different sizes, the same will happen here,
    // resized polynomial will have a different hash from the initial one.
    template<typename FieldValueType, typename Allocator>
    struct std::hash<nil::crypto3::math::polynomial_dfs<FieldValueType, Allocator>>
    {
        std::hash<FieldValueType> value_hasher;

        std::size_t operator()(const nil::crypto3::math::polynomial_dfs<FieldValueType, Allocator>& poly) const
        {
            std::size_t result = poly.degree();
            for (const auto& val: poly) {
                boost::hash_combine(result, value_hasher(val));
            }
            return result;
        }
    };

} // namespace std

#endif    // CRYPTO3_MATH_POLYNOMIAL_POLYNOM_DFT_HPP
