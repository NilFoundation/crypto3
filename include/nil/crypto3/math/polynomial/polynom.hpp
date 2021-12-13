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

                template <typename FieldValueType>
                class polynom : private std::vector<FieldValueType>{

                public:

                    using typename std::vector<FieldValueType>::const_iterator;
                    using typename std::vector<FieldValueType>::const_reverse_iterator;
                    using typename std::vector<FieldValueType>::iterator;
                    using typename std::vector<FieldValueType>::reverse_iterator;

                    using std::vector<FieldValueType>::begin;
                    using std::vector<FieldValueType>::emplace_back;
                    using std::vector<FieldValueType>::pop_back;
                    using std::vector<FieldValueType>::empty;
                    using std::vector<FieldValueType>::end;
                    using std::vector<FieldValueType>::back;
                    using std::vector<FieldValueType>::insert;
                    using std::vector<FieldValueType>::rbegin;
                    using std::vector<FieldValueType>::rend;
                    using std::vector<FieldValueType>::reserve;
                    using std::vector<FieldValueType>::size;
                    using std::vector<FieldValueType>::operator[];
                    using std::vector<FieldValueType>::operator=;
                    using std::vector<FieldValueType>::resize;

                    polynom():
                        std::vector<FieldValueType>({0}){};

                    polynom(std::size_t count, FieldValueType value = FieldValueType()):
                        std::vector<FieldValueType>(count, value){};

                    polynom(std::initializer_list<FieldValueType> init):
                        std::vector<FieldValueType>(init){};

                    polynom(FieldValueType value, std::size_t power):
                        std::vector<FieldValueType>(power+1, FieldValueType(0)){
                            (*this)[power] = value;
                        };

                    template <typename Range>
                    FieldValueType evaluate(Range &values){

                        assert(values.size() + 1 == this->size());

                        FieldValueType result = (*this)[0];
                        for (std::size_t i = 0; i < values.size(); i++){
                            result += (*this)[i + 1]*values[i];
                        }

                        return result;
                    }

                    /**
                     * Returns true if polynom is a zero polynom.
                     */
                    bool is_zero() const {
                        return std::all_of(
                            this->begin(), this->end(),
                            [](FieldValueType i) {
                                return i == FieldValueType(0);
                            });
                    }

                    /**
                     * Removes extraneous zero entries from in vector representation of polynomial.
                     * Example - Degree-4 Polynomial: [0, 1, 2, 3, 4, 0, 0, 0, 0] -> [0, 1, 2, 3, 4]
                     * Note: Simplest condensed form is a zero polynomial of vector form: [0]
                     */
                    void condense() {
                        for (auto first = this->begin();
                             first != this->end() &&
                             this->back() == FieldValueType();
                             ++first) {
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
                    polynom operator+(const polynom &other) const{
                        if (this->is_zero()) {
                            return other;
                        } else if (other.is_zero()) {
                            return *this;
                        } else {
                            polynom result;

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

                    polynom operator-() const{
                        
                        polynom result (this->size());
                        std::transform(this->begin(), this->end(), result.begin(), std::negate<FieldValueType>());

                        return result;
                    }

                    /**
                     * Computes the standard polynomial subtraction, polynomial A - polynomial B, and stores result in
                     * polynomial C.
                     */
                    polynom operator-(const polynom &other) const{
                        if (this->is_zero()) {
                            return -(other);
                        } else if (other.is_zero()) {
                            return *this;
                        } else {
                            polynom result;

                            std::size_t a_size = std::distance(this->begin(), this->end());
                            std::size_t b_size = std::distance(other.begin(), other.end());

                            if (a_size > b_size) {
                                result.resize(a_size);
                                std::transform(this->begin(), this->begin() + b_size, 
                                    other.begin(), result.begin(), std::minus<FieldValueType>());
                                std::copy(this->begin() + b_size, this->end(), result.begin() + b_size);
                            } else {
                                result.resize(b_size);
                                std::transform(this->begin(), this->end(), other.begin(), 
                                    result.begin(), std::minus<FieldValueType>());
                                std::transform(other.begin() + a_size, other.end(), 
                                    result.begin() + a_size, std::negate<FieldValueType>());
                            }

                            result.condense();

                            return result;
                        }
                    }

                    /**
                     * Perform the multiplication of two polynomials, polynomial A * polynomial B, and stores result in
                     * polynomial C.
                     */
                    polynom operator*(const polynom &other) const {
                        polynom result;
                        multiplication_on_fft(result, *this, other);
                        return result;
                    }

                    /**
                     * Perform the standard Euclidean Division algorithm.
                     * Input: Polynomial A, Polynomial B, where A / B
                     * Output: Polynomial Q, such that A = (Q * B) + R.
                     */
                    polynom operator/(const polynom &other) const {

                        std::size_t d = other.size() - 1;       /* Degree of B */
                        FieldValueType c = other.back().inversed(); /* Inverse of Leading Coefficient of B */

                        polynom r(*this);
                        polynom q = polynom(r.size(), FieldValueType::zero());

                        std::size_t r_deg = r.size() - 1;
                        std::size_t shift;

                        while (r_deg >= d && !r.is_zero()) {
                            if (r_deg >= d)
                                shift = r_deg - d;
                            else
                                shift = 0;

                            FieldValueType lead_coeff = r.back() * c;

                            q[shift] += lead_coeff;

                            if (other.size() + shift + 1 > r.size())
                                r.resize(other.size() + shift + 1);
                            auto glambda = [=](FieldValueType x, FieldValueType y) { return y - (x * lead_coeff); };
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
                    polynom operator%(const polynom &other) const {

                        std::size_t d = other.size() - 1;       /* Degree of B */
                        FieldValueType c = other.back().inversed(); /* Inverse of Leading Coefficient of B */

                        polynom r(*this);
                        polynom q = polynom(r.size(), FieldValueType::zero());

                        std::size_t r_deg = r.size() - 1;
                        std::size_t shift;

                        while (r_deg >= d && !r.is_zero()) {
                            if (r_deg >= d)
                                shift = r_deg - d;
                            else
                                shift = 0;

                            FieldValueType lead_coeff = r.back() * c;

                            q[shift] += lead_coeff;

                            if (other.size() + shift + 1 > r.size())
                                r.resize(other.size() + shift + 1);
                            auto glambda = [=](FieldValueType x, FieldValueType y) { return y - (x * lead_coeff); };
                            std::transform(other.begin(), other.end(), r.begin() + shift, r.begin() + shift, glambda);
                            r.condense();

                            r_deg = r.size() - 1;
                        }

                        return r;
                    }
                };
            }    // namespace polynomial
        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_POLYNOMIAL_POLYNOM_HPP
