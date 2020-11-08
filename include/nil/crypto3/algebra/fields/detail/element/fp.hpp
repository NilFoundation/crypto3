//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP_HPP

#include <nil/crypto3/algebra/fields/detail/exponentiation.hpp>
#include <boost/multiprecision/ressol.hpp>
#include <boost/multiprecision/inverse.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    template<typename FieldParams>
                    class element_fp {
                        typedef FieldParams policy_type;

                    public:
                        typedef typename policy_type::field_type field_type;

                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        using value_type = number_type;

                        value_type data;

                        element_fp() : data(value_type(0, modulus)) {};

                        element_fp(value_type data) : data(data) {};

                        element_fp(modulus_type data) : data(data, modulus) {};

                        element_fp(int data) : data(data, modulus) {};

                        element_fp(const element_fp &B) {
                            data = B.data;
                        };

                        inline static element_fp zero() {
                            return element_fp(0);
                        }

                        inline static element_fp one() {
                            return element_fp(1);
                        }

                        bool is_zero() const {
                            return data == value_type(0, modulus);
                        }

                        bool is_one() const {
                            return data == value_type(1, modulus);
                        }

                        bool operator==(const element_fp &B) const {
                            return data == B.data;
                        }

                        bool operator!=(const element_fp &B) const {
                            return data != B.data;
                        }

                        element_fp &operator=(const element_fp &B) {
                            data = B.data;

                            return *this;
                        }

                        element_fp operator+(const element_fp &B) const {
                            return element_fp(data + B.data);
                        }

                        element_fp operator-(const element_fp &B) const {
                            return element_fp(data - B.data);
                        }

                        element_fp &operator-=(const element_fp &B) {
                            data -= B.data;

                            return *this;
                        }

                        element_fp &operator+=(const element_fp &B) {
                            data += B.data;

                            return *this;
                        }

                        element_fp &operator*=(const element_fp &B) {
                            data *= B.data;

                            return *this;
                        }

                        element_fp &operator/=(const element_fp &B) {
                            data *= B.inversed().data;

                            return *this;
                        }

                        element_fp operator-() const {
                            return element_fp(-data);
                        }

                        element_fp operator*(const element_fp &B) const {
                            return element_fp(data * B.data);
                        }

                        const element_fp operator/(const element_fp &B) const {
                            //                        return element_fp(data / B.data);
                            return element_fp(data * B.inversed().data);
                        }

                        const bool operator<(const element_fp &B) const {
                            return data < B.data;
                        }

                        const bool operator>(const element_fp &B) const {
                            return data > B.data;
                        }

                        element_fp doubled() const {
                            return element_fp(data + data);
                        }

                        element_fp sqrt() const {
                            return element_fp(ressol(data));
                        }

                        element_fp inversed() const {
                            return element_fp(inverse_extended_euclidean_algorithm(data));
                        }

                        element_fp _2z_add_3x() {
                        }

                        element_fp squared() const {
                            return element_fp(data * data);    // maybe can be done more effective
                        }

                        bool is_square() const {
                            return (this->sqrt() != -1);    // maybe can be done more effective
                        }

                        template<typename PowerType>
                        element_fp pow(const PowerType &pwr) const {
                            return element_fp(power(*this, modulus_type(pwr)));
                        }
                    };

                    template<typename FieldParams>
                    constexpr typename element_fp<FieldParams>::modulus_type const element_fp<FieldParams>::modulus;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP_HPP
