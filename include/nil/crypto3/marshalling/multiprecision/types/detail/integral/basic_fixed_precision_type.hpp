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

#ifndef CRYPTO3_MARSHALLING_BASIC_INTEGRAL_FIXED_PRECISION_HPP
#define CRYPTO3_MARSHALLING_BASIC_INTEGRAL_FIXED_PRECISION_HPP

#include <type_traits>

#include <boost/type_traits/is_integral.hpp>

#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/traits/max_digits10.hpp>

#include <nil/crypto3/marshalling/multiprecision/processing/integral.hpp>
#include <nil/crypto3/marshalling/multiprecision/types/detail/integral/basic_type.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                namespace detail {
                    template<typename TTypeBase,
                             typename Backend,
                             multiprecision::expression_template_option ExpressionTemplates>
                    class basic_integral<TTypeBase, Backend, ExpressionTemplates, true> : public TTypeBase {

                        using backend_type = Backend;
                        using T = multiprecision::number<backend_type, ExpressionTemplates>;

                        using base_impl_type = TTypeBase;

                    public:
                        using value_type = T;
                        using serialized_type = value_type;

                        basic_integral() = default;

                        explicit basic_integral(value_type val) : value_(val) {
                        }

                        basic_integral(const basic_integral &) = default;

                        basic_integral(basic_integral &&) = default;

                        ~basic_integral() noexcept = default;

                        basic_integral &operator=(const basic_integral &) = default;

                        basic_integral &operator=(basic_integral &&) = default;

                        const value_type &value() const {
                            return value_;
                        }

                        value_type &value() {
                            return value_;
                        }

                        static constexpr std::size_t length() {
                            return max_length();
                        }

                        static constexpr std::size_t min_length() {
                            return min_bit_length() / 8 + ((min_bit_length() % 8) ? 1 : 0);
                        }

                        static constexpr std::size_t max_length() {
                            return max_bit_length() / 8 + ((max_bit_length() % 8) ? 1 : 0);
                        }

                        static constexpr std::size_t bit_length() {
                            return max_bit_length();
                        }

                        static constexpr std::size_t min_bit_length() {
                            return nil::crypto3::multiprecision::backends::min_precision<backend_type>::value ==
                                           UINT_MAX ?
                                       INT_MAX :
                                       nil::crypto3::multiprecision::backends::min_precision<backend_type>::value;
                        }

                        static constexpr std::size_t max_bit_length() {
                            return nil::crypto3::multiprecision::backends::max_precision<backend_type>::value ==
                                           UINT_MAX ?
                                       INT_MAX :
                                       nil::crypto3::multiprecision::backends::max_precision<backend_type>::value;
                        }

                        static constexpr serialized_type to_serialized(value_type val) {
                            return static_cast<serialized_type>(val);
                        }

                        static constexpr value_type from_serialized(serialized_type val) {
                            return val;
                        }

                        template<typename TIter>
                        nil::marshalling::status_type read(TIter &iter, std::size_t size) {
                            
                            if (size < (std::is_same_v<typename std::iterator_traits<TIter>::value_type, bool> ? 
                                            bit_length() : length())) {
                                return nil::marshalling::status_type::not_enough_data;
                            }

                            read_no_status(iter);
                            iter += (std::is_same_v<typename std::iterator_traits<TIter>::value_type, bool> ? 
                                            max_bit_length() : max_length());
                            return nil::marshalling::status_type::success;
                        }

                        template<typename TIter>
                        void read_no_status(TIter &iter) {
                            value_ = crypto3::marshalling::processing::
                                read_data<bit_length(), value_type, typename base_impl_type::endian_type>(iter);
                        }

                        template<typename TIter>
                        nil::marshalling::status_type write(TIter &iter, std::size_t size) const {
                            if (size < (std::is_same_v<typename std::iterator_traits<TIter>::value_type, bool> ? 
                                            bit_length() : length())) {
                                return nil::marshalling::status_type::buffer_overflow;
                            }

                            write_no_status(iter);

                            iter += (std::is_same_v<typename std::iterator_traits<TIter>::value_type, bool> ? 
                                            max_bit_length() : max_length());
                            return nil::marshalling::status_type::success;
                        }

                        template<typename TIter>
                        void write_no_status(TIter &iter) const {
                            crypto3::marshalling::processing::write_data<bit_length(),
                                                                         typename base_impl_type::endian_type>(value_,
                                                                                                               iter);
                        }

                    private:
                        value_type value_ = static_cast<value_type>(0);
                    };
                }    // namespace detail
            }        // namespace types
        }            // namespace marshalling
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_BASIC_INTEGRAL_FIXED_PRECISION_HPP
