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

#ifndef CRYPTO3_MARSHALLING_BASIC_CURVE_ELEMENT_HPP
#define CRYPTO3_MARSHALLING_BASIC_CURVE_ELEMENT_HPP

#include <type_traits>

#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/marshalling/algebra/processing/curve_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                namespace detail {
                    template<typename TTypeBase, typename CurveGroup>
                    class basic_curve_element : public TTypeBase {
                        using T = typename CurveGroup::value_type;
                        using base_impl_type = TTypeBase;

                        using params_type =
                            crypto3::marshalling::processing::curve_element_marshalling_params<CurveGroup>;
                        using reader_type =
                            crypto3::marshalling::processing::curve_element_reader<typename base_impl_type::endian_type,
                                                                                   CurveGroup>;
                        using writer_type =
                            crypto3::marshalling::processing::curve_element_writer<typename base_impl_type::endian_type,
                                                                                   CurveGroup>;

                    public:
                        using value_type = T;
                        using serialized_type = value_type;

                        basic_curve_element() = default;

                        explicit basic_curve_element(value_type val) : value_(val) {
                        }

                        basic_curve_element(const basic_curve_element &) = default;

                        basic_curve_element(basic_curve_element &&) = default;

                        ~basic_curve_element() noexcept = default;

                        basic_curve_element &operator=(const basic_curve_element &) = default;

                        basic_curve_element &operator=(basic_curve_element &&) = default;

                        const value_type &value() const {
                            return value_;
                        }

                        value_type &value() {
                            return value_;
                        }

                        static constexpr std::size_t length() {
                            return params_type::length();
                        }

                        static constexpr std::size_t min_length() {
                            return params_type::min_length();
                        }

                        static constexpr std::size_t max_length() {
                            return params_type::max_length();
                        }

                        static constexpr std::size_t bit_length() {
                            return params_type::bit_length();
                        }

                        static constexpr std::size_t max_bit_length() {
                            return params_type::max_bit_length();
                        }

                        static constexpr serialized_type to_serialized(value_type val) {
                            return static_cast<serialized_type>(val);
                        }

                        static constexpr value_type from_serialized(serialized_type val) {
                            return val;
                        }

                        template<typename TIter>
                        nil::marshalling::status_type read(TIter &iter, std::size_t size) {
                            nil::marshalling::status_type status = reader_type::process(value(), iter);
                            iter += max_length();
                            return status;
                        }

                        template<typename TIter>
                        void read_no_status(TIter &iter) {
                            reader_type::process(value(), iter);
                        }

                        template<typename TIter>
                        nil::marshalling::status_type write(TIter &iter, std::size_t size) const {
                            nil::marshalling::status_type status = writer_type::process(value(), iter);
                            iter += max_length();
                            return status;
                        }

                        template<typename TIter>
                        void write_no_status(TIter &iter) const {
                            writer_type::process(value(), iter);
                        }

                    private:
                        value_type value_;
                    };
                }    // namespace detail
            }        // namespace types
        }            // namespace marshalling
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_BASIC_CURVE_ELEMENT_HPP
