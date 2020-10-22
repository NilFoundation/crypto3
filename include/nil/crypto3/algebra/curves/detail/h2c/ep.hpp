//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_HPP
#define CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_HPP

#include <nil/crypto3/algebra/curves/detail/h2c/h2c_suites.hpp>
#include <nil/crypto3/algebra/curves/detail/h2c/h2c_utils.hpp>

#include <type_traits>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    template<typename GroupType>
                    struct ep_map {
                        typedef h2c_suite<GroupType> suite_type;
                        static_assert(suite_type::m == 1, "field has wrong extension");

                        typedef typename suite_type::group_value_type group_value_type;
                        typedef typename suite_type::field_value_type field_value_type;
                        typedef typename suite_type::expand_message expand_message;
                        typedef typename suite_type::number_type number_type;

                        template<typename InputType, typename = typename std::enable_if<std::is_same<
                                                         std::uint8_t, typename InputType::value_type>::value>::type>
                        static inline group_value_type hash_to_curve(const InputType &msg) {
                            auto u = hash_to_field<2>(msg);
                            group_value_type Q0 = map_to_curve(u[0]);
                            group_value_type Q1 = map_to_curve(u[1]);
                            group_value_type R = Q0 + Q1;
                            return clear_cofactor(R);
                        }

                        template<typename InputType, typename = typename std::enable_if<std::is_same<
                                                         std::uint8_t, typename InputType::value_type>::value>::type>
                        static inline group_value_type encode_to_curve(const InputType &msg) {
                            auto u = hash_to_field<1>(msg);
                            group_value_type Q = map_to_curve(u[0]);
                            return clear_cofactor(Q);
                        }

                        // private:
                        template<std::size_t N, typename InputType>
                        static inline std::array<field_value_type, N> hash_to_field(InputType msg) {
                            std::array<std::uint8_t, N * expand_message::bits_per_element> uniform_bytes {0};
                            expand_message::template process<N>(msg, suite_type::suite_id, uniform_bytes);

                            number_type e;
                            auto L = suite_type::L;
                            std::array<field_value_type, N> result {0};
                            for (std::size_t i = 0; i < N; i++) {
                                auto elm_offset = L * i;
                                auto uniform_bytes_iter = uniform_bytes.begin() + elm_offset;
                                import_bits(e, uniform_bytes_iter, uniform_bytes_iter + L);
                                result[i] = field_value_type(e);
                            }

                            return result;
                        }

                        static inline group_value_type map_to_curve(const group_value_type &p) {
                        }

                        static inline group_value_type clear_cofactor(const group_value_type &p) {
                        }
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_HPP
