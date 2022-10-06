//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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
// @file Three-bit window lookup (2bits + signature bit) in 2bit table using two constraints. Maps the bits `b` to a
// list of constants `c`
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_LOOKUP_SIGNED_3BIT_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_LOOKUP_SIGNED_3BIT_COMPONENT_HPP

#include <vector>
#include <iterator>
#include <algorithm>
#include <type_traits>

#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/math/linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename Field>
                struct lookup_signed_3bit : public component<Field> {
                    using field_type = Field;
                    using field_value_type = typename field_type::value_type;

                    static constexpr std::size_t chunk_bits = 3;
                    static constexpr std::size_t lookup_bits = 2;

                    // Input variables
                    std::vector<field_value_type> c;
                    const detail::blueprint_variable_vector<field_type> b;
                    // Intermediate variable
                    detail::blueprint_variable<field_type> b0b1;
                    // Output variable
                    detail::blueprint_variable<field_type> result;

                    /// Auto allocation of the result
                    template<typename Constants,
                             typename std::enable_if<std::is_same<field_value_type,
                                                                  typename std::iterator_traits<
                                                                      typename Constants::iterator>::value_type>::value,
                                                     bool>::type = true>
                    lookup_signed_3bit(blueprint<field_type> &bp,
                                       const Constants &in_constants,
                                       const detail::blueprint_variable_vector<field_type> &in_bits) :
                        component<field_type>(bp),
                        b(in_bits) {
                        this->b0b1.allocate(this->bp);
                        this->result.allocate(this->bp);
                        std::copy(std::cbegin(in_constants), std::cend(in_constants), std::back_inserter(this->c));
                    }

                    /// Manual allocation of the result
                    template<typename Constants,
                             typename std::enable_if<std::is_same<field_value_type,
                                                                  typename std::iterator_traits<
                                                                      typename Constants::iterator>::value_type>::value,
                                                     bool>::type = true>
                    lookup_signed_3bit(blueprint<field_type> &bp,
                                       const Constants &in_constants,
                                       const detail::blueprint_variable_vector<field_type> &in_bits,
                                       const detail::blueprint_variable<field_type> &in_result) :
                        component<field_type>(bp),
                        b(in_bits), result(in_result) {
                        this->b0b1.allocate(this->bp);
                        std::copy(std::cbegin(in_constants), std::cend(in_constants), std::back_inserter(this->c));
                    }

                    void generate_r1cs_constraints() {
                        /// b0b1 = b[0] * b[1]
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>(this->b[0], this->b[1], this->b0b1));

                        /// y_lc = c[0] + b[0] * (c[1]-c0) + b[1] * (c[2]-c[0]) + b[0]&b[1] * (c[3] - c[2] - c[1] +
                        /// c[0])
                        detail::blueprint_linear_combination<field_type> y_lc;
                        y_lc.assign(
                            this->bp,
                            math::linear_term<field_type>(detail::blueprint_variable<field_type>(0), this->c[0]) +
                                math::linear_term<field_type>(this->b[0], this->c[1] - this->c[0]) +
                                math::linear_term<field_type>(this->b[1], this->c[2] - this->c[0]) +
                                math::linear_term<field_type>(this->b0b1,
                                                              this->c[3] - this->c[2] - this->c[1] + this->c[0]));

                        /// (y_lc + y_lc) * b[2] == y_lc - result
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({y_lc + y_lc}, this->b[2], {y_lc - this->result}));
                    }

                    void generate_r1cs_witness() {
                        auto i = static_cast<std::size_t>(static_cast<typename field_type::integral_type>(
                            this->b.get_field_element_from_bits(this->bp).data));
                        field_value_type result = this->c[i & 3];
                        if (i > 3) {
                            result = result * (-field_value_type::one());
                        }
                        this->bp.val(this->b0b1) = this->bp.val(this->b[0]) * this->bp.val(this->b[1]);
                        this->bp.val(this->result) = result;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_LOOKUP_SIGNED_3BIT_COMPONENT_HPP
