//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_FIELD_TO_BITS_COMPONENTS_HPP
#define CRYPTO3_ZK_BLUEPRINT_FIELD_TO_BITS_COMPONENTS_HPP

#include <cassert>
#include <memory>

#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/zk/blueprint/r1cs.hpp>

#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/components/packing.hpp>
#include <nil/crypto3/zk/components/lookup_1bit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                /**
                 * Converts a field element to bits, with strict validation that
                 * ensures it's less than the (hard-coded) field modulus.
                 *
                 * This allows the 254th bit to be decoded.
                 *
                 * Given an array of variable bits and an equal length array of fixed bits
                 * verify that the variable bits are lower than the fixed bits.
                 *
                 * Starting with the MSB, continuing to the LSB, for each pair of bits:
                 *
                 *   If fixed bit is 1 and variable bit is 1, state is 'equal'
                 *   If fixed bit is 0 and variable bit is 0, state is 'equal'
                 *   If fixed bit is 1 and variable bit is 0, state is 'less'
                 *   If fixed bit is 0 and variable bit is 1, state is 'greater'
                 *
                 * The comparison continues until the state 'less' or 'greater' occurs
                 * any further comparisons are ignored and don't affect the result.
                 * The first differing bit determines the result, the default is 'equal'.
                 *
                 * The result must be 'less' for success to ensure congruency between
                 * the bits and the field element.
                 *
                 * f = fixed bit
                 * v = variable bit
                 *
                 * F(f,v) = LUT [f v] -> [equal, greater, less, equal]
                 *
                 *  0 0 -> equal
                 *  0 1 -> greater
                 *  1 0 -> less
                 *  1 1 -> equal
                 *
                 * This gives us the bit-by-bit comparison, but what's necessary is
                 * to terminate the comparison upon the less or greater states.
                 * One constraint at the end must enforce the final result being 'less' or 'equal'
                 *
                 * When the desired result is less or equal to `q-1`, then 3 states can be merged
                 * into one, where the 'greater' state zeros any further states. This makes an
                 * accumulator of sorts, where the result of the next comparison is AND'd by the
                 * previous result. This means the current result can be multiplied by the previous
                 * assuming the state `greater` maps to zero, and all others are mapped to `1`.
                 *
                 * The final state will be `1` if it's less or equal than `F_q`, otherwise 0.
                 * The constraints necessary for this are:
                 *
                 *  current * previous = result
                 *
                 * Where if `previous` is 0 then `result` will be 0, and all following results
                 * will be zero.
                 */
                template<typename Field>
                struct field_to_bits_strict : public component<Field> {
                    using field_type = Field;
                    using field_value_type = typename field_type::value_type;
                    using result_type = detail::blueprint_variable_vector<field_type>;

                    // Output bits
                    result_type result;

                    // Intermediate variables & components
                    packing<field_type> packer;
                    detail::blueprint_variable_vector<field_type> results;
                    std::vector<lookup_1bit<field_type>> comparisons;

                private:
                    void init() {
                        // Constant bit is 0
                        const std::vector<field_value_type> table_cmp_0 = {
                            field_value_type::zero(),    // 0, equal
                            field_value_type::one()      // 1, greater
                        };

                        // Constant bit is 1
                        const std::vector<field_value_type> table_cmp_1 = {
                            field_value_type::one(),    // 0, less
                            field_value_type::one()     // 1, equal
                        };

                        const typename field_type::integral_type largest_value = field_type::modulus - 1;

                        for (size_t i = 0; i < field_type::value_bits; ++i) {
                            if (multiprecision::bit_test(largest_value, i)) {
                                this->comparisons.emplace_back(this->bp, table_cmp_1, this->result[i]);
                            } else {
                                this->comparisons.emplace_back(this->bp, table_cmp_0, this->result[i]);
                            }
                        }
                    }

                public:
                    /// Auto allocation of the result
                    field_to_bits_strict(blueprint<field_type> &bp,
                                         const detail::blueprint_linear_combination<field_type> &in_field_element) :
                        component<field_type>(bp),
                        result([&]() {
                            detail::blueprint_variable_vector<field_type> r;
                            r.allocate(bp, field_type::value_bits);
                            return r;
                        }()),
                        packer(bp, result, in_field_element), results([&]() {
                            detail::blueprint_variable_vector<field_type> r;
                            r.allocate(bp, field_type::value_bits - 1);
                            return r;
                        }()) {
                        init();
                    }

                    /// Manual allocation of the result
                    field_to_bits_strict(blueprint<field_type> &bp,
                                         const detail::blueprint_linear_combination<field_type> &in_field_element,
                                         const result_type &in_result) :
                        component<field_type>(bp),
                        result(in_result), packer(bp, result, in_field_element), results([&]() {
                            detail::blueprint_variable_vector<field_type> r;
                            r.allocate(bp, field_type::value_bits - 1);
                            return r;
                        }()) {
                        init();
                    }

                    void generate_r1cs_constraints() {
                        this->packer.generate_r1cs_constraints(true);

                        for (auto &component_it : this->comparisons) {
                            component_it.generate_r1cs_constraints();
                        }

                        // AND all of the comparisons
                        std::size_t last_bit = field_type::value_bits - 1;
                        for (std::size_t i = last_bit; i > 0; --i) {
                            if (i == last_bit) {
                                this->bp.add_r1cs_constraint(
                                    snark::r1cs_constraint<field_type>(this->comparisons[i - 1].result,
                                                                       this->comparisons[i].result,
                                                                       this->results[i - 1]));
                            } else {
                                this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                                    this->comparisons[i - 1].result, this->results[i], this->results[i - 1]));
                            }
                        }
                    }

                    void generate_r1cs_witness() {
                        this->packer.generate_r1cs_witness_from_packed();

                        for (auto &component_it : this->comparisons) {
                            component_it.generate_r1cs_witness();
                        }

                        // Iterate from MSB to LSB
                        std::size_t last_bit = (field_type::value_bits - 1);
                        for (std::size_t i = last_bit; i > 0; --i) {
                            // current * previous = result
                            if (i == last_bit) {
                                this->bp.val(this->results[i - 1]) = this->bp.val(this->comparisons[i - 1].result) *
                                                                     this->bp.val(this->comparisons[i].result);
                            } else {
                                this->bp.val(this->results[i - 1]) =
                                    this->bp.val(this->results[i]) * this->bp.val(this->comparisons[i - 1].result);
                            }
                        }
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_FIELD_TO_BITS_COMPONENTS_HPP
