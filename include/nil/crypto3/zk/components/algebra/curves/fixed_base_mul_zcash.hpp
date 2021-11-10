//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_FIXED_BASE_MUL_ZCASH_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_FIXED_BASE_MUL_ZCASH_COMPONENT_HPP

#include <type_traits>
#include <vector>
#include <iterator>
#include <cmath>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>
#include <boost/range/concepts.hpp>

#include <nil/crypto3/detail/static_pow.hpp>

#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/blueprint_linear_combination.hpp>

#include <nil/crypto3/zk/components/lookup_signed_3bit.hpp>

#include <nil/crypto3/zk/components/algebra/fields/element_fp.hpp>

#include <nil/crypto3/zk/components/algebra/curves/element_ops.hpp>
#include <nil/crypto3/zk/components/algebra/curves/element_g1_affine.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename Curve>
                struct fixed_base_mul_zcash : public component<typename Curve::base_field_type> {
                    using curve_type = Curve;
                    using field_type = typename curve_type::base_field_type;
                    using field_value_type = typename field_type::value_type;
                    using montgomery_element_component = element_g1<curve_type, algebra::curves::forms::montgomery,
                                                                    algebra::curves::coordinates::affine>;
                    using twisted_edwards_element_component =
                        element_g1<curve_type, algebra::curves::forms::twisted_edwards,
                                   algebra::curves::coordinates::affine>;

                    static_assert(std::is_same<field_type, typename montgomery_element_component::field_type>::value);
                    static_assert(
                        std::is_same<field_type, typename twisted_edwards_element_component::field_type>::value);

                    using lookup_component = lookup_signed_3bit<field_type>;

                    /// See definition of \p c in https://zips.z.cash/protocol/protocol.pdf#concretepedersenhash
                    static constexpr std::size_t chunks_per_base_point = []() {
                        using scalar_field_type = typename curve_type::scalar_field_type;

                        typename scalar_field_type::extended_integral_type two(2);
                        std::size_t c = 1;
                        std::size_t prev_c = 0;
                        /// (Fr - 1) / 2
                        typename scalar_field_type::extended_integral_type upper_bound =
                            (scalar_field_type::modulus - 1) / 2;
                        // TODO: first multiplier should be verified
                        /// (chunk_bits + 1) * ((2^(c * (chunk_bits + 1)) - 1) / (2^(chunk_bits + 1) - 1))
                        auto get_test_value = [&](auto i) {
                            return (lookup_component::chunk_bits + 1) *
                                   ((::nil::crypto3::detail::pow(two, i * (lookup_component::chunk_bits + 1)) - 1) /
                                    (::nil::crypto3::detail::pow(two, lookup_component::chunk_bits + 1) - 1));
                        };
                        auto test_value = get_test_value(c);

                        while (test_value <= upper_bound) {
                            prev_c = c++;
                            test_value = get_test_value(c);
                        }

                        return prev_c;
                    }();

                    std::vector<typename montgomery_element_component::addition_component> montgomery_adders;
                    std::vector<typename montgomery_element_component::to_twisted_edwards_component> point_converters;
                    std::vector<typename twisted_edwards_element_component::addition_component> edward_adders;
                    std::vector<element_fp<field_type>> m_windows_x;
                    std::vector<lookup_component> m_windows_y;

                private:
                    /// Number of segments
                    std::size_t basepoints_required(std::size_t n_bits) {
                        return std::ceilf(n_bits / float(lookup_component::chunk_bits * chunks_per_base_point));
                    }

                public:
                    template<typename BasePoints,
                             typename std::enable_if<
                                 std::is_same<
                                     typename twisted_edwards_element_component::group_value_type,
                                     typename std::iterator_traits<typename BasePoints::iterator>::value_type>::value,
                                 bool>::type = true>
                    fixed_base_mul_zcash(blueprint<field_type> &bp,
                                         const BasePoints &base_points,
                                         const blueprint_variable_vector<field_type> &in_scalar) :
                        component<field_type>(bp) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::RandomAccessRangeConcept<const SinglePassRange>));
                        assert(in_scalar.size() > 0);
                        assert((in_scalar.size() % lookup_component::chunk_bits) == 0);
                        assert(basepoints_required(in_scalar.size()) <= base_points.size());

                        const std::size_t window_size_items = 1 << lookup_component::lookup_bits;
                        const std::size_t n_windows = in_scalar.size() / lookup_component::chunk_bits;

                        typename twisted_edwards_element_component::group_value_type start = base_points[0];
                        // Precompute values for all lookup window tables
                        for (std::size_t i = 0; i < n_windows; ++i) {
                            std::vector<field_type> lookup_x;
                            std::vector<field_type> lookup_y;

                            lookup_x.reserve(window_size_items);
                            lookup_y.reserve(window_size_items);

                            if (i % chunks_per_base_point == 0) {
                                start = base_points[i / chunks_per_base_point];
                            }

                            // For each window, generate 4 points, in little endian:
                            // (0,0) = 0 = start = base*2^4i
                            // (1,0) = 1 = 2*start
                            // (0,1) = 2 = 3*start
                            // (1,1) = 3 = 4*start
                            typename twisted_edwards_element_component::group_value_type current = start;
                            for (std::size_t j = 0; j < window_size_items; ++j) {
                                if (j != 0) {
                                    current = current + start;
                                }
                                const typename montgomery_element_component::group_value_type montgomery =
                                    current.to_montgomery();
                                lookup_x.emplace_back(montgomery.X);
                                lookup_y.emplace_back(montgomery.Y);

                                assert(montgomery.to_twisted_edwards() == current);
                            }

                            const auto bits_begin = in_scalar.begin() + (i * lookup_component::chunk_bits);
                            const blueprint_variable_vector<field_type> window_bits_x(
                                bits_begin, bits_begin + lookup_component::lookup_bits);
                            const blueprint_variable_vector<field_type> window_bits_y(
                                bits_begin, bits_begin + lookup_component::chunk_bits);
                            this->m_windows_y.emplace_back(this->bp, lookup_y, window_bits_y);

                            // Pass x lookup as a linear combination to avoid extra constraint.
                            // x_lc = c[0] + b[0] * (c[1]-c[0]) + b[1] * (c[2]-c[0]) + b[0]&b[1] * (c[3] - c[2] - c[1] +
                            // c[0])
                            blueprint_linear_combination<field_type> x_lc;
                            x_lc.assign(
                                this->bp,
                                snark::linear_term<field_type>(field_value_type::one(), lookup_x[0]) +
                                    snark::linear_term<field_type>(window_bits_x[0], (lookup_x[1] - lookup_x[0])) +
                                    snark::linear_term<field_type>(window_bits_x[1], (lookup_x[2] - lookup_x[0])) +
                                    snark::linear_term<field_type>(
                                        this->m_windows_y.back().b0b1,
                                        (lookup_x[3] - lookup_x[2] - lookup_x[1] + lookup_x[0])));
                            this->m_windows_x.emplace_back(x_lc);

                            // current is at 2^2 * start, for next iteration start needs to be 2^4
                            start = current.doubled().doubled();
                        }

                        // Chain adders within one segment together via montgomery adders
                        for (std::size_t i = 1; i < n_windows; ++i) {
                            if (i % chunks_per_base_point == 0) {
                                if (i + 1 < n_windows) {
                                    // 0th lookup will be used in the next iteration to connect
                                    // the first two adders of a new base point.
                                    continue;
                                } else {
                                    // This is the last point. No need to add it to anything in its
                                    // montgomery form, but we have to make sure it will be part of
                                    // the final edwards addition at the end
                                    this->point_converters.emplace_back(
                                        this->bp, montgomery_element_component(this->m_windows_x[i],
                                                                               this->m_windows_y[i].result));
                                }
                            } else if (i % chunks_per_base_point == 1) {
                                this->montgomery_adders.emplace_back(
                                    this->bp,
                                    montgomery_element_component(this->m_windows_x[i - 1],
                                                                 this->m_windows_y[i - 1].result),
                                    montgomery_element_component(this->m_windows_x[i], this->m_windows_y[i].result));
                            } else {
                                this->montgomery_adders.emplace_back(
                                    this->bp, this->montgomery_adders.back().result,
                                    montgomery_element_component(this->m_windows_x[i], this->m_windows_y[i].result));
                            }
                        }

                        // Convert every point at the end of a segment back to edwards format
                        const std::size_t segment_width = chunks_per_base_point - 1;

                        for (std::size_t i = segment_width; i < this->montgomery_adders.size(); i += segment_width) {
                            this->point_converters.emplace_back(this->bp, this->montgomery_adders[i - 1].result);
                        }
                        // TODO: check
                        // The last segment might be incomplete
                        this->point_converters.emplace_back(this->bp, this->montgomery_adders.back().result);

                        // Chain adders of converted segment tails together
                        for (std::size_t i = 1; i < this->point_converters.size(); ++i) {
                            if (i == 1) {
                                this->edward_adders.emplace_back(this->bp, this->point_converters[i - 1].result,
                                                                 this->point_converters[i].result);
                            } else {
                                this->edward_adders.emplace_back(this->bp, this->edward_adders[i - 2].result,
                                                                 this->point_converters[i].result);
                            }
                        }
                    }

                    void generate_r1cs_constraints() {
                        for (auto &lut_y : this->m_windows_y) {
                            lut_y.generate_r1cs_constraints();
                        }

                        for (auto &adder : this->montgomery_adders) {
                            adder.generate_r1cs_constraints();
                        }

                        for (auto &converter : this->point_converters) {
                            converter.generate_r1cs_constraints();
                        }

                        for (auto &adder : this->edward_adders) {
                            adder.generate_r1cs_constraints();
                        }
                    }

                    void generate_r1cs_witness() {
                        // y lookups have to be solved first, because
                        // x depends on the `b0 && b1` constraint.
                        for (auto &lut_y : this->m_windows_y) {
                            lut_y.generate_r1cs_witness();
                        }

                        for (auto &lut_x : this->m_windows_x) {
                            lut_x.evaluate(this->bp);
                        }

                        for (auto &adder : this->montgomery_adders) {
                            adder.generate_r1cs_witness();
                        }

                        for (auto &converter : this->point_converters) {
                            converter.generate_r1cs_witness();
                        }

                        for (auto &adder : this->edward_adders) {
                            adder.generate_r1cs_witness();
                        }
                    }

                    const twisted_edwards_element_component &result() const {
                        return this->edward_adders.size() ? this->edward_adders.back().result :
                                                            this->point_converters.back().result;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_FIXED_BASE_MUL_ZCASH_COMPONENT_HPP
