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

#ifndef CRYPTO3_ZK_BLUEPRINT_HASHES_PEDERSEN_HPP
#define CRYPTO3_ZK_BLUEPRINT_HASHES_PEDERSEN_HPP

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/find_group_hash.hpp>
#include <nil/crypto3/hash/algorithm/to_curve.hpp>

#include <nil/crypto3/zk/components/algebra/curves/fixed_base_mul_zcash.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                /**
                 * Windowed hash function using elliptic curves point multiplication
                 *
                 * For a given input of scalars, create an equivalent set of base points within a namespace.
                 */
                template<typename Curve, typename Hash = hashes::sha2<256>,
                         typename HashParams = hashes::find_group_hash_default_params>
                struct pedersen_to_point : public component<typename Curve::base_field_type> {
                    using curve_type = Curve;
                    using hash_type = Hash;
                    using hash_params = HashParams;
                    using commitment_component = fixed_base_mul_zcash<curve_type>;
                    using field_type = typename commitment_component::field_type;
                    using element_component = typename commitment_component::twisted_edwards_element_component;
                    using result_type = element_component;

                    commitment_component m_commitment;
                    result_type &result;

                    static std::vector<typename element_component::group_value_type> get_base_points(std::size_t n) {
                        using group_hash_type =
                            hashes::find_group_hash<hash_params, hash_type, typename element_component::group_type>;
                        assert(n > 0);
                        std::vector<typename element_component::group_value_type> basepoints;
                        for (std::uint32_t i = 0; i < n; ++i) {
                            // TODO: possible error here - i should be in little endian
                            basepoints.emplace_back(to_curve<group_hash_type>({
                                i,
                            }));
                        }
                        return basepoints;
                    }

                    /// Auto allocation of the result
                    pedersen_to_point(blueprint<field_type> &bp, const blueprint_variable_vector<field_type> &in_bits) :
                        component<field_type>(bp),
                        m_commitment(bp, get_base_points(commitment_component::basepoints_required(in_bits.size())),
                                     in_bits),
                        result(m_commitment.result) {
                    }

                    /// Manual allocation of the result
                    pedersen_to_point(blueprint<field_type> &bp, const blueprint_variable_vector<field_type> &in_bits,
                                      const result_type &in_result) :
                        component<field_type>(bp),
                        m_commitment(bp, get_base_points(commitment_component::basepoints_required(in_bits.size())),
                                     in_bits, in_result),
                        result(m_commitment.result) {
                    }

                    void generate_r1cs_constraints() {
                        this->m_commitment.generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        this->m_commitment.generate_r1cs_witness();
                    }
                };

                template<typename Curve, typename Hash = hashes::sha2<256>,
                         typename HashParams = hashes::find_group_hash_default_params>
                struct pedersen : public component<typename Curve::base_field_type> {
                    using curve_type = Curve;
                    using hash_type = Hash;
                    using hash_params = HashParams;
                    using hash_component = pedersen_to_point<curve_type, hash_type, hash_params>;
                    using field_type = typename hash_component::field_type;
                    using element_component = typename hash_component::element_component;
                    using to_bits_component = typename element_component::to_bits_component;
                    using result_type = typename to_bits_component::result_type;

                    hash_component hash_creator;
                    to_bits_component to_bits_converter;
                    result_type &result;

                    /// Auto allocation of the result
                    pedersen(blueprint<field_type> &bp, const blueprint_variable_vector<field_type> &in_bits) :
                        component<field_type>(bp), hash_creator(bp, in_bits),
                        to_bits_converter(bp, hash_creator.result), result(to_bits_converter.result) {
                    }

                    /// Manual allocation of the result
                    pedersen(blueprint<field_type> &bp, const blueprint_variable_vector<field_type> &in_bits,
                             const result_type &in_result) :
                        component<field_type>(bp),
                        hash_creator(bp, in_bits), to_bits_converter(bp, hash_creator.result, in_result),
                        result(to_bits_converter.result) {
                    }

                    void generate_r1cs_constraints() {
                        this->hash_creator.generate_r1cs_constraints();
                        this->to_bits_converter.generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        this->hash_creator.generate_r1cs_witness();
                        this->to_bits_converter.generate_r1cs_witness();
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_HASHES_PEDERSEN_HPP