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
                template<typename Curve,
                         typename Hash = hashes::sha2<256>,
                         typename HashParams = hashes::find_group_hash_default_params>
                struct pedersen : public component<typename Curve::base_field_type> {
                    using curve_type = Curve;
                    using hash_type = Hash;
                    using hash_params = HashParams;
                    using commitment_component = fixed_base_mul_zcash<curve_type>;
                    using field_type = typename commitment_component::field_type;
                    using element_component = typename commitment_component::twisted_edwards_element_component;

                    commitment_component m_commitment;

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

                    pedersen(blueprint<field_type> &bp, const blueprint_variable_vector<field_type> &in_bits) :
                        component<field_type>(bp),
                        m_commitment(bp,
                                     get_base_points(commitment_component::basepoints_required(in_bits.size())),
                                     in_bits) {
                    }

                    void generate_r1cs_constraints() {
                        m_commitment.generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        m_commitment.generate_r1cs_witness();
                    }
                };

                // /**
                //  * The X coordinate is distinct
                //  */
                // template<typename CurveType>
                // struct PedersenHashToBits : public component<typename CurveType::base_field_type> {
                //
                //     using curve_type = CurveType;
                //     using field_type = typename curve_type::base_field_type;
                //     constexpr static const algebra::curves::representations representation_type =
                //         algebra::curves::representations::edwards;
                //     using element_component = element_g1<curve_type, representation_type>;
                //
                //     PedersenHash<curve_type> pedersen_hash;
                //     element_component pedersen_hash_result;
                //     field_to_bits_strict<field_type> tobits;
                //
                //     PedersenHashToBits(blueprint<field_type> &bp,
                //                        const blueprint_variable_vector<field_type> &bits,
                //                        blueprint_variable_vector<field_type> &result) :
                //         component<field_type>(bp),
                //         pedersen_hash_result(bp), pedersen_hash(bp, bits, pedersen_hash_result),
                //         tobits(bp, pedersen_hash_result.X, result) {
                //     }
                //
                //     void generate_r1cs_constraints() {
                //         pedersen_hash.generate_r1cs_constraints();
                //         tobits.generate_r1cs_constraints();
                //     }
                //
                //     void generate_r1cs_witness() {
                //         pedersen_hash.generate_r1cs_witness();
                //         tobits.generate_r1cs_witness();
                //     }
                // };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_HASHES_PEDERSEN_HPP