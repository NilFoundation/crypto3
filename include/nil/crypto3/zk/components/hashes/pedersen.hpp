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
#include <nil/crypto3/hash/pedersen.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/zk/components/algebra/curves/fixed_base_mul_zcash.hpp>
#include <nil/crypto3/zk/components/hashes/hash_io.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                /**
                 * Windowed hash function using elliptic curves point multiplication
                 *
                 * For a given input of scalars, create an equivalent set of base points within a namespace.
                 */
                template<typename Curve = nil::crypto3::algebra::curves::jubjub,
                         typename BasePointGeneratorHash = hashes::sha2<256>,
                         typename HashParams = hashes::find_group_hash_default_params>
                struct pedersen_to_point : public component<typename Curve::base_field_type> {
                    using curve_type = Curve;
                    using commitment_component = fixed_base_mul_zcash<curve_type>;
                    using field_type = typename commitment_component::field_type;
                    using element_component = typename commitment_component::twisted_edwards_element_component;

                    using result_type = element_component;

                    // hash_type is corresponding to the component hash policy
                    // void means there is no implementation of the corresponding hash algorithm
                    using hash_type = void;

                    commitment_component m_commitment;
                    result_type result;

                    static std::vector<typename element_component::group_value_type> get_base_points(std::size_t n) {
                        using group_hash_type = hashes::find_group_hash<HashParams, BasePointGeneratorHash,
                                                                        typename element_component::group_type>;
                        assert(n > 0);
                        std::vector<typename element_component::group_value_type> basepoints;
                        for (std::uint32_t i = 0; i < n; ++i) {
                            basepoints.emplace_back(hash<group_hash_type>({
                                i,
                            }));
                        }
                        return basepoints;
                    }

                    /// Auto allocation of the result.
                    /// Take in_bits as blueprint_variable_vector.
                    pedersen_to_point(blueprint<field_type> &bp,
                                      const detail::blueprint_variable_vector<field_type> &in_bits) :
                        component<field_type>(bp),
                        m_commitment(bp, get_base_points(commitment_component::basepoints_required(in_bits.size())),
                                     in_bits),
                        result(m_commitment.result) {
                    }

                    /// Auto allocation of the result.
                    /// Take in_bits as block_variable.
                    pedersen_to_point(blueprint<field_type> &bp, const block_variable<field_type> &in_block) :
                        pedersen_to_point(bp, in_block.bits) {
                    }

                    /// Auto allocation of the result.
                    /// Take in_bits as digest_variable.
                    pedersen_to_point(blueprint<field_type> &bp, const digest_variable<field_type> &in_digest) :
                        pedersen_to_point(bp, in_digest.bits) {
                    }

                    /// Auto allocation of the result.
                    /// Take in_bits as container of block_variable.
                    template<
                        typename Blocks,
                        typename std::enable_if<
                            std::is_same<block_variable<field_type>,
                                         typename std::iterator_traits<typename Blocks::iterator>::value_type>::value,
                            bool>::type = true>
                    pedersen_to_point(blueprint<field_type> &bp, const Blocks &in_blocks) :
                        pedersen_to_point(bp, [&]() {
                            detail::blueprint_variable_vector<field_type> in_bits;
                            for (const auto &in_block : in_blocks) {
                                in_bits.insert(std::end(in_bits), std::cbegin(in_block.bits), std::cend(in_block.bits));
                            }
                            return in_bits;
                        }()) {
                    }

                    /// Auto allocation of the result.
                    /// Take in_bits as container of digest_variable.
                    template<
                        typename Digests,
                        typename std::enable_if<
                            std::is_same<digest_variable<field_type>,
                                         typename std::iterator_traits<typename Digests::iterator>::value_type>::value,
                            bool>::type = true>
                    pedersen_to_point(blueprint<field_type> &bp, const Digests &in_digests) :
                        pedersen_to_point(bp, [&]() {
                            detail::blueprint_variable_vector<field_type> in_bits;
                            for (const auto &in_digest : in_digests) {
                                in_bits.insert(std::end(in_bits), std::cbegin(in_digest.bits),
                                               std::cend(in_digest.bits));
                            }
                            return in_bits;
                        }()) {
                    }

                    /// Manual allocation of the result
                    /// Take in_bits as blueprint_variable_vector.
                    pedersen_to_point(blueprint<field_type> &bp,
                                      const detail::blueprint_variable_vector<field_type> &in_bits,
                                      const result_type &in_result) :
                        component<field_type>(bp),
                        m_commitment(bp, get_base_points(commitment_component::basepoints_required(in_bits.size())),
                                     in_bits, in_result),
                        result(m_commitment.result) {
                    }

                    /// Manual allocation of the result
                    /// Take in_bits as block_variable.
                    pedersen_to_point(blueprint<field_type> &bp, const block_variable<field_type> &in_block,
                                      const result_type &in_result) :
                        pedersen_to_point(bp, in_block.bits, in_result) {
                    }

                    /// Manual allocation of the result
                    /// Take in_bits as digest_variable.
                    pedersen_to_point(blueprint<field_type> &bp, const digest_variable<field_type> &in_digest,
                                      const result_type &in_result) :
                        pedersen_to_point(bp, in_digest.bits, in_result) {
                    }

                    /// Manual allocation of the result
                    /// Take in_bits as container of block_variable.
                    template<
                        typename Blocks,
                        typename std::enable_if<
                            std::is_same<block_variable<field_type>,
                                         typename std::iterator_traits<typename Blocks::iterator>::value_type>::value,
                            bool>::type = true>
                    pedersen_to_point(blueprint<field_type> &bp, const Blocks &in_blocks,
                                      const result_type &in_result) :
                        pedersen_to_point(
                            bp,
                            [&]() {
                                detail::blueprint_variable_vector<field_type> in_bits;
                                for (const auto &in_block : in_blocks) {
                                    in_bits.insert(std::end(in_bits), std::cbegin(in_block.bits),
                                                   std::cend(in_block.bits));
                                }
                                return in_bits;
                            }(),
                            in_result) {
                    }

                    /// Manual allocation of the result
                    /// Take in_bits as container of digest_variable.
                    template<
                        typename Digests,
                        typename std::enable_if<
                            std::is_same<digest_variable<field_type>,
                                         typename std::iterator_traits<typename Digests::iterator>::value_type>::value,
                            bool>::type = true>
                    pedersen_to_point(blueprint<field_type> &bp, const Digests &in_digests,
                                      const result_type &in_result) :
                        pedersen_to_point(
                            bp,
                            [&]() {
                                detail::blueprint_variable_vector<field_type> in_bits;
                                for (const auto &in_digest : in_digests) {
                                    in_bits.insert(std::end(in_bits), std::cbegin(in_digest.bits),
                                                   std::cend(in_digest.bits));
                                }
                                return in_bits;
                            }(),
                            in_result) {
                    }

                    // TODO: ignored for now, enforce bitness checking constrains
                    void generate_r1cs_constraints(bool ensure_output_bitness = false) {
                        this->m_commitment.generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        this->m_commitment.generate_r1cs_witness();
                    }
                };

                template<typename Curve = nil::crypto3::algebra::curves::jubjub,
                         typename BasePointGeneratorHash = hashes::sha2<256>,
                         typename HashParams = hashes::find_group_hash_default_params>
                struct pedersen : public component<typename Curve::base_field_type> {
                    using curve_type = Curve;
                    using hash_component = pedersen_to_point<curve_type, BasePointGeneratorHash, HashParams>;
                    using field_type = typename hash_component::field_type;
                    using element_component = typename hash_component::element_component;
                    using to_bits_component = typename element_component::to_bits_component;

                    using result_type = digest_variable<field_type>;

                    // hash_type is corresponding to the component hash policy
                    using hash_type = nil::crypto3::hashes::pedersen<HashParams, BasePointGeneratorHash,
                                                                     typename element_component::group_type>;
                    // TODO: retrieve digest_bits from hash_type
                    static constexpr std::size_t digest_bits = field_type::value_bits;

                    hash_component hasher;
                    to_bits_component to_bits_converter;
                    result_type result;

                    /// Auto allocation of the result.
                    /// Take in_bits as blueprint_variable_vector.
                    pedersen(blueprint<field_type> &bp, const detail::blueprint_variable_vector<field_type> &in_bits) :
                        component<field_type>(bp), hasher(bp, in_bits), to_bits_converter(bp, hasher.result),
                        result(bp, digest_bits, to_bits_converter.result, 0) {
                        assert(this->result.digest_size == digest_bits);
                    }

                    /// Auto allocation of the result.
                    /// Take in_bits as block_variable.
                    pedersen(blueprint<field_type> &bp, const block_variable<field_type> &in_block) :
                        pedersen(bp, in_block.bits) {
                    }

                    /// Auto allocation of the result.
                    /// Take in_bits as digest_variable.
                    pedersen(blueprint<field_type> &bp, const digest_variable<field_type> &in_digest) :
                        pedersen(bp, in_digest.bits) {
                    }

                    /// Auto allocation of the result.
                    /// Take in_bits as container of block_variable.
                    template<
                        typename Blocks,
                        typename std::enable_if<
                            std::is_same<block_variable<field_type>,
                                         typename std::iterator_traits<typename Blocks::iterator>::value_type>::value,
                            bool>::type = true>
                    pedersen(blueprint<field_type> &bp, const Blocks &in_blocks) :
                        pedersen(bp, [&]() {
                            detail::blueprint_variable_vector<field_type> in_bits;
                            for (const auto &in_block : in_blocks) {
                                in_bits.insert(std::end(in_bits), std::cbegin(in_block.bits), std::cend(in_block.bits));
                            }
                            return in_bits;
                        }()) {
                    }

                    /// Auto allocation of the result.
                    /// Take in_bits as container of digest_variable.
                    template<
                        typename Digests,
                        typename std::enable_if<
                            std::is_same<digest_variable<field_type>,
                                         typename std::iterator_traits<typename Digests::iterator>::value_type>::value,
                            bool>::type = true>
                    pedersen(blueprint<field_type> &bp, const Digests &in_digests) :
                        pedersen(bp, [&]() {
                            detail::blueprint_variable_vector<field_type> in_bits;
                            for (const auto &in_digest : in_digests) {
                                in_bits.insert(std::end(in_bits), std::cbegin(in_digest.bits),
                                               std::cend(in_digest.bits));
                            }
                            return in_bits;
                        }()) {
                    }

                    /// Manual allocation of the result.
                    /// Take in_bits as blueprint_variable_vector.
                    pedersen(blueprint<field_type> &bp, const detail::blueprint_variable_vector<field_type> &in_bits,
                             const result_type &in_result) :
                        component<field_type>(bp),
                        hasher(bp, in_bits), to_bits_converter(bp, hasher.result, in_result.bits), result(in_result) {
                        assert(this->result.digest_size == digest_bits);
                    }

                    /// Manual allocation of the result.
                    /// Take in_bits as block_variable.
                    pedersen(blueprint<field_type> &bp, const block_variable<field_type> &in_block,
                             const result_type &in_result) :
                        pedersen(bp, in_block.bits, in_result) {
                    }

                    /// Manual allocation of the result.
                    /// Take in_bits as digest_variable.
                    pedersen(blueprint<field_type> &bp, const digest_variable<field_type> &in_digest,
                             const result_type &in_result) :
                        pedersen(bp, in_digest.bits, in_result) {
                    }

                    /// Manual allocation of the result.
                    /// Take in_bits as container of block_variable.
                    template<
                        typename Blocks,
                        typename std::enable_if<
                            std::is_same<block_variable<field_type>,
                                         typename std::iterator_traits<typename Blocks::iterator>::value_type>::value,
                            bool>::type = true>
                    pedersen(blueprint<field_type> &bp, const Blocks &in_blocks, const result_type &in_result) :
                        pedersen(
                            bp,
                            [&]() {
                                detail::blueprint_variable_vector<field_type> in_bits;
                                for (const auto &in_block : in_blocks) {
                                    in_bits.insert(std::end(in_bits), std::cbegin(in_block.bits),
                                                   std::cend(in_block.bits));
                                }
                                return in_bits;
                            }(),
                            in_result) {
                    }

                    /// Manual allocation of the result.
                    /// Take in_bits as container of digest_variable.
                    template<
                        typename Digests,
                        typename std::enable_if<
                            std::is_same<digest_variable<field_type>,
                                         typename std::iterator_traits<typename Digests::iterator>::value_type>::value,
                            bool>::type = true>
                    pedersen(blueprint<field_type> &bp, const Digests &in_digests, const result_type &in_result) :
                        pedersen(
                            bp,
                            [&]() {
                                detail::blueprint_variable_vector<field_type> in_bits;
                                for (const auto &in_digest : in_digests) {
                                    in_bits.insert(std::end(in_bits), std::cbegin(in_digest.bits),
                                                   std::cend(in_digest.bits));
                                }
                                return in_bits;
                            }(),
                            in_result) {
                    }

                    // TODO: ignored for now, enforce bitness checking constrains
                    void generate_r1cs_constraints(bool ensure_output_bitness = false) {
                        this->hasher.generate_r1cs_constraints(ensure_output_bitness);
                        this->to_bits_converter.generate_r1cs_constraints();
                        this->result.generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        this->hasher.generate_r1cs_witness();
                        // to_bits_converter generate witness also for result
                        this->to_bits_converter.generate_r1cs_witness();
                    }

                    static std::size_t get_digest_len() {
                        return digest_bits;
                    }
                };

                /// @brief See https://zips.z.cash/protocol/protocol.pdf#concretewindowedcommit
                template<typename Curve = nil::crypto3::algebra::curves::jubjub,
                         typename BasePointGeneratorHash = hashes::sha2<256>,
                         typename HashParams = hashes::find_group_hash_default_params>
                struct pedersen_commitment_to_point : public component<typename Curve::base_field_type> {
                    using hash_component = pedersen_to_point<Curve, BasePointGeneratorHash, HashParams>;
                    using element_component = typename hash_component::element_component;
                    using addition_component = typename element_component::addition_component;

                    using field_type = typename hash_component::field_type;
                    using result_type = typename hash_component::result_type;

                public:
                    result_type result;

                private:
                    hash_component hasher;
                    element_component random_point;
                    addition_component adder;

                    /// Auto allocation of the result
                    /// Take in_bits as blueprint_variable_vector.
                    pedersen_commitment_to_point(blueprint<field_type> &bp,
                                                 const detail::blueprint_variable_vector<field_type> &in_bits) :
                        component<field_type>(bp),
                        // public field
                        result(bp),
                        // private fields
                        hasher(bp, in_bits), random_point(bp), adder(bp, hasher.result, random_point, result) {
                    }

                    /// Manual allocation of the result
                    /// Take in_bits as blueprint_variable_vector.
                    pedersen_commitment_to_point(blueprint<field_type> &bp,
                                                 const detail::blueprint_variable_vector<field_type> &in_bits,
                                                 const result_type &result) :
                        component<field_type>(bp),
                        // public field
                        result(result),
                        // private fields
                        hasher(bp, in_bits), random_point(bp), adder(bp, hasher.result, random_point, result) {
                    }

                    void generate_r1cs_constraints(bool ensure_output_bitness = false) {
                        hasher.generate_r1cs_constraints(ensure_output_bitness);
                        adder.generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness(const typename field_type::value_type &r) {
                        using group_hash_type = hashes::find_group_hash<HashParams, BasePointGeneratorHash,
                                                                        typename element_component::group_type>;

                        hasher.generate_r1cs_witness();
                        random_point.generate_r1cs_witness(r * hash<group_hash_type>(std::vector<std::uint8_t> {
                                                                   'r',
                                                               }));
                        adder.generate_r1cs_witness();
                    }
                };

                template<typename Curve = nil::crypto3::algebra::curves::jubjub,
                         typename BasePointGeneratorHash = hashes::sha2<256>,
                         typename HashParams = hashes::find_group_hash_default_params>
                struct pedersen_commitment : public component<typename Curve::base_field_type> {
                    using commitment_component =
                        pedersen_commitment_to_point<Curve, BasePointGeneratorHash, HashParams>;
                    using element_component = typename commitment_component::element_component;
                    using to_bits_component = typename element_component::to_bits_component;

                    using field_type = typename commitment_component::field_type;
                    using result_type = digest_variable<field_type>;

                private:
                    commitment_component commiter;
                    to_bits_component to_bits_converter;

                public:
                    result_type result;

                    /// Auto allocation of the result
                    /// Take in_bits as blueprint_variable_vector.
                    pedersen_commitment(blueprint<field_type> &bp,
                                        const detail::blueprint_variable_vector<field_type> &in_bits) :
                        component<field_type>(bp),
                        // private fields
                        commiter(bp, in_bits), to_bits_converter(bp, commiter.result),
                        // public field
                        result(bp, field_type::value_bits, to_bits_converter.result, 0) {
                    }

                    /// Manual allocation of the result
                    /// Take in_bits as blueprint_variable_vector.
                    pedersen_commitment(blueprint<field_type> &bp,
                                        const detail::blueprint_variable_vector<field_type> &in_bits,
                                        const result_type &result) :
                        component<field_type>(bp),
                        // private fields
                        commiter(bp, in_bits), to_bits_converter(bp, commiter.result, result.bits),
                        // public field
                        result(result) {
                    }

                    void generate_r1cs_constraints(bool ensure_output_bitness = false) {
                        commiter.generate_r1cs_constraints(ensure_output_bitness);
                        to_bits_converter.generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness(const typename field_type::value_type &r) {
                        commiter.generate_r1cs_witness(r);
                        // to_bits_converter generate witness also for result
                        to_bits_converter.generate_r1cs_witness();
                        result.generate_r1cs_constraints();
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_HASHES_PEDERSEN_HPP