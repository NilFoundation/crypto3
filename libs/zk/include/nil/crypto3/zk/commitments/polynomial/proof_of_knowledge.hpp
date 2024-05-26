//---------------------------------------------------------------------------//
// Copyright (c) 2022 Noam Y <@NoamDev>
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

#ifndef CRYPTO3_ZK_PROOF_OF_KNOWLEDGE_HPP
#define CRYPTO3_ZK_PROOF_OF_KNOWLEDGE_HPP

#include <nil/crypto3/zk/commitments/detail/polynomial/element_proof_of_knowledge.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/marshalling/algebra/types/fast_curve_element.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/blake2b.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                template<typename CurveType>
                struct proof_of_knowledge {
                    typedef CurveType curve_type;
                    using scalar_field_type = typename curve_type::scalar_field_type;
                    using scalar_field_value_type = typename scalar_field_type::value_type;
                    using g1_type = typename CurveType::template g1_type<>;
                    using g2_type = typename CurveType::template g2_type<>;
                    using g1_value_type = typename g1_type::value_type;
                    using g2_value_type = typename g2_type::value_type;
                    typedef detail::element_pok<curve_type> proof_type;

                    template<typename RNG = boost::random_device>
                    static proof_type proof_eval(const scalar_field_value_type &x,
                                                 const std::vector<std::uint8_t> &transcript,
                                                 std::uint8_t personalization,
                                                 RNG &&rng = boost::random_device()) {
                        const g1_value_type g1_s = algebra::random_element<g1_type>(rng);
                        const g1_value_type g1_s_x = x * g1_s;
                        const g2_value_type g2_s = compute_g2_s(g1_s, g1_s_x, transcript, personalization);
                        const g2_value_type g2_s_x = x * g2_s;

                        return proof_type(g1_s, g1_s_x, g2_s_x);
                    }

                    static bool verify_eval(const proof_type &proof,
                                            const std::vector<std::uint8_t> &transcript,
                                            std::uint8_t personalization) {
                        const g2_value_type g2_s = compute_g2_s(proof.g1_s, proof.g1_s_x, transcript, personalization);
                        return verify_eval(proof, g2_s);
                    }

                    static bool verify_eval(const proof_type &proof, const g2_value_type &g2_s) {
                        return algebra::pair_reduced<curve_type>(proof.g1_s, proof.g2_s_x) ==
                               algebra::pair_reduced<curve_type>(proof.g1_s_x, g2_s);
                    }

                    static g2_value_type compute_g2_s(const g1_value_type &g1_s,
                                                      const g1_value_type &g1_s_x,
                                                      const std::vector<std::uint8_t> &transcript,
                                                      std::uint8_t personalization) {
                        std::vector<std::uint8_t> personalization_transcript_g1s_g1sx;

                        personalization_transcript_g1s_g1sx.emplace_back(personalization);

                        std::copy(std::cbegin(transcript),
                                  std::cend(transcript),
                                  std::back_inserter(personalization_transcript_g1s_g1sx));

                        auto g1_s_blob = serialize_g1_uncompressed(g1_s);
                        std::copy(std::cbegin(g1_s_blob), std::cend(g1_s_blob), std::back_inserter(g1_s_blob));

                        auto g1_s_x_blob = serialize_g1_uncompressed(g1_s_x);
                        std::copy(std::cbegin(g1_s_x_blob), std::cend(g1_s_x_blob), std::back_inserter(g1_s_x_blob));

                        std::vector<std::uint8_t> hash =
                                nil::crypto3::hash<hashes::blake2b<256>>(personalization_transcript_g1s_g1sx);

                        // this is unsecure as it's only using the first byte,
                        // it should be chacha which is currently broken
                        boost::random::mt19937 gen;
                        // random::chacha gen;
                        gen.seed(hash[0]);
                        // gen.seed(hash.begin(), hash.end());
                        return algebra::random_element<g2_type>(gen);
                    }

                    static std::vector<std::uint8_t> serialize_g1_uncompressed(const g1_value_type &g) {
                        using endianness = nil::marshalling::option::little_endian;
                        auto filled_val =
                                nil::crypto3::marshalling::types::fill_fast_curve_element<g1_type, endianness>(g);
                        std::vector<std::uint8_t> blob(filled_val.length());
                        auto it = std::begin(blob);
                        nil::marshalling::status_type status = filled_val.write(it, blob.size());
                        if (status != nil::marshalling::status_type::success) {
                            return {};
                        } else {
                            return blob;
                        }
                    }
                };
            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PROOF_OF_KNOWLEDGE_HPP