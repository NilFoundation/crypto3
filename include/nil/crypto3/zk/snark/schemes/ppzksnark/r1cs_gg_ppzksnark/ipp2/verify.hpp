//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_VERIFY_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_VERIFY_HPP

#include <memory>
#include <vector>
#include <tuple>

#include <boost/iterator/zip_iterator.hpp>

#include <nil/crypto3/detail/pack_numeric.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/verification_key.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/proof.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/srs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                struct Op {
                    typedef CurveType curve_type;

                    typedef typename curve_type::pairing::fqk_type::value_type TAB;
                    typedef typename curve_type::pairing::fqk_type::value_type UAB;
                    typedef typename curve_type::pairing::fqk_type::value_type ZAB;
                    typedef typename curve_type::pairing::fqk_type::value_type TC;
                    typedef typename curve_type::pairing::fqk_type::value_type UC;
                    typedef typename curve_type::pairing::g1_type::value_type ZC;
                };

                /// Keeps track of the variables that have been sent by the prover and must
                /// be multiplied together by the verifier. Both MIPP and TIPP are merged
                /// together.
                template<typename CurveType>
                struct gipa_tuz {
                    typedef CurveType curve_type;
                    typedef typename curve_type::scalar_field_type::value_type fr_type;

                    std::pair<typename curve_type::pairing::fqk_type::value_type, fr_type::value_type> tab;
                    std::pair<typename curve_type::pairing::fqk_type::value_type, fr_type::value_type> uab;
                    std::pair<typename curve_type::pairing::fqk_type::value_type, fr_type::value_type> zab;
                    std::pair<typename curve_type::pairing::fqk_type::value_type, fr_type::value_type> tc;
                    std::pair<typename curve_type::pairing::fqk_type::value_type, fr_type::value_type> uc;
                    std::pair<typename curve_type::pairing::g1_type, fr_type> zc;
                };

                /// gipa_verify_tipp_mipp recurse on the proof and statement and produces the final
                /// values to be checked by TIPP and MIPP verifier, namely, for TIPP for example:
                /// * T,U: the final commitment values of A and B
                /// * Z the final product between A and B.
                /// * Challenges are returned in inverse order as well to avoid
                /// repeating the operation multiple times later on.
                /// * There are T,U,Z vectors as well for the MIPP relationship. Both TIPP and
                /// MIPP share the same challenges however, enabling to re-use common operations
                /// between them, such as the KZG proof for commitment keys.
                template<typename CurveType, typename Hash = hashes::sha2<256>>
                std::tuple<gipa_tuz<CurveType>, std::vector<typename CurveType::scalar_field_type::value_type>,
                           std::vector<typename CurveType::scalar_field_type::value_type>>
                    gipa_verify_tipp_mipp(const r1cs_gg_ppzksnark_aggregate_proof<CurveType> &proof) {
                    std::vector<typename CurveType::scalar_field_type::value_type> challenges, challenges_inv;

                    typename CurveType::scalar_field_type::value_type default_transcript =
                        typename CurveType::scalar_field_type::value_type::zero();

                    // We first generate all challenges as this is the only consecutive process
                    // that can not be parallelized then we scale the commitments in a
                    // parallelized way
                    std::for_each(
                        boost::make_zip_iterator(
                            std::make_tuple(proof.tmipp.gipa.comms_ab.begin(), proof.tmipp.gipa.z_ab.begin(),
                                            proof.tmipp.gipa.comms_c.begin(), proof.tmipp.gipa.z_c.begin())),
                        boost::make_zip_iterator(
                            std::make_tuple(proof.tmipp.gipa.comms_ab.end(), proof.tmipp.gipa.z_ab.end(),
                                            proof.tmipp.gipa.comms_c.end(), proof.tmipp.gipa.z_c.end())),
                        [&](const std::tuple<const std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>,
                                                             r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>> &,
                                             const std::pair<typename CurveType::pairing::fqk_type::value_type,
                                                             typename CurveType::pairing::fqk_type::value_type> &,
                                             const std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>,
                                                             r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>> &,
                                             const std::pair<typename CurveType::g1_type::value_type,
                                                             typename CurveType::g1_type::value_type> &> &t) {
                            auto tab_l = std::get<0>(std::get<0>(t));
                            auto tab_r = std::get<1>(std::get<0>(t));

                            auto zab_l = std::get<0>(std::get<1>(t));
                            auto zab_r = std::get<1>(std::get<1>(t));

                            auto tc_l = std::get<0>(std::get<2>(t));
                            auto tc_r = std::get<1>(std::get<2>(t));

                            auto zc_l = std::get<0>(std::get<3>(t));
                            auto zc_r = std::get<1>(std::get<3>(t));

                            // Fiat-Shamir challenge
                            auto transcript = challenges.empty() ? *(challenges.end() - 1) : default_transcript;

                            std::size_t counter_nonce = 1;
                            std::array<std::uint8_t, sizeof(std::size_t)> counter_nonce_bytes;
                            crypto3::detail::pack<stream_endian::big_byte_big_bit>({counter_nonce},
                                                                                   counter_nonce_bytes);
                            accumulator_set<Hash> acc;

                            hash<Hash>(counter_nonce_bytes, acc);
                            hash<Hash>(transcript, acc);
                            hash<Hash>(std::get<0>(tab_l), acc);
                            hash<Hash>(std::get<1>(tab_l), acc);
                            hash<Hash>(std::get<0>(tab_r), acc);
                            hash<Hash>(std::get<1>(tab_r), acc);
                            hash<Hash>(zab_l, acc);
                            hash<Hash>(zab_r, acc);
                            hash<Hash>(zc_l, acc);
                            hash<Hash>(zc_r, acc);
                            hash<Hash>(std::get<0>(tc_l), acc);
                            hash<Hash>(std::get<1>(tc_l), acc);
                            hash<Hash>(std::get<0>(tc_r), acc);
                            hash<Hash>(std::get<1>(tc_r), acc);

                            typename Hash::digest_type d = accumulators::extract::hash<Hash>(acc);
                            typename CurveType::scalar_field_type::value_type c;
                            multiprecision::import_bits(c.data, d);

                            challenges.emplace_back(c);
                            challenges_inv.emplace_back(c.inversed());
                        });

                    gipa_tuz<CurveType> final_res = {std::get<0>(proof.com_ab), std::get<1>(proof.com_ab), proof.ip_ab,
                                                     std::get<0>(proof.com_c),  std::get<1>(proof.com_c),  proof.agg_c};

                    // we first multiply each entry of the Z U and L vectors by the respective
                    // challenges independently
                    // Since at the end we want to multiple all "t" values together, we do
                    // multiply all of them in parrallel and then merge then back at the end.
                    // same for u and z.
                    std::for_each(
                        boost::make_zip_iterator(
                            std::make_tuple(proof.tmipp.gipa.comms_ab.begin(), proof.tmipp.gipa.z_ab.begin(),
                                            proof.tmipp.gipa.comms_c.begin(), proof.tmipp.gipa.z_c.begin(),
                                            challenges.begin(), challenges_inv.begin())),
                        boost::make_zip_iterator(
                            std::make_tuple(proof.tmipp.gipa.comms_ab.end(), proof.tmipp.gipa.z_ab.end(),
                                            proof.tmipp.gipa.comms_c.end(), proof.tmipp.gipa.z_c.end(),
                                            challenges.end(), challenges_inv.end())),
                        [&](const std::tuple<const std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>,
                                                             r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>> &,
                                             const std::pair<typename CurveType::pairing::fqk_type::value_type,
                                                             typename CurveType::pairing::fqk_type::value_type> &,
                                             const std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>,
                                                             r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>> &,
                                             const std::pair<typename CurveType::g1_type::value_type,
                                                             typename CurveType::g1_type::value_type> &,
                                             const typename CurveType::scalar_field_type::value_type &,
                                             const typename CurveType::scalar_field_type::value_type &> &t) {
                            // T and U values for right and left for AB part
                            auto tab_l = std::get<0>(std::get<0>(std::get<0>(t)));
                            auto uab_l = std::get<1>(std::get<0>(std::get<0>(t)));
                            auto tab_r = std::get<0>(std::get<1>(std::get<0>(t)));
                            auto uab_r = std::get<1>(std::get<1>(std::get<0>(t)));

                            auto zab_l = std::get<0>(std::get<1>(t));
                            auto zab_r = std::get<1>(std::get<1>(t));

                            // T and U values for right and left for C part
                            auto tc_l = std::get<0>(std::get<0>(std::get<2>(t)));
                            auto uc_l = std::get<1>(std::get<0>(std::get<2>(t)));
                            auto tc_r = std::get<0>(std::get<1>(std::get<2>(t)));
                            auto uc_r = std::get<1>(std::get<1>(std::get<2>(t)));

                            auto zc_l = std::get<0>(std::get<3>(t));
                            auto zc_r = std::get<1>(std::get<3>(t));

                            // we multiple left side by x and right side by x^-1
                            vec ![
                                Op<CurveType>::TAB(tab_l, std::get<4>(t)),
                                Op<CurveType>::tab(tab_r, c_inv_repr),
                                Op::UAB(uab_l, c_repr),
                                Op::UAB(uab_r, c_inv_repr),
                                Op::ZAB(zab_l, c_repr),
                                Op::ZAB(zab_r, c_inv_repr),
                                Op::TC::<E>(tc_l, c_repr),
                                Op::TC(tc_r, c_inv_repr),
                                Op::UC(uc_l, c_repr),
                                Op::UC(uc_r, c_inv_repr),
                                Op::ZC(zc_l, c_repr),
                                Op::ZC(zc_r, c_inv_repr),
                            ]
                        });
                }

                /// verify_tipp_mipp returns a pairing equation to check the tipp proof.  $r$ is
                /// the randomness used to produce a random linear combination of A and B and
                /// used in the MIPP part with C
                template<typename CurveType>
                PairingCheck<CurveType> verify_tipp_mipp(const r1cs_gg_ppzksnark_verifying_srs<CurveType> &v_srs,
                                                         const r1cs_gg_ppzksnark_aggregate_proof<CurveType> &proof,
                                                         const typename CurveType::scalar_field_type::value_type &r_shift) {
                    // (T,U), Z for TIPP and MIPP  and all challenges
                    std::tuple<gipa_tuz<CurveType>, std::vector<typename CurveType::scalar_field_type::value_type>,
                               std::vector<typename CurveType::scalar_field_type::value_type>>
                        gtmp = gipa_verify_tipp_mipp(proof);
                    auto &final_res = std::get<0>(gtmp);
                    auto &challenges = std::get<1>(gtmp);
                    auto &challenges_inv = std::get<2>(gtmp);

                    // we reverse the order so the KZG polynomial have them in the expected
                    // order to construct them in logn time.
                    std::reverse(challenges.begin(), challenges.end());
                    std::reverse(challenges_inv.begin(), challenges_inv.end());

                    // Verify commitment keys wellformed
                    auto fvkey = proof.tmipp.gipa.final_vkey;
                    auto fwkey = proof.tmipp.gipa.final_wkey;
                }

                template<typename CurveType, typename InputPublicInputsIterator>
                bool verify_aggregate_proof(const r1cs_gg_ppzksnark_verifying_srs<CurveType> &ip_verifier_srs,
                                            const r1cs_gg_ppzksnark_processed_verification_key<CurveType> &pvk,
                                            InputPublicInputsIterator public_inputs_first,
                                            InputPublicInputsIterator public_inputs_last,
                                            const r1cs_gg_ppzksnark_aggregate_proof<CurveType> &proof) {

                    // Random linear combination of proofs
                    std::size_t counter_nonce = 1;
                    std::array<std::uint8_t, sizeof(std::size_t)> counter_nonce_bytes;
                    crypto3::detail::pack<stream_endian::big_byte_big_bit>({counter_nonce}, counter_nonce_bytes);
                    accumulator_set<hashes::sha2<256>> acc;

                    hash<hashes::sha2<256>>(counter_nonce_bytes, acc);
                    hash<hashes::sha2<256>>(std::get<0>(proof.com_ab), acc);
                    hash<hashes::sha2<256>>(std::get<1>(proof.com_ab), acc);
                    hash<hashes::sha2<256>>(std::get<0>(proof.com_c), acc);
                    hash<hashes::sha2<256>>(std::get<1>(proof.com_c), acc);

                    typename hashes::sha2<256>::digest_type d = accumulators::extract::hash<hashes::sha2<256>>(acc);
                    typename CurveType::scalar_field_type::value_type r;
                    crypto3::detail::pack(d, r.data);
                    r = r.inversed();

                    InputPublicInputsIterator vpitr = public_inputs_first;

                    while (vpitr != public_inputs_last) {
                        BOOST_ASSERT_MSG(vpitr->size() + 1 == pvk.ic.size(), "malformed verification key!");
                        ++vpitr;
                    }

                    // 1.Check TIPA proof ab
                    // 2.Check TIPA proof c
                    auto tipa_ab =
                        verify_tipp_mipp<CurveType>(ip_verifier_srs,
                                                    proof,
                                                    r    // we give the extra r as it's not part of the proof itself
                                                         // - it is simply used on top for the groth16 aggregation
                        );
                }

                /// verify_kzg_opening_g2 takes a KZG opening, the final commitment key, SRS and
                /// any shift (in TIPP we shift the v commitment by r^-1) and returns a pairing
                /// tuple to check if the opening is correct or not.
                template<typename CurveType, typename InputScalarIterator>
                PairingCheck<CurveType> verify_kzg_opening_g2(
                    const r1cs_gg_ppzksnark_verifying_srs<CurveType> &v_srs,
                    const r1cs_gg_ppzksnark_ipp2_vkey<CurveType> &final_vkey,
                    const kzg_opening<typename CurveType::g2_type> &vkey_opening,
                    InputScalarIterator challenges_first,
                    InputScalarIterator challenges_last,
                    const typename std::iterator_traits<InputScalarIterator>::value_type &r_shift,
                    const typename std::iterator_traits<InputScalarIterator>::value_type &kzg_challenge) {
                }

                /// Similar to verify_kzg_opening_g2 but for g1.
                template<typename CurveType, typename InputScalarIterator>
                PairingCheck<CurveType> verify_kzg_opening_g1(
                    const r1cs_gg_ppzksnark_verifier_srs<CurveType> &v_srs,
                    const r1cs_gg_ppzksnark_ipp2_wkey<CurveType> &final_wkey,
                    const kzg_opening<typename CurveType::g1_type> &wkey_opening, InputScalarIterator challenges_first,
                    InputScalarIterator challenges_last, ,
                    const typename std::iterator_traits<InputScalarIterator>::value_type &r_shift,
                    const typename std::iterator_traits<InputScalarIterator>::value_type &kzg_challenge) {
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
