//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_PROVE_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_PROVE_HPP

#include <algorithm>
#include <memory>
#include <vector>
#include <tuple>
#include <string>

#include <boost/iterator/zip_iterator.hpp>

#include <nil/crypto3/detail/pack_numeric.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/proof.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/srs.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/poly.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/proof.hpp>

#include <nil/crypto3/fft/polynomial_arithmetic/basic_operations.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/multiexp/multiexp.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /// Returns the vector used for the linear combination fo the inner pairing product
                /// between A and B for the Groth16 aggregation: A^r * B. It is required as it
                /// is not enough to simply prove the ipp of A*B, we need a random linear
                /// combination of those.
                template<typename FieldType>
                std::vector<typename FieldType::value_type>
                    structured_scalar_power(std::size_t num, const typename FieldType::value_type &s) {
                    std::vector<typename FieldType::value_type> powers = {FieldType::value_type::one()};
                    for (int i = 1; i < num; i++) {
                        powers.emplace_back(powers.back() * s);
                    }
                    return powers;
                }

                /// compress is similar to commit::{V,W}KEY::compress: it modifies the `vec`
                /// vector by setting the value at index $i:0 -> split$  $vec[i] = vec[i] +
                /// vec[i+split]^scaler$. The `vec` vector is half of its size after this call.
                template<
                    typename GroupType, typename InputRange,
                    typename ValueType = std::iterator_traits<typename InputRange::iterator>::value_type,
                    std::enable_if<std::is_same<typename GroupType::value_type, ValueType>::value, bool>::type = true>
                void compress(InputRange &vec, std::size_t split,
                              const typename GroupType::curve_type::scalar_field_type::value_type &scaler) {
                    std::for_each(
                        boost::make_zip_iterator(std::make_tuple(vec.begin(), vec.begin() + split)),
                        boost::make_zip_iterator(std::make_tuple(vec.begin() + split, vec.end())),
                        [&](const std::tuple<typename GroupType::value_type &, typename GroupType::value_type &> &t) {
                            std::get<0>(t) = std::get<0>(t) + std::get<1>(t) * scaler;
                        });
                    vec.resize(split);
                }

                /// Aggregate `n` zkSnark proofs, where `n` must be a power of two.
                template<typename CurveType, typename InputPubInputIterator, typename InputProofIterator,
                         typename Hash = hashes::sha2<256>,
                         typename std::enable_if<
                             std::is_same<typename CurveType::scalar_field_type::value_type,
                                          typename std::iterator_traits<InputPubInputIterator>::value_type>::value,
                             bool>::type = true>
                typename std::enable_if<std::is_same<typename std::iterator_traits<InputProofIterator>::value_type,
                                                     r1cs_gg_ppzksnark_proof<CurveType>>::value,
                                        r1cs_gg_ppzksnark_aggregate_proof<CurveType>>::type
                    aggregate_proofs(const r1cs_gg_ppzksnark_proving_srs<CurveType> &srs,
                                     InputPubInputIterator pub_input_first, InputPubInputIterator pub_input_last,
                                     InputProofIterator proofs_first, InputProofIterator proofs_last) {
                    std::size_t nproofs = std::distance(first, last);
                    BOOST_ASSERT(nproofs >= 2);
                    BOOST_ASSERT((nproofs & (nproofs - 1)) == 0);
                    BOOST_ASSERT(srs.has_correct_len(nproofs));

                    // We first commit to A B and C - these commitments are what the verifier
                    // will use later to verify the TIPP and MIPP proofs
                    // TODO: parallel
                    std::vector<typename CurveType::g1_type::value_type> a, c;
                    std::vector<typename CurveType::g2_type::value_type> b;
                    while (proofs_first != proofs_last) {
                        a.emplace_back(*proofs_first.g_A);
                        b.emplace_back(*proofs_first.g_B);
                        c.emplace_back(*proofs_first.g_C);
                        ++proofs_first;
                    }

                    // A and B are committed together in this scheme
                    // we need to take the reference so the macro doesn't consume the value
                    // first
                    typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type com_ab =
                        r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(srs.vkey, srs.wkey, a.begin(), a.end(),
                                                                           b.begin(), b.end());
                    typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type com_c =
                        r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::single(srs.vkey, c.begin(), c.end());

                    // TODO: serialize/deserialize
                    // Derive a random scalar to perform a linear combination of proofs
                    // std::size_t counter_nonce = 1;
                    // std::array<std::uint8_t, sizeof(std::size_t)> counter_nonce_bytes;
                    // detail::pack<stream_endian::big_byte_big_bit>({counter_nonce}, counter_nonce_bytes);
                    // std::string application_tag_str = "snarkpack";
                    // std::vector<std::uint8_t> application_tag(application_tag_str.begin(),
                    // application_tag_str.end()); std::string domain_separator_str = "random-r";
                    // std::vector<std::uint8_t> domain_separator(domain_separator_str.begin(),
                    // domain_separator_str.end());
                    //
                    // accumulator_set<Hash> acc;
                    // hash<Hash>(counter_nonce_bytes, acc);
                    // hash<Hash>(std::get<0>(com_ab), acc);
                    // hash<Hash>(std::get<1>(com_ab), acc);
                    // hash<Hash>(std::get<0>(com_c), acc);
                    // hash<Hash>(std::get<1>(com_c), acc);
                    //
                    // typename Hash::digest_type d = accumulators::extract::hash<Hash>(acc);
                    // typename CurveType::scalar_field_type::value_type r;
                    // detail::pack(d, r.data);
                    // r = r.inversed();
                    typename CurveType::scalar_field_type::value_type r(12345);

                    // 1,r, r^2, r^3, r^4 ...
                    std::vector<typename CurveType::scalar_field_type::value_type> r_vec =
                        structured_scalar_power<typename CurveType::scalar_field_type>(std::distance(first, last), r);
                    // 1,r^-1, r^-2, r^-3
                    std::vector<typename CurveType::scalar_field_type::value_type> r_inv;
                    std::transform(r_vec.begin(), r_vec.end(), std::back_inserter(r_inv),
                                   [](const auto &r_i) { return r_i.inversed(); });

                    // B^{r}
                    std::vector<typename CurveType::g2_type::value_type> b_r;
                    std::for_each(boost::make_zip_iterator(std::make_tuple(b.begin(), r_vec.begin())),
                                  boost::make_zip_iterator(std::make_tuple(b.end(), r_vec.end())),
                                  [&](const std::tuple<const typename CurveType::g2_type::value_type &,
                                                       const typename CurveType::scalar_field_type::value_type &> &t) {
                                      b_r.emplace_back((std::get<0>(t) * std::get<1>(t)));
                                  });
                    // compute A * B^r for the verifier
                    // auto ip_ab = algebra::pair<CurveType>(a, b_r);
                    typename CurveType::gt_type::value_type ip_ab = typename CurveType::gt_type::value_type::one();
                    std::for_each(boost::make_zip_iterator(std::make_tuple(a.begin(), b_r.begin())),
                                  boost::make_zip_iterator(std::make_tuple(a.end(), b_r.end())),
                                  [&](const std::tuple<const typename CurveType::g1_type::value_type &,
                                                       const typename CurveType::g2_type::value_type &> &t) {
                                      ip_ab = ip_ab * algebra::pair<curve_type>(std::get<0>(t), std::get<1>(t));
                                  });
                    // compute C^r for the verifier
                    typename CurveType::g1_type::value_type agg_c =
                        algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(c.begin(), c.end(),
                                                                                         r_vec.begin(), r_vec.end(), 1);

                    // w^{r^{-1}}
                    r1cs_gg_ppzksnark_ipp2_commitment_key<typename CurveType::g1_type> wkey_r_inv =
                        srs.wkey.scale(r_inv.begin(), r_inv.end());

                    // we prove tipp and mipp using the same recursive loop
                    tipp_mipp_proof<CurveType> proof =
                        prove_tipp_mipp(srs, wkey_r_inv, a.begin(), a.end(), b_r.begin(), b_r.end(), c.begin(), c.end(),
                                        r_vec.begin(), r_vec.end());

                    // debug assert
                    auto computed_com_ab = r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(
                        srs.vkey, wkey_r_inv, a.begin(), a.end(), b_r.begin(), b_r.end());
                    BOOST_ASSERT(com_ab == computed_com_ab);

                    return {com_ab, com_c, ip_ab, agg_c, proof};
                }

                /// Proves a TIPP relation between A and B as well as a MIPP relation with C and
                /// r. Commitment keys must be of size of A, B and C. In the context of Groth16
                /// aggregation, we have that B = B^r and wkey is scaled by r^{-1}. The
                /// commitment key v is used to commit to A and C recursively in GIPA such that
                /// only one KZG proof is needed for v. In the original paper version, since the
                /// challenges of GIPA would be different, two KZG proofs would be needed.
                template<typename CurveType, typename InputG1Iterator, typename InputG2Iterator,
                         typename InputScalarIterator, typename Hash = hashes::sha2<256>,
                         typename std::enable_if<
                             std::is_same<typename CurveType::g1_type::value_type,
                                          typename std::iterator_traits<InputG1Iterator>::value_type>::value,
                             bool>::type = true,
                         typename std::enable_if<
                             std::is_same<typename CurveType::g2_type::value_type,
                                          typename std::iterator_traits<InputG2Iterator>::value_type>::value,
                             bool>::type = true,
                         typename std::enable_if<
                             std::is_same<typename CurveType::scalar_field_type::value_type,
                                          typename std::iterator_traits<InputScalarIterator>::value_type>::value,
                             bool>::type = true>
                tipp_mipp_proof<CurveType> prove_tipp_mipp(const r1cs_gg_ppzksnark_proving_srs<CurveType> &srs,
                                                           InputG1Iterator a_first, InputG1Iterator a_last,
                                                           InputG2Iterator b_first, InputG2Iterator b_last,
                                                           InputG1Iterator c_first, InputG1Iterator c_last,
                                                           const r1cs_gg_ppzksnark_ipp2_wkey<CurveType> &wkey,
                                                           InputScalarIterator r_first, InputScalarIterator r_last) {
                    std::size_t a_size = std::distance(a_first, a_last);
                    std::size_t b_size = std::distance(b_first, b_last);
                    std::size_t c_size = std::distance(c_first, c_last);

                    BOOST_ASSERT((a_size & (a_size - 1)) == 0 && a_size == b_size && a_size == c_size);
                    typename CurveType::scalar_field_type::value_type r_shift = *(r_first + 1);

                    // Run GIPA
                    auto [proof, challenges, challenges_inv] = gipa_tipp_mipp<CurveType>(
                        a_first, a_last, b_first, b_last, c_first, c_last, srs.vkey, wkey, r_first, r_last);

                    // Prove final commitment keys are wellformed
                    // we reverse the transcript so the polynomial in kzg opening is constructed
                    // correctly - the formula indicates x_{l-j}. Also for deriving KZG
                    // challenge point, input must be the last challenge.
                    std::reverse(challenges.begin(), challenges.end());
                    std::reverse(challenges_inv.begin(), challenges_inv.end());
                    typename CurveType::scalar_field_type::value_type r_inverse = r_shift.inverse();

                    // TODO: serialize/deserialize
                    // KZG challenge point
                    // std::size_t counter_nonce = 1;
                    // std::array<std::uint8_t, sizeof(std::size_t)> counter_nonce_bytes;
                    // detail::pack<stream_endian::big_byte_big_bit>({counter_nonce}, counter_nonce_bytes);
                    // accumulator_set<Hash> acc;
                    //
                    // hash<Hash>(counter_nonce_bytes, acc);
                    // hash<Hash>(*std::get<1>(gtm).begin(), acc);
                    // hash<Hash>(std::get<0>(std::get<0>(gtm).final_vkey), acc);
                    // hash<Hash>(std::get<1>(std::get<0>(gtm).final_vkey), acc);
                    // hash<Hash>(std::get<0>(std::get<0>(gtm).final_wkey), acc);
                    // hash<Hash>(std::get<1>(std::get<0>(gtm).final_wkey), acc);
                    //
                    // typename Hash::digest_type d = accumulators::extract::hash<Hash>(acc);
                    // typename CurveType::scalar_field_type::value_type z;
                    // multiprecision::import_bits(z.data, d);
                    // z = z.inversed();
                    typename CurveType::scalar_field_type::value_type z(12345);

                    // Complete KZG proofs
                    kzg_opening<typename CurveType::g2_type> vkey_opening =
                        prove_commitment_v(srs.h_alpha_powers_table, srs.h_beta_powers_table, srs.n,
                                           challenges_inv.begin(), challenges_inv.end(), z);
                    kzg_opening<typename CurveType::g1_type> wkey_opening =
                        prove_commitment_w(srs.g_alpha_powers_table, srs.g_beta_powers_table, srs.n, challenges.begin(),
                                           challenges.end(), z);

                    return tipp_mipp_proof<CurveType> {proof, vkey_opening, wkey_opening};
                }

                /// gipa_tipp_mipp peforms the recursion of the GIPA protocol for TIPP and MIPP.
                /// It returns a proof containing all intermdiate committed values, as well as
                /// the challenges generated necessary to do the polynomial commitment proof
                /// later in TIPP.
                template<typename CurveType, typename InputG1Iterator, typename InputG2Iterator,
                         typename InputScalarIterator, typename Hash = hashes::sha2<256>,
                         typename std::enable_if<
                             std::is_same<typename CurveType::g1_type::value_type,
                                          typename std::iterator_traits<InputG1Iterator>::value_type>::value,
                             bool>::type = true,
                         typename std::enable_if<
                             std::is_same<typename CurveType::g2_type::value_type,
                                          typename std::iterator_traits<InputG2Iterator>::value_type>::value,
                             bool>::type = true,
                         typename std::enable_if<
                             std::is_same<typename CurveType::scalar_field_type::value_type,
                                          typename std::iterator_traits<InputScalarIterator>::value_type>::value,
                             bool>::type = true>
                std::tuple<gipa_proof<CurveType>, std::vector<typename CurveType::scalar_field_type::value_type>,
                           std::vector<typename CurveType::scalar_field_type::value_type>>
                    gipa_tipp_mipp(InputG1Iterator a_first, InputG1Iterator a_last, InputG2Iterator b_first,
                                   InputG2Iterator b_last, InputG1Iterator c_first, InputG1Iterator c_last,
                                   const r1cs_gg_ppzksnark_ipp2_vkey<CurveType> &vkey_input,
                                   const r1cs_gg_ppzksnark_ipp2_wkey<CurveType> &wkey_input,
                                   InputScalarIterator r_first, InputScalarIterator r_last) {
                    // the values of vectors A and B rescaled at each step of the loop
                    // the values of vectors C and r rescaled at each step of the loop
                    std::vector<typename CurveType::g1_type::value_type> m_a = {a_first, a_last},
                                                                         m_c = {c_first, c_last};
                    std::vector<typename CurveType::g2_type::value_type> m_b = {b_first, b_last};
                    std::vector<typename CurveType::scalar_field_type::value_type> m_r = {r_first, r_last};

                    r1cs_gg_ppzksnark_ipp2_vkey<CurveType> vkey = vkey_input;
                    r1cs_gg_ppzksnark_ipp2_wkey<CurveType> wkey = wkey_input;

                    // storing the values for including in the proof
                    std::vector<std::pair<typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type,
                                          typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type>>
                        comms_ab;
                    std::vector<std::pair<typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type,
                                          typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type>>
                        comms_c;
                    std::vector<
                        std::pair<typename curve_type::gt_type::value_type, typename curve_type::gt_type::value_type>>
                        z_ab;
                    std::vector<
                        std::pair<typename curve_type::g1_type::value_type, typename curve_type::g1_type::value_type>>
                        z_c;
                    std::vector<typename CurveType::scalar_field_type::value_type> challenges, challenges_inv;

                    while (m_a.size() > 1) {
                        // recursive step
                        // Recurse with problem of half size
                        std::size_t split = m_a.size() / 2;

                        // TIPP ///
                        std::vector<typename CurveType::g1_type::value_type> a_left = {m_a.begin(),
                                                                                       m_a.begin() + split},
                                                                             a_right = {m_a.begin() + split, m_a.end()};
                        std::vector<typename CurveType::g2_type::value_type> b_left = {m_b.begin(),
                                                                                       m_b.begin() + split},
                                                                             b_right = {m_b.begin() + split, m_b.end()};
                        // MIPP ///
                        // c[:n']   c[n':]
                        std::vector<typename CurveType::g1_type::value_type> c_left = {m_c.begin() + m_c.begin() +
                                                                                       split},
                                                                             c_right = {m_c.begin() + split, m_c.end()};
                        // r[:n']   r[:n']
                        std::vector<typename CurveType::scalar_field_type::value_type> r_left = {m_r.begin(),
                                                                                                 m_r.begin() + split},
                                                                                       r_right = {m_r.begin() + split,
                                                                                                  m_r.end()};

                        auto [vk_left, vk_right] = vkey.split(split);
                        auto [wk_left, wk_right] = wkey.split(split);

                        // TODO: parallel
                        // See section 3.3 for paper version with equivalent names
                        // TIPP part
                        typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type tab_l =
                            r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(
                                vk_left, wk_right, a_right.begin(), a_right.end(), b_left.begin(), b_left.end());
                        typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type tab_r =
                            r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(
                                vk_right, wk_left, a_left.begin(), a_left.end(), b_right.begin(), b_right.end());

                        // \prod e(A_right,B_left)
                        typename CurveType::gt_type::value_type zab_l = typename CurveType::gt_type::value_type::one();
                        std::for_each(boost::make_zip_iterator(std::make_tuple(a_right.begin(), b_left.begin())),
                                      boost::make_zip_iterator(std::make_tuple(a_right.end(), b_left.end())),
                                      [&](const std::tuple<const typename CurveType::g1_type::value_type &,
                                                           const typename CurveType::g2_type::value_type &> &t) {
                                          zab_l = zab_l * algebra::pair<CurveType>(std::get<0>(t), std::get<1>(t));
                                      });
                        typename CurveType::gt_type::value_type zab_r = typename CurveType::gt_type::value_type::one();
                        std::for_each(boost::make_zip_iterator(std::make_tuple(a_left.begin(), b_right.begin())),
                                      boost::make_zip_iterator(std::make_tuple(a_left.end(), b_right.end())),
                                      [&](const std::tuple<const typename CurveType::g1_type::value_type &,
                                                           const typename CurveType::g2_type::value_type &> &t) {
                                          zab_r = zab_r * algebra::pair<CurveType>(std::get<0>(t), std::get<1>(t));
                                      });

                        // MIPP part
                        // z_l = c[n':] ^ r[:n']
                        typename CurveType::g1_type::value_type zc_l =
                            algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(
                                c_right.begin(), c_right.end(), r_left.begin(), r_left.end());
                        // Z_r = c[:n'] ^ r[n':]
                        typename CurveType::g1_type::value_type zc_r =
                            algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(
                                c_left.begin(), c_left.end(), r_right.begin(), r_right.end());
                        // u_l = c[n':] * v[:n']
                        typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type tuc_l =
                            r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::single(vk_left, c_right.begin(),
                                                                                 c_right.end());
                        // u_r = c[:n'] * v[n':]
                        typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type tuc_r =
                            r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::single(vk_right, c_left.begin(),
                                                                                 c_left.end());

                        // TODO: serialize/deserialize
                        // Fiat-Shamir challenge
                        // typename CurveType::scalar_field_type::value_type default_transcript =
                        //     CurveType::scalar_field_type::value_type::zero();
                        // auto transcript = challenges.empty() ? default_transcript : *(challenges.end() - 1);
                        //
                        // // combine both TIPP and MIPP transcript
                        // std::size_t counter_nonce = 1;
                        // std::array<std::uint8_t, sizeof(std::size_t)> counter_nonce_bytes;
                        // detail::pack<stream_endian::big_byte_big_bit>({counter_nonce}, counter_nonce_bytes);
                        // accumulator_set<Hash> acc;
                        //
                        // hash<Hash>(counter_nonce_bytes, acc);
                        // hash<Hash>(transcript, acc);
                        // hash<Hash>(std::get<0>(tab_l), acc);
                        // hash<Hash>(std::get<1>(tab_l), acc);
                        // hash<Hash>(std::get<0>(tab_r), acc);
                        // hash<Hash>(std::get<1>(tab_r), acc);
                        // hash<Hash>(zab_l, acc);
                        // hash<Hash>(zab_r, acc);
                        // hash<Hash>(zc_l, acc);
                        // hash<Hash>(zc_r, acc);
                        // hash<Hash>(std::get<0>(tuc_l), acc);
                        // hash<Hash>(std::get<1>(tuc_l), acc);
                        // hash<Hash>(std::get<0>(tuc_r), acc);
                        // hash<Hash>(std::get<1>(tuc_r), acc);
                        //
                        // typename hashes::sha2<256>::digest_type d =
                        // accumulators::extract::hash<hashes::sha2<256>>(acc); typename
                        // CurveType::scalar_field_type::value_type c_inv; detail::pack(d, c_inv.data); c_inv =
                        // c_inv.inversed();
                        typename CurveType::scalar_field_type::value_type c_inv(12345);

                        // Optimization for multiexponentiation to rescale G2 elements with
                        // 128-bit challenge Swap 'c' and 'c_inv' since can't control bit size
                        // of c_inv
                        typename CurveType::scalar_field_type::value_type c = c_inv.inversed();

                        // Set up values for next step of recursion
                        // A[:n'] + A[n':] ^ x
                        compress(m_a, split, c);
                        // B[:n'] + B[n':] ^ x^-1
                        compress(m_b, split, c_inv);

                        // c[:n'] + c[n':]^x
                        compress(m_c, split, c);
                        std::for_each(boost::make_zip_iterator(std::make_tuple(r_left.begin(), r_right.begin())),
                                      boost::make_zip_iterator(std::make_tuple(r_left.end(), r_right.end())),
                                      [&](const std::tuple<typename CurveType::scalar_field_type::value_type &,
                                                           typename CurveType::scalar_field_type::value_type &> &t) {
                                          // r[:n'] + r[n':]^x^-1
                                          std::get<0>(t) = std::get<0>(t) + std::get<1>(t) * c_inv;
                                      });
                        std::size_t len = r_left.size();
                        m_r.resize(len);    // shrink to new size

                        // v_left + v_right^x^-1
                        vkey = vk_left.compress(vk_right, c_inv);
                        // w_left + w_right^x
                        wkey = wk_left.compress(wk_right, c);

                        comms_ab.emplace_back(std::make_pair(tab_l, tab_r));
                        comms_c.emplace_back(std::make_pair(tuc_l, tuc_r));
                        z_ab.emplace_back(std::make_pair(zab_l, zab_r));
                        z_c.emplace_back(std::make_pair(zc_l, zc_r));
                        challenges.emplace_back(c);
                        challenges_inv.emplace_back(c_inv);
                    }

                    BOOST_ASSERT(m_a.size() == 1 && m_b.size() == 1);
                    BOOST_ASSERT(m_c.size() == 1 && m_r.size() == 1);
                    BOOST_ASSERT(vkey.a.size() == 1 && vkey.b.size() == 1);
                    BOOST_ASSERT(wkey.a.size() == 1 && wkey.b.size() == 1);

                    return std::make_tuple(gipa_proof<CurveType> {std::distance(a_first, a_last), comms_ab, comms_c,
                                                                  z_ab, z_c, m_a[0], m_b[0], m_c[0], m_r[0],
                                                                  vkey.first(), wkey.first()},
                                           challenges, challenges_inv);
                }

                template<typename CurveType, typename InputScalarIterator,
                         typename std::enable_if<
                             std::is_same<typename CurveType::scalar_field_type::value_type,
                                          typename std::iterator_traits<InputScalarIterator>::value_type>::value,
                             bool>::type = true>
                kzg_opening<typename CurveType::g2_type> prove_commitment_v(
                    const multiscalar_precomp_owned<typename CurveType::g2_type> &srs_powers_alpha_table,
                    const multiscalar_precomp_owned<typename CurveType::g2_type> &srs_powers_beta_table, std::size_t n,
                    InputScalarIterator transcript_first, InputScalarIterator transcript_last,
                    const typename CurveType::scalar_field_type::value_type &kzg_challenge) {
                    std::vector<typename CurveType::scalar_field_type::value_type> vkey_poly =
                        fft::_condense(polynomial_coefficients_from_transcript(
                            transcript_first, transcript_last, CurveType::scalar_field_type::value_type::one()));
                    BOOST_ASSERT(!fft::_is_zero(vkey_poly));

                    typename CurveType::scalar_field_type::value_type vkey_poly_z =
                        polynomial_evaluation_product_form_from_transcript(
                            transcript_first, transcript_last, kzg_challenge,
                            CurveType::scalar_field_type::value_type::one());

                    return prove_commitment_key_kzg_opening(srs_powers_alpha_table, srs_powers_beta_table, n, vkey_poly,
                                                            vkey_poly_z, kzg_challenge);
                }

                /// Returns the KZG opening proof for the given commitment key. Specifically, it
                /// returns $g^{f(alpha) - f(z) / (alpha - z)}$ for $a$ and $b$.
                template<typename GroupType, typename InputScalarIterator,
                         typename std::enable_if<
                             std::is_same<typename GroupType::curve_type::scalar_field_type::value_type,
                                          typename std::iterator_traits<InputFieldValueIterator>::value_type>::value,
                             bool>::type = true>
                kzg_opening<GroupType> prove_commitment_key_kzg_opening(
                    const multiscalar_precomp_owned<GroupType> &srs_powers_alpha_table,
                    const multiscalar_precomp_owned<GroupType> &srs_powers_beta_table, std::size_t srs_powers_len,
                    InputScalarIterator transcript_first, InputScalarIterator transcript_last,
                    const typename GroupType::curve_type::scalar_field_type::value_type &eval_poly,
                    const typename GroupType::curve_type::scalar_field_type::value_type &kzg_challenge) {
                    // f_v
                    DensePolynomial vkey_poly(
                        polynomial_coefficients_from_transcript(transcript_first, transcript_last, r_shift));

                    BOOST_ASSERT_MSG(srs_powers_len != vkey_poly.coeffs().size(), "Malformed SRS");
                    // f_v(z)
                    std::vector<typename std::iterator_traits<InputScalarIterator>::value_type> vkey_poly_z =
                        polynomial_evaluation_product_form_from_transcript(transcript_first, transcript_last,
                                                                           kzg_challenge, r_shift);

                    typename std::iterator_traits<InputScalarIterator>::value_type neg_kzg_challenge =
                        kzg_challenge.negate();

                    // f_v(X) - f_v(z) / (X - z)
                    DensePolynomial quotient_polynomial =
                        (vkey_poly - DensePolynomial(vkey_poly_z)) /
                        (DensePolynomial(
                            {neg_kzg_challenge, std::iterator_traits<InputScalarIterator>::value_type::one()}));

                    std::vector<typename std::iterator_traits<InputScalarIterator>::value_type>
                        quotient_polynomial_coeffs = quotient_polynomial.into_coeffs();

                    // multiexponentiation inner_product, inlined to optimize
                    std::size_t quotient_polynomial_coeffs_len = quotient_polynomial_coeffs.size();
                    auto getter = [&](std::size_t i) -> typename CurveAffine::scalar_field_type::value_type {
                        return i >= quotient_polynomial_coeffs_len ?
                                   std::iterator_traits<InputScalarIterator>::value_type::zero() :
                                   quotient_polynomial_coeffs[i];
                    };
                }

                /// It returns the evaluation of the polynomial $\prod (1 + x_{l-j}(rX)^{2j}$ at
                /// the point z, where transcript contains the reversed order of all challenges (the x).
                /// The challenges must be in reversed order for the correct evaluation of the
                /// polynomial in O(logn)
                template<typename FieldType, typename InputFieldValueIterator>
                typename std::enable_if<std::is_same<typename std::iterator_traits<InputFieldIterator>::value_type,
                                                     typename FieldType::value_type>::value,
                                        typename FieldType::value_type>::type
                    polynomial_evaluation_product_form_from_transcript(InputFieldValueIterator transcript_first,
                                                                       InputFieldValueIterator transcript_last,
                                                                       const typename FieldType::value_type &z,
                                                                       const typename FieldType::value_type &r_shift) {
                    // this is the term (rz) that will get squared at each step to produce the
                    // $(rz)^{2j}$ of the formula
                    typename FieldType::value_type power_zr = z;
                    power_zr = power_zr * r_shift;

                    // 0 iteration
                    InputFieldValueIterator transcript_iter = transcript_first;
                    typename FieldType::value_type res = FieldType::value_type::one() + (*transcript_iter * power_zr);
                    power_zr = power_zr * power_zr;
                    ++transcript_iter;

                    // the rest
                    while (transcript_iter != transcript_last) {
                        res = res * (FieldType::value_type::one() + (*transcript_iter * power_zr));
                        power_zr = power_zr * power_zr;
                        ++transcript_iter;
                    }

                    return res;
                }

                // Compute the coefficients of the polynomial $\prod_{j=0}^{l-1} (1 + x_{l-j}(rX)^{2j})$
                // It does this in logarithmic time directly; here is an example with 2
                // challenges:
                //
                //     We wish to compute $(1+x_1ra)(1+x_0(ra)^2) = 1 +  x_1ra + x_0(ra)^2 + x_0x_1(ra)^3$
                //     Algorithm: $c_{-1} = [1]$; $c_j = c_{i-1} \| (x_{l-j} * c_{i-1})$; $r = r*r$
                //     $c_0 = c_{-1} \| (x_1 * r * c_{-1}) = [1] \| [rx_1] = [1, rx_1]$, $r = r^2$
                //     $c_1 = c_0 \| (x_0 * r^2c_0) = [1, rx_1] \| [x_0r^2, x_0x_1r^3] = [1, x_1r, x_0r^2, x_0x_1r^3]$
                //     which is equivalent to $f(a) = 1 + x_1ra + x_0(ra)^2 + x_0x_1r^2a^3$
                //
                // This method expects the coefficients in reverse order so transcript[i] =
                // x_{l-j}.
                template<typename FieldType, typename InputFieldValueIterator>
                typename std::enable_if<std::is_same<typename std::iterator_traits<InputFieldValueIterator>::value_type,
                                                     typename FieldType::value_type>::value,
                                        std::vector<typename FieldType::value_type>>::type
                    polynomial_coefficients_from_transcript(InputFieldValueIterator transcript_first,
                                                            InputFieldValueIterator transcript_last,
                                                            const typename FieldType::value_type &r_shift) {
                    std::vector<typename FieldType::value_type> coefficients = {FieldType::value_type::one()};
                    typename FieldType::value_type power_2_r = r_shift;

                    InputFieldValueIterator transcript_iter = transcript_first;
                    while (transcript_iter != transcript_last) {
                        std::size_t n = coefficients.size();
                        for (int j = 0; j < n; j++) {
                            coefficients.emplace_back(coefficients[j] * (*transcript_iter * power_2_r));
                        }
                        power_2_r = power_2_r * power_2_r;

                        ++transcript_iter;
                    }

                    return coefficients;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
