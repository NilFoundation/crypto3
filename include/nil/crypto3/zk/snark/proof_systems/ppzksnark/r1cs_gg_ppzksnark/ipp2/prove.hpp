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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_PROVE_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_PROVE_HPP

#include <algorithm>
#include <memory>
#include <vector>
#include <tuple>

#include <boost/iterator/zip_iterator.hpp>

#include <nil/crypto3/detail/pack_numeric.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/proof.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/srs.hpp>

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
                        powers.emplace_back(powers[i - 1] * s);
                    }
                    return powers;
                }

                /// compress is similar to commit::{V,W}KEY::compress: it modifies the `vec`
                /// vector by setting the value at index $i:0 -> split$  $vec[i] = vec[i] +
                /// vec[i+split]^scaler$. The `vec` vector is half of its size after this call.
                template<typename CurveAffine>
                void compress(std::vector<typename CurveAffine::value_type> &vec, std::size_t split,
                              const typename CurveAffine::scalar &scaler) {
                    std::vector<typename CurveAffine::value_type> left = {vec.begin(), vec.begin() + split},
                                                                  right = {vec.begin() + split, vec.end()};
                    std::for_each(boost::make_zip_iterator(std::make_tuple(left.begin(), right.begin())),
                                  boost::make_zip_iterator(std::make_tuple(left.end(), right.end())),
                                  [&](const std::tuple<const typename CurveAffine::value_type &,
                                                       const typename CurveAffine::value_type &> &t) {
                                      auto x = std::get<1>(t).to_projective() * scaler;
                                      x += std::get<0>(t);
                                      std::get<0>(t) = x.to_affine();
                                  });

                    vec.resize(left.size());
                }

                /// Aggregate `n` zkSnark proofs, where `n` must be a power of two.
                template<typename CurveType, typename InputProofIterator, typename Hash = hashes::sha2<256>>
                typename std::enable_if<std::is_same<typename std::iterator_traits<InputProofIterator>::value_type,
                                                     r1cs_gg_ppzksnark_aggregate_proof<CurveType>>::value,
                                        r1cs_gg_ppzksnark_aggregate_proof<CurveType>>::type
                    aggregate_proofs(const r1cs_gg_ppzksnark_proving_srs<CurveType> &srs, InputProofIterator first,
                                     InputProofIterator last) {
                    std::size_t size = std::distance(first, last);
                    BOOST_ASSERT((size & (size - 1)) == 0);
                    BOOST_ASSERT(srs.valid(size));

                    std::vector<typename CurveType::g1_type::value_type> a, c;
                    std::vector<typename CurveType::g2_type::value_type> b;

                    // We first commit to A B and C - these commitments are what the verifier
                    // will use later to verify the TIPP and MIPP proofs
                    while (first != last) {
                        a.emplace_back(*first.g_A);
                        b.emplace_back(*first.g_B);
                        c.emplace_back(*first.g_C);
                        ++first;
                    }

                    // A and B are committed together in this scheme
                    // we need to take the reference so the macro doesn't consume the value
                    // first
                    r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType> com_ab =
                        r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(srs.vkey, srs.wkey, a.begin(), a.end(),
                                                                           b.begin(), b.end());
                    r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType> com_c =
                        r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(srs.vkey, c.begin(), c.end());

                    // Random linear combination of proofs
                    std::size_t counter_nonce = 1;
                    std::array<std::uint8_t, sizeof(std::size_t)> counter_nonce_bytes;
                    detail::pack<stream_endian::big_byte_big_bit>({counter_nonce}, counter_nonce_bytes);
                    accumulator_set<Hash> acc;

                    hash<Hash>(counter_nonce_bytes, acc);
                    hash<Hash>(std::get<0>(com_ab), acc);
                    hash<Hash>(std::get<1>(com_ab), acc);
                    hash<Hash>(std::get<0>(com_c), acc);
                    hash<Hash>(std::get<1>(com_c), acc);

                    typename Hash::digest_type d = accumulators::extract::hash<Hash>(acc);
                    typename CurveType::scalar_field_type::value_type r;
                    detail::pack(d, r.data);
                    r = r.inversed();

                    // r, r^2, r^3, r^4 ...
                    std::vector<typename CurveType::scalar_field_type::value_type> r_vec =
                        structured_scalar_power<typename CurveType::scalar_field_type>(std::distance(first, last), r);
                    // r^-1, r^-2, r^-3
                    std::vector<typename CurveType::scalar_field_type::value_type> r_inv;
                    for (const typename CurveType::scalar_field_type::value_type &ri : r_vec) {
                        r_inv.emplace_back(ri.inversed());
                    }

                    // B^{r}
                    std::vector<typename CurveType::scalar_field_type::value_type> b_r;
                    std::for_each(boost::make_zip_iterator(std::make_tuple(b.begin(), r_vec.begin())),
                                  boost::make_zip_iterator(std::make_tuple(b.end(), r_vec.end())),
                                  [&](const std::tuple<const typename CurveType::g2_type::value_type &,
                                                       const typename CurveType::scalar_field_type::value_type &> &t) {
                                      b_r.emplace_back((std::get<0>(t).to_projective() * std::get<1>(t)).to_affine());
                                  });

                    // w^{r^{-1}}
                    auto wkey_r_inv = srs.wkey.scale(r_inv);

                    // we prove tipp and mipp using the same recursive loop
                    tipp_mipp_proof<CurveType> proof =
                        prove_tipp_mipp(srs, wkey_r_inv, a.begin(), a.end(), b_r.begin(), b_r.end(), c.begin(), c.end(),
                                        r_vec.begin(), r_vec.end());
                    // compute A * B^r for the verifier
                    auto ip_ab = algebra::pair<CurveType>(a, b_r);
                    // compute C^r for the verifier
                    auto agg_c = algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(c, r_vec);

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
                         typename InputScalarIterator, typename Hash = hashes::sha2<256>>
                tipp_mipp_proof<CurveType> prove_tipp_mipp(const r1cs_gg_ppzksnark_proving_srs<CurveType> &srs,
                                                           const r1cs_gg_ppzksnark_ipp2_wkey<CurveType> &wkey,
                                                           InputG1Iterator afirst, InputG1Iterator alast,
                                                           InputG2Iterator bfirst, InputG2Iterator blast,
                                                           InputG1Iterator cfirst, InputG1Iterator clast,
                                                           InputScalarIterator rfirst, InputScalarIterator rlast) {
                    std::size_t asize = std::distance(afirst, alast);
                    std::size_t bsize = std::distance(bfirst, blast);

                    BOOST_ASSERT((asize & (asize - 1)) == 0 || asize == bsize);
                    typename std::iterator_traits<InputScalarIterator>::value_type r_shift = *rfirst + 1;

                    // Run GIPA
                    std::tuple<gipa_proof<CurveType>, std::vector<typename CurveType::scalar_field_type::value_type>,
                               std::vector<typename CurveType::scalar_field_type::value_type>>
                        gtm =
                            gipa_tipp_mipp(afirst, alast, bfirst, blast, cfirst, clast, rfirst, rlast, srs.vkey, wkey);

                    // Prove final commitment keys are wellformed
                    // we reverse the transcript so the polynomial in kzg opening is constructed
                    // correctly - the formula indicates x_{l-j}. Also for deriving KZG
                    // challenge point, input must be the last challenge.
                    std::reverse(std::get<1>(gtm).begin(), std::get<1>(gtm).end());
                    std::reverse(std::get<2>(gtm).begin(), std::get<2>(gtm).end());
                    typename std::iterator_traits<InputScalarIterator>::value_type r_inverse = r_shift.inverse();

                    // KZG challenge point
                    std::size_t counter_nonce = 1;
                    std::array<std::uint8_t, sizeof(std::size_t)> counter_nonce_bytes;
                    detail::pack<stream_endian::big_byte_big_bit>({counter_nonce}, counter_nonce_bytes);
                    accumulator_set<Hash> acc;

                    hash<Hash>(counter_nonce_bytes, acc);
                    hash<Hash>(*std::get<1>(gtm).begin(), acc);
                    hash<Hash>(std::get<0>(std::get<0>(gtm).final_vkey), acc);
                    hash<Hash>(std::get<1>(std::get<0>(gtm).final_vkey), acc);
                    hash<Hash>(std::get<0>(std::get<0>(gtm).final_wkey), acc);
                    hash<Hash>(std::get<1>(std::get<0>(gtm).final_wkey), acc);

                    typename Hash::digest_type d = accumulators::extract::hash<Hash>(acc);
                    typename CurveType::scalar_field_type::value_type z;
                    multiprecision::import_bits(z.data, d);
                    z = z.inversed();

                    // Complete KZG proofs
                    kzg_opening<typename CurveType::g2_type> vkey_opening = prove_commitment_key_kzg_opening(
                        srs.h_alpha_powers_table, srs.h_beta_powers_table, srs.n, std::get<2>(gtm),
                        CurveType::scalar_field_type::value_type::one(), z);
                    kzg_opening<typename CurveType::g1_type> wkey_opening = prove_commitment_key_kzg_opening(
                        srs.g_alpha_powers_table, srs.g_beta_powers_table, srs.n, std::get<1>(gtm), r_inverse, z);

                    return {std::get<0>(gtm), vkey_opening, wkey_opening};
                }

                /*
                 * @brief gipa_tipp_mipp peforms the recursion of the GIPA protocol for TIPP and MIPP.
                 * It returns a proof containing all intermdiate committed values, as well as
                 * the challenges generated necessary to do the polynomial commitment proof
                 * later in TIPP.
                 * @param wkey scaled key w^r^-1
                 */
                template<typename CurveType, typename InputG1Iterator, typename InputG2Iterator,
                         typename InputScalarIterator, typename Hash = hashes::sha2<256>>
                std::tuple<gipa_proof<CurveType>, std::vector<typename CurveType::scalar_field_type::value_type>,
                           std::vector<typename CurveType::scalar_field_type::value_type>>
                    gipa_tipp_mipp(InputG1Iterator afirst, InputG1Iterator alast, InputG2Iterator bfirst,
                                   InputG2Iterator blast, InputG1Iterator cfirst, InputG1Iterator clast,
                                   InputScalarIterator rfirst, InputScalarIterator rlast,
                                   const r1cs_gg_ppzksnark_ipp2_vkey<CurveType> &vkey,
                                   const r1cs_gg_ppzksnark_ipp2_wkey<CurveType> &wkey) {

                    std::vector<typename std::iterator_traits<InputG1Iterator>::value_type> m_a = {afirst, alast},
                                                                                            m_c = {cfirst, clast};
                    std::vector<typename std::iterator_traits<InputG2Iterator>::value_type> m_b = {bfirst, blast};
                    std::vector<typename std::iterator_traits<InputScalarIterator>::value_type> m_r = {rfirst, rlast};

                    r1cs_gg_ppzksnark_ipp2_vkey<CurveType> vkey = vkey;
                    r1cs_gg_ppzksnark_ipp2_wkey<CurveType> wkey = wkey;

                    // storing the values for including in the proof
                    std::vector<std::tuple<typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type,
                                           typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type>>
                        comms_ab;
                    std::vector<std::tuple<typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type,
                                           typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type>>
                        comms_c;
                    std::vector<typename CurveType::pairing::gt_type::value_type> z_ab;
                    std::vector<typename std::iterator_traits<InputG1Iterator>::value_type> z_c;
                    std::vector<typename CurveType::scalar_field_type::value_type> challenges, challenges_inv;

                    while (m_a.size() > 1) {
                        // recursive step
                        // Recurse with problem of half size
                        std::size_t split = m_a.size() / 2;

                        // TIPP ///
                        std::vector<typename std::iterator_traits<InputG1Iterator>::value_type>
                            a_left = {m_a.begin(), m_a.begin() + split},
                            a_right = {m_a.begin() + split, m_a.end()};
                        std::vector<typename std::iterator_traits<InputG2Iterator>::value_type>
                            b_left = {m_b.begin(), m_b.begin() + split},
                            b_right = {m_b.begin() + split, m_b.end()};
                        // MIPP ///
                        // c[:n']   c[n':]
                        std::vector<typename std::iterator_traits<InputG1Iterator>::value_type>
                            c_left = {m_c.begin() + m_c.begin() + split},
                            c_right = {m_c.begin() + split, m_c.end()};
                        // r[:n']   r[:n']
                        std::vector<typename std::iterator_traits<InputScalarIterator>::value_type>
                            r_left = {m_r.begin(), m_r.begin() + split},
                            r_right = {m_r.begin() + split, m_r.end()};

                        r1cs_gg_ppzksnark_ipp2_vkey<CurveType> vk_left = {{vkey.a.begin(), vkey.a.begin() + split},
                                                                          {vkey.b.begin(), vkey.b.begin() + split}},
                                                               vk_right = {{vkey.a.begin() + split, vkey.a.end()},
                                                                           {vkey.b.begin() + split, vkey.b.end()}};

                        r1cs_gg_ppzksnark_ipp2_wkey<CurveType> wk_left = {{wkey.a.begin(), wkey.a.begin() + split},
                                                                          {wkey.b.begin(), wkey.b.begin() + split}},
                                                               wk_right = {{wkey.a.begin() + split, wkey.a.end()},
                                                                           {wkey.b.begin() + split, wkey.b.end()}};

                        // See section 3.3 for paper version with equivalent names
                        typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type tab_l =
                            r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(vk_left, wk_right, a_right, b_left);
                        typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type tab_r =
                            r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(vk_right, wk_left, a_left, b_right);

                        // TIPP part
                        typename CurveType::pairing::gt_type::value_type zab_l =
                            algebra::pair<CurveType>(a_right, b_left);
                        typename CurveType::pairing::gt_type::value_type zab_r =
                            algebra::pair<CurveType>(a_left, b_right);

                        // MIPP part
                        // z_l = c[n':] ^ r[:n']
                        typename std::iterator_traits<InputG1Iterator>::value_type zc_l =
                            algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(c_right, r_left);
                        // Z_r = c[:n'] ^ r[n':]
                        typename std::iterator_traits<InputG1Iterator>::value_type zc_r =
                            algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(c_left, r_right);
                        // u_l = c[n':] * v[:n']
                        typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type tuc_l =
                            r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(vk_left, c_right);
                        // u_r = c[:n'] * v[n':]
                        typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type tuc_r =
                            r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(vk_right, c_left);

                        // Fiat-Shamir challenge
                        typename CurveType::scalar_field_type::value_type default_transcript =
                            CurveType::scalar_field_type::value_type::zero();
                        auto transcript = challenges.empty() ? default_transcript : *(challenges.end() - 1);

                        // combine both TIPP and MIPP transcript
                        std::size_t counter_nonce = 1;
                        std::array<std::uint8_t, sizeof(std::size_t)> counter_nonce_bytes;
                        detail::pack<stream_endian::big_byte_big_bit>({counter_nonce}, counter_nonce_bytes);
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
                        hash<Hash>(std::get<0>(tuc_l), acc);
                        hash<Hash>(std::get<1>(tuc_l), acc);
                        hash<Hash>(std::get<0>(tuc_r), acc);
                        hash<Hash>(std::get<1>(tuc_r), acc);

                        typename hashes::sha2<256>::digest_type d = accumulators::extract::hash<hashes::sha2<256>>(acc);
                        typename CurveType::scalar_field_type::value_type c_inv;
                        detail::pack(d, c_inv.data);
                        c_inv = c_inv.inversed();

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
                        std::for_each(
                            boost::make_zip_iterator(std::make_tuple(r_left.begin(), r_right.begin())),
                            boost::make_zip_iterator(std::make_tuple(r_left.end(), r_right.end())),
                            [&](const std::tuple<typename std::iterator_traits<InputScalarIterator>::value_type &,
                                                 typename std::iterator_traits<InputScalarIterator>::value_type &> &t) {
                                // r[:n'] + r[n':]^x^-1
                                std::get<1>(t) *= c_inv;
                                std::get<0>(t) += std::get<1>(t);
                            });
                        std::size_t len = r_left.size();
                        m_r.resize(len);    // shrink to new size

                        // v_left + v_right^x^-1
                        vkey = vk_left.compress(vk_right, c_inv);
                        // w_left + w_right^x
                        wkey = wk_left.compress(wk_right, c);

                        comms_ab.emplace_back({tab_l, tab_r});
                        comms_c.emplace_back({tuc_l, tuc_r});
                        z_ab.emplace_back({zab_l, zab_r});
                        z_c.emplace_back({zc_l, zc_r});
                        challenges.emplace_back(c);
                        challenges_inv.emplace_back(c_inv);
                    }

                    BOOST_ASSERT(m_a.size() == 1 && m_b.size() == 1);
                    BOOST_ASSERT(m_c.size() == 1 && m_r.size() == 1);
                    BOOST_ASSERT(vkey.a.size() == 1 && vkey.b.size() == 1);
                    BOOST_ASSERT(wkey.a.size() == 1 && wkey.b.size() == 1);

                    return std::make_tuple({a.size(), comms_ab, comms_c, z_ab, z_c, m_a[0], m_b[0], m_c[0], m_r[0],
                                            *vkey.begin(), *wkey.begin()},
                                           challenges, challenges_inv);
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
                    power_zr *= r_shift;

                    // 0 iteration
                    typename FieldType::value_type res =
                        FieldType::value_type::one() + (*transcript_first * power_zr);
                    power_zr *= power_zr;
                    ++transcript_first;

                    // the rest
                    while (transcript_first != transcript_last) {
                        res *= FieldType::value_type::one() + (*transcript_first * power_zr);
                        power_zr *= power_zr;
                        ++transcript_first;
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

                    while (transcript_first != transcript_last) {
                        std::size_t n = coefficients.size();
                        for (int j = 0; j < n; j++) {
                            coefficients.emplace_back(coefficients[j] * (*transcript_first * power_2_r));
                        }
                        power_2_r *= power_2_r;

                        ++transcript_first;
                    }

                    return coefficients;
                }

                /// Returns the KZG opening proof for the given commitment key. Specifically, it
                /// returns $g^{f(alpha) - f(z) / (alpha - z)}$ for $a$ and $b$.
                template<typename CurveAffine, typename InputScalarIterator>
                kzg_opening<CurveAffine> prove_commitment_key_kzg_opening(
                    MultiscalarPrecomp<CurveAffine> &srs_powers_alpha_table,
                    MultiscalarPrecomp<CurveAffine> &srs_powers_beta_table, std::size_t srs_powers_len,
                    InputScalarIterator transcript_first, InputScalarIterator transcript_last,
                    const typename std::iterator_traits<InputScalarIterator>::value_type &r_shift,
                    const typename std::iterator_traits<InputScalarIterator>::value_type &kzg_challenge) {
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
                        (DensePolynomial({neg_kzg_challenge,
                                          std::iterator_traits<InputScalarIterator>::value_type::one()}));

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
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
