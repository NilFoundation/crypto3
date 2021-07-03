//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/detail/basic_policy.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/proof.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/srs.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/transcript.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/proof.hpp>

#include <nil/crypto3/fft/polynomial_arithmetic/basic_operations.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>

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
                template<typename CurveType, typename InputRange,
                         typename ValueType = typename std::iterator_traits<typename InputRange::iterator>::value_type>
                typename std::enable_if<
                    std::is_same<typename CurveType::g1_type::value_type, ValueType>::value ||
                    std::is_same<typename CurveType::g2_type::value_type, ValueType>::value ||
                    std::is_same<typename CurveType::scalar_field_type::value_type, ValueType>::value>::type
                    compress(InputRange &vec, std::size_t split,
                             const typename CurveType::scalar_field_type::value_type &scalar) {
                    std::for_each(boost::make_zip_iterator(boost::make_tuple(vec.begin(), vec.begin() + split)),
                                  boost::make_zip_iterator(boost::make_tuple(vec.begin() + split, vec.end())),
                                  [&](const boost::tuple<ValueType &, ValueType &> &t) {
                                      t.template get<0>() = t.template get<0>() + t.template get<1>() * scalar;
                                  });
                    vec.resize(split);
                }

                /// It returns the evaluation of the polynomial $\prod (1 + x_{l-j}(rX)^{2j}$ at
                /// the point z, where transcript contains the reversed order of all challenges (the x).
                /// The challenges must be in reversed order for the correct evaluation of the
                /// polynomial in O(logn)
                template<typename FieldType, typename InputFieldValueIterator>
                typename std::enable_if<std::is_same<typename std::iterator_traits<InputFieldValueIterator>::value_type,
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

                /// Returns the KZG opening proof for the given commitment key. Specifically, it
                /// returns $g^{f(alpha) - f(z) / (alpha - z)}$ for $a$ and $b$.
                template<typename GroupType, typename InputGroupIterator, typename InputScalarRange>
                typename std::enable_if<
                    std::is_same<typename GroupType::value_type,
                                 typename std::iterator_traits<InputGroupIterator>::value_type>::value &&
                        std::is_same<
                            typename GroupType::curve_type::scalar_field_type::value_type,
                            typename std::iterator_traits<typename InputScalarRange::iterator>::value_type>::value,
                    kzg_opening<GroupType>>::type
                    prove_commitment_key_kzg_opening(
                        InputGroupIterator srs_powers_alpha_first, InputGroupIterator srs_powers_alpha_last,
                        InputGroupIterator srs_powers_beta_first, InputGroupIterator srs_powers_beta_last,
                        const InputScalarRange &poly,
                        const typename GroupType::curve_type::scalar_field_type::value_type &eval_poly,
                        const typename GroupType::curve_type::scalar_field_type::value_type &kzg_challenge) {
                    typename GroupType::curve_type::scalar_field_type::value_type neg_kzg_challenge = -kzg_challenge;

                    BOOST_ASSERT(poly.size() == std::distance(srs_powers_alpha_first, srs_powers_alpha_last));
                    BOOST_ASSERT(poly.size() == std::distance(srs_powers_beta_first, srs_powers_beta_last));

                    // f_v(X) - f_v(z) / (X - z)
                    std::vector<typename GroupType::curve_type::scalar_field_type::value_type> f_vX_sub_f_vZ;
                    fft::_polynomial_subtraction<typename GroupType::curve_type::scalar_field_type>(f_vX_sub_f_vZ, poly,
                                                                                                    {{
                                                                                                        eval_poly,
                                                                                                    }});
                    std::vector<typename GroupType::curve_type::scalar_field_type::value_type> quotient_polynomial,
                        remainder_polynomial;
                    fft::_polynomial_division<typename GroupType::curve_type::scalar_field_type>(
                        quotient_polynomial, remainder_polynomial, f_vX_sub_f_vZ,
                        {{
                            neg_kzg_challenge,
                            GroupType::curve_type::scalar_field_type::value_type::one(),
                        }});

                    if (quotient_polynomial.size() < poly.size()) {
                        quotient_polynomial.resize(poly.size(),
                                                   GroupType::curve_type::scalar_field_type::value_type::zero());
                    }
                    BOOST_ASSERT(quotient_polynomial.size() == poly.size());

                    // we do one proof over h^a and one proof over h^b (or g^a and g^b depending
                    // on the curve we are on). that's the extra cost of the commitment scheme
                    // used which is compatible with Groth16 CRS insteaf of the original paper
                    // of Bunz'19
                    return kzg_opening<GroupType> {algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(
                                                       srs_powers_alpha_first, srs_powers_alpha_last,
                                                       quotient_polynomial.begin(), quotient_polynomial.end(), 1),
                                                   algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(
                                                       srs_powers_beta_first, srs_powers_beta_last,
                                                       quotient_polynomial.begin(), quotient_polynomial.end(), 1)};
                }

                template<typename CurveType, typename InputG2Iterator, typename InputScalarIterator>
                typename std::enable_if<
                    std::is_same<typename CurveType::g2_type::value_type,
                                 typename std::iterator_traits<InputG2Iterator>::value_type>::value &&
                        std::is_same<typename CurveType::scalar_field_type::value_type,
                                     typename std::iterator_traits<InputScalarIterator>::value_type>::value,
                    kzg_opening<typename CurveType::g2_type>>::type
                    prove_commitment_v(InputG2Iterator srs_powers_alpha_first, InputG2Iterator srs_powers_alpha_last,
                                       InputG2Iterator srs_powers_beta_first, InputG2Iterator srs_powers_beta_last,
                                       InputScalarIterator transcript_first, InputScalarIterator transcript_last,
                                       const typename CurveType::scalar_field_type::value_type &kzg_challenge) {
                    std::vector<typename CurveType::scalar_field_type::value_type> vkey_poly =
                        polynomial_coefficients_from_transcript<typename CurveType::scalar_field_type>(
                            transcript_first, transcript_last, CurveType::scalar_field_type::value_type::one());
                    fft::_condense(vkey_poly);
                    BOOST_ASSERT(!fft::_is_zero(vkey_poly));

                    typename CurveType::scalar_field_type::value_type vkey_poly_z =
                        polynomial_evaluation_product_form_from_transcript<typename CurveType::scalar_field_type>(
                            transcript_first, transcript_last, kzg_challenge,
                            CurveType::scalar_field_type::value_type::one());

                    return prove_commitment_key_kzg_opening<typename CurveType::g2_type>(
                        srs_powers_alpha_first, srs_powers_alpha_last, srs_powers_beta_first, srs_powers_beta_last,
                        vkey_poly, vkey_poly_z, kzg_challenge);
                }

                template<typename CurveType, typename InputG1Iterator, typename InputScalarIterator>
                typename std::enable_if<
                    std::is_same<typename CurveType::g1_type::value_type,
                                 typename std::iterator_traits<InputG1Iterator>::value_type>::value &&
                        std::is_same<typename CurveType::scalar_field_type::value_type,
                                     typename std::iterator_traits<InputScalarIterator>::value_type>::value,
                    kzg_opening<typename CurveType::g1_type>>::type
                    prove_commitment_w(InputG1Iterator srs_powers_alpha_first, InputG1Iterator srs_powers_alpha_last,
                                       InputG1Iterator srs_powers_beta_first, InputG1Iterator srs_powers_beta_last,
                                       InputScalarIterator transcript_first, InputScalarIterator transcript_last,
                                       typename CurveType::scalar_field_type::value_type r_shift,
                                       const typename CurveType::scalar_field_type::value_type &kzg_challenge) {
                    std::size_t n = std::distance(srs_powers_beta_first, srs_powers_beta_last) / 2;
                    BOOST_ASSERT(2 * n == std::distance(srs_powers_alpha_first, srs_powers_alpha_last));

                    // this computes f(X) = \prod (1 + x (rX)^{2^j})
                    std::vector<typename CurveType::scalar_field_type::value_type> fcoeffs =
                        polynomial_coefficients_from_transcript<typename CurveType::scalar_field_type>(
                            transcript_first, transcript_last, r_shift);
                    // this computes f_w(X) = X^n * f(X) - it simply shifts all coefficients to by n
                    fcoeffs.insert(fcoeffs.begin(), n, CurveType::scalar_field_type::value_type::zero());

                    // this computes f(z)
                    typename CurveType::scalar_field_type::value_type fz =
                        polynomial_evaluation_product_form_from_transcript<typename CurveType::scalar_field_type>(
                            transcript_first, transcript_last, kzg_challenge, r_shift);
                    // this computes the "shift" z^n
                    typename CurveType::scalar_field_type::value_type zn = kzg_challenge.pow(n);
                    // this computes f_w(z) by multiplying by zn
                    typename CurveType::scalar_field_type::value_type fwz = fz * zn;

                    return prove_commitment_key_kzg_opening<typename CurveType::g1_type>(
                        srs_powers_alpha_first, srs_powers_alpha_last, srs_powers_beta_first, srs_powers_beta_last,
                        fcoeffs, fwz, kzg_challenge);
                }

                /// gipa_tipp_mipp peforms the recursion of the GIPA protocol for TIPP and MIPP.
                /// It returns a proof containing all intermdiate committed values, as well as
                /// the challenges generated necessary to do the polynomial commitment proof
                /// later in TIPP.
                template<typename CurveType, typename Hash = hashes::sha2<256>, typename InputG1Iterator1,
                         typename InputG2Iterator, typename InputG1Iterator2, typename InputScalarIterator>
                typename std::enable_if<
                    std::is_same<typename CurveType::g1_type::value_type,
                                 typename std::iterator_traits<InputG1Iterator1>::value_type>::value &&
                        std::is_same<typename CurveType::g2_type::value_type,
                                     typename std::iterator_traits<InputG2Iterator>::value_type>::value &&
                        std::is_same<typename CurveType::scalar_field_type::value_type,
                                     typename std::iterator_traits<InputScalarIterator>::value_type>::value &&
                        std::is_same<typename CurveType::g1_type::value_type,
                                     typename std::iterator_traits<InputG1Iterator2>::value_type>::value,
                    std::tuple<gipa_proof<CurveType>, std::vector<typename CurveType::scalar_field_type::value_type>,
                               std::vector<typename CurveType::scalar_field_type::value_type>>>::type
                    gipa_tipp_mipp(transcript<CurveType, Hash> &tr, InputG1Iterator1 a_first, InputG1Iterator1 a_last,
                                   InputG2Iterator b_first, InputG2Iterator b_last, InputG1Iterator2 c_first,
                                   InputG1Iterator2 c_last, const r1cs_gg_ppzksnark_ipp2_vkey<CurveType> &vkey_input,
                                   const r1cs_gg_ppzksnark_ipp2_wkey<CurveType> &wkey_input,
                                   InputScalarIterator r_first, InputScalarIterator r_last) {
                    std::size_t input_len = std::distance(a_first, a_last);
                    BOOST_ASSERT(input_len >= 2);
                    BOOST_ASSERT((input_len & (input_len - 1)) == 0);
                    BOOST_ASSERT(input_len == std::distance(b_first, b_last));
                    BOOST_ASSERT(input_len == std::distance(r_first, r_last));
                    BOOST_ASSERT(input_len == std::distance(c_first, c_last));

                    // the values of vectors A and B rescaled at each step of the loop
                    // the values of vectors C and r rescaled at each step of the loop
                    std::vector<typename CurveType::g1_type::value_type> m_a {a_first, a_last}, m_c {c_first, c_last};
                    std::vector<typename CurveType::g2_type::value_type> m_b {b_first, b_last};
                    std::vector<typename CurveType::scalar_field_type::value_type> m_r {r_first, r_last};

                    // the values of the commitment keys rescaled at each step of the loop
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
                        std::pair<typename CurveType::gt_type::value_type, typename CurveType::gt_type::value_type>>
                        z_ab;
                    std::vector<
                        std::pair<typename CurveType::g1_type::value_type, typename CurveType::g1_type::value_type>>
                        z_c;
                    std::vector<typename CurveType::scalar_field_type::value_type> challenges, challenges_inv;

                    constexpr std::array<std::uint8_t, 4> domain_separator {'g', 'i', 'p', 'a'};
                    tr.write_domain_separator(domain_separator.begin(), domain_separator.end());
                    typename CurveType::scalar_field_type::value_type _i = tr.read_challenge();

                    while (m_a.size() > 1) {
                        // recursive step
                        // Recurse with problem of half size
                        std::size_t split = m_a.size() / 2;

                        auto [vk_left, vk_right] = vkey.split(split);
                        auto [wk_left, wk_right] = wkey.split(split);

                        // TODO: parallel
                        // See section 3.3 for paper version with equivalent names
                        // TIPP part
                        typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type tab_l =
                            r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(
                                vk_left, wk_right, m_a.begin() + split, m_a.end(), m_b.begin(), m_b.begin() + split);
                        typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type tab_r =
                            r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(
                                vk_right, wk_left, m_a.begin(), m_a.begin() + split, m_b.begin() + split, m_b.end());

                        // \prod e(A_right,B_left)
                        typename CurveType::gt_type::value_type zab_l = CurveType::gt_type::value_type::one();
                        std::for_each(boost::make_zip_iterator(boost::make_tuple(m_a.begin() + split, m_b.begin())),
                                      boost::make_zip_iterator(boost::make_tuple(m_a.end(), m_b.begin() + split)),
                                      [&](const boost::tuple<const typename CurveType::g1_type::value_type &,
                                                             const typename CurveType::g2_type::value_type &> &t) {
                                          zab_l = zab_l *
                                                  algebra::pair<CurveType>(t.template get<0>(), t.template get<1>());
                                      });
                        zab_l = algebra::final_exponentiation<CurveType>(zab_l);
                        typename CurveType::gt_type::value_type zab_r = CurveType::gt_type::value_type::one();
                        std::for_each(boost::make_zip_iterator(boost::make_tuple(m_a.begin(), m_b.begin() + split)),
                                      boost::make_zip_iterator(boost::make_tuple(m_a.begin() + split, m_b.end())),
                                      [&](const boost::tuple<const typename CurveType::g1_type::value_type &,
                                                             const typename CurveType::g2_type::value_type &> &t) {
                                          zab_r = zab_r *
                                                  algebra::pair<CurveType>(t.template get<0>(), t.template get<1>());
                                      });
                        zab_r = algebra::final_exponentiation<CurveType>(zab_r);

                        // MIPP part
                        // z_l = c[n':] ^ r[:n']
                        typename CurveType::g1_type::value_type zc_l =
                            algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(
                                m_c.begin() + split, m_c.end(), m_r.begin(), m_r.begin() + split, 1);
                        // Z_r = c[:n'] ^ r[n':]
                        typename CurveType::g1_type::value_type zc_r =
                            algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(
                                m_c.begin(), m_c.begin() + split, m_r.begin() + split, m_r.end(), 1);
                        // u_l = c[n':] * v[:n']
                        typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type tuc_l =
                            r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::single(vk_left, m_c.begin() + split,
                                                                                 m_c.end());
                        // u_r = c[:n'] * v[n':]
                        typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type tuc_r =
                            r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::single(vk_right, m_c.begin(),
                                                                                 m_c.begin() + split);

                        // Fiat-Shamir challenge
                        // combine both TIPP and MIPP transcript
                        tr.template write<typename CurveType::gt_type>(zab_l);
                        tr.template write<typename CurveType::gt_type>(zab_r);
                        tr.template write<typename CurveType::g1_type>(zc_l);
                        tr.template write<typename CurveType::g1_type>(zc_r);
                        tr.template write<typename CurveType::gt_type>(tab_l.first);
                        tr.template write<typename CurveType::gt_type>(tab_l.second);
                        tr.template write<typename CurveType::gt_type>(tab_r.first);
                        tr.template write<typename CurveType::gt_type>(tab_r.second);
                        tr.template write<typename CurveType::gt_type>(tuc_l.first);
                        tr.template write<typename CurveType::gt_type>(tuc_l.second);
                        tr.template write<typename CurveType::gt_type>(tuc_r.first);
                        tr.template write<typename CurveType::gt_type>(tuc_r.second);
                        typename CurveType::scalar_field_type::value_type c_inv = tr.read_challenge();

                        // Optimization for multiexponentiation to rescale G2 elements with
                        // 128-bit challenge Swap 'c' and 'c_inv' since can't control bit size
                        // of c_inv
                        typename CurveType::scalar_field_type::value_type c = c_inv.inversed();

                        // Set up values for next step of recursion
                        // A[:n'] + A[n':] ^ x
                        compress<CurveType>(m_a, split, c);
                        // B[:n'] + B[n':] ^ x^-1
                        compress<CurveType>(m_b, split, c_inv);
                        // c[:n'] + c[n':]^x
                        compress<CurveType>(m_c, split, c);
                        // r[:n'] + r[n':]^x^-1
                        compress<CurveType>(m_r, split, c_inv);

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

                    return std::make_tuple(gipa_proof<CurveType> {input_len, comms_ab, comms_c, z_ab, z_c, m_a[0],
                                                                  m_b[0], m_c[0], vkey.first(), wkey.first()},
                                           challenges, challenges_inv);
                }

                /// Proves a TIPP relation between A and B as well as a MIPP relation with C and
                /// r. Commitment keys must be of size of A, B and C. In the context of Groth16
                /// aggregation, we have that B = B^r and wkey is scaled by r^{-1}. The
                /// commitment key v is used to commit to A and C recursively in GIPA such that
                /// only one KZG proof is needed for v. In the original paper version, since the
                /// challenges of GIPA would be different, two KZG proofs would be needed.
                template<typename CurveType, typename Hash = hashes::sha2<256>, typename InputG1Iterator1,
                         typename InputG2Iterator, typename InputG1Iterator2, typename InputScalarIterator>
                typename std::enable_if<
                    std::is_same<typename CurveType::g1_type::value_type,
                                 typename std::iterator_traits<InputG1Iterator1>::value_type>::value &&
                        std::is_same<typename CurveType::g2_type::value_type,
                                     typename std::iterator_traits<InputG2Iterator>::value_type>::value &&
                        std::is_same<typename CurveType::g1_type::value_type,
                                     typename std::iterator_traits<InputG1Iterator2>::value_type>::value &&
                        std::is_same<typename CurveType::scalar_field_type::value_type,
                                     typename std::iterator_traits<InputScalarIterator>::value_type>::value,
                    tipp_mipp_proof<CurveType>>::type
                    prove_tipp_mipp(const r1cs_gg_ppzksnark_aggregate_proving_srs<CurveType> &srs,
                                    transcript<CurveType, Hash> &tr, InputG1Iterator1 a_first, InputG1Iterator1 a_last,
                                    InputG2Iterator b_first, InputG2Iterator b_last, InputG1Iterator2 c_first,
                                    InputG1Iterator2 c_last, const r1cs_gg_ppzksnark_ipp2_wkey<CurveType> &wkey,
                                    InputScalarIterator r_first, InputScalarIterator r_last) {
                    typename CurveType::scalar_field_type::value_type r_shift = *(r_first + 1);
                    // Run GIPA
                    auto [proof, challenges, challenges_inv] = gipa_tipp_mipp<CurveType>(
                        tr, a_first, a_last, b_first, b_last, c_first, c_last, srs.vkey, wkey, r_first, r_last);

                    // Prove final commitment keys are wellformed
                    // we reverse the transcript so the polynomial in kzg opening is constructed
                    // correctly - the formula indicates x_{l-j}. Also for deriving KZG
                    // challenge point, input must be the last challenge.
                    std::reverse(challenges.begin(), challenges.end());
                    std::reverse(challenges_inv.begin(), challenges_inv.end());
                    typename CurveType::scalar_field_type::value_type r_inverse = r_shift.inversed();

                    // KZG challenge point
                    constexpr std::array<std::uint8_t, 8> domain_separator {'r', 'a', 'n', 'd', 'o', 'm', '-', 'z'};
                    tr.write_domain_separator(domain_separator.begin(), domain_separator.end());
                    tr.template write<typename CurveType::scalar_field_type>(challenges[0]);
                    tr.template write<typename CurveType::g2_type>(proof.final_vkey.first);
                    tr.template write<typename CurveType::g2_type>(proof.final_vkey.second);
                    tr.template write<typename CurveType::g1_type>(proof.final_wkey.first);
                    tr.template write<typename CurveType::g1_type>(proof.final_wkey.second);
                    typename CurveType::scalar_field_type::value_type z = tr.read_challenge();

                    // Complete KZG proofs
                    return tipp_mipp_proof<CurveType> {
                        proof,
                        prove_commitment_v<CurveType>(srs.h_alpha_powers.begin(), srs.h_alpha_powers.end(),
                                                      srs.h_beta_powers.begin(), srs.h_beta_powers.end(),
                                                      challenges_inv.begin(), challenges_inv.end(), z),
                        prove_commitment_w<CurveType>(srs.g_alpha_powers.begin(), srs.g_alpha_powers.end(),
                                                      srs.g_beta_powers.begin(), srs.g_beta_powers.end(),
                                                      challenges.begin(), challenges.end(), r_inverse, z)};
                }

                /// Aggregate `n` zkSnark proofs, where `n` must be a power of two.
                template<typename CurveType, typename Hash = hashes::sha2<256>, typename InputTranscriptIncludeIterator,
                         typename InputProofIterator>
                typename std::enable_if<
                    std::is_same<std::uint8_t,
                                 typename std::iterator_traits<InputTranscriptIncludeIterator>::value_type>::value &&
                        std::is_same<typename std::iterator_traits<InputProofIterator>::value_type,
                                     r1cs_gg_ppzksnark_proof<CurveType>>::value,
                    r1cs_gg_ppzksnark_aggregate_proof<CurveType>>::type
                    aggregate_proofs(const r1cs_gg_ppzksnark_aggregate_proving_srs<CurveType> &srs,
                                     InputTranscriptIncludeIterator tr_include_first,
                                     InputTranscriptIncludeIterator tr_include_last, InputProofIterator proofs_first,
                                     InputProofIterator proofs_last) {
                    std::size_t nproofs = std::distance(proofs_first, proofs_last);
                    BOOST_ASSERT(nproofs >= 2);
                    BOOST_ASSERT((nproofs & (nproofs - 1)) == 0);
                    BOOST_ASSERT(srs.has_correct_len(nproofs));

                    // TODO: parallel
                    // We first commit to A B and C - these commitments are what the verifier
                    // will use later to verify the TIPP and MIPP proofs
                    std::vector<typename CurveType::g1_type::value_type> a, c;
                    std::vector<typename CurveType::g2_type::value_type> b;
                    auto proofs_it = proofs_first;
                    while (proofs_it != proofs_last) {
                        a.emplace_back(proofs_it->g_A);
                        b.emplace_back(proofs_it->g_B);
                        c.emplace_back(proofs_it->g_C);
                        ++proofs_it;
                    }

                    // A and B are committed together in this scheme
                    // we need to take the reference so the macro doesn't consume the value
                    // first
                    typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type com_ab =
                        r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(srs.vkey, srs.wkey, a.begin(), a.end(),
                                                                           b.begin(), b.end());
                    typename r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::output_type com_c =
                        r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::single(srs.vkey, c.begin(), c.end());

                    // Derive a random scalar to perform a linear combination of proofs
                    constexpr std::array<std::uint8_t, 9> application_tag = {'s', 'n', 'a', 'r', 'k',
                                                                             'p', 'a', 'c', 'k'};
                    constexpr std::array<std::uint8_t, 8> domain_separator {'r', 'a', 'n', 'd', 'o', 'm', '-', 'r'};
                    transcript<CurveType, Hash> tr(application_tag.begin(), application_tag.end());
                    tr.write_domain_separator(domain_separator.begin(), domain_separator.end());
                    tr.template write<typename CurveType::gt_type>(com_ab.first);
                    tr.template write<typename CurveType::gt_type>(com_ab.second);
                    tr.template write<typename CurveType::gt_type>(com_c.first);
                    tr.template write<typename CurveType::gt_type>(com_c.second);
                    tr.write(tr_include_first, tr_include_last);
                    typename CurveType::scalar_field_type::value_type r = tr.read_challenge();

                    // 1,r, r^2, r^3, r^4 ...
                    std::vector<typename CurveType::scalar_field_type::value_type> r_vec =
                        structured_scalar_power<typename CurveType::scalar_field_type>(
                            std::distance(proofs_first, proofs_last), r);
                    // 1,r^-1, r^-2, r^-3
                    std::vector<typename CurveType::scalar_field_type::value_type> r_inv;
                    std::transform(r_vec.begin(), r_vec.end(), std::back_inserter(r_inv),
                                   [](const auto &r_i) { return r_i.inversed(); });

                    // B^{r}
                    std::vector<typename CurveType::g2_type::value_type> b_r;
                    std::for_each(
                        boost::make_zip_iterator(boost::make_tuple(b.begin(), r_vec.begin())),
                        boost::make_zip_iterator(boost::make_tuple(b.end(), r_vec.end())),
                        [&](const boost::tuple<const typename CurveType::g2_type::value_type &,
                                               const typename CurveType::scalar_field_type::value_type &> &t) {
                            b_r.emplace_back((t.template get<0>() * t.template get<1>()));
                        });
                    // TODO: parallel
                    // compute A * B^r for the verifier
                    // auto ip_ab = algebra::pair<CurveType>(a, b_r);
                    typename CurveType::gt_type::value_type ip_ab = CurveType::gt_type::value_type::one();
                    std::for_each(boost::make_zip_iterator(boost::make_tuple(a.begin(), b_r.begin())),
                                  boost::make_zip_iterator(boost::make_tuple(a.end(), b_r.end())),
                                  [&](const boost::tuple<const typename CurveType::g1_type::value_type &,
                                                         const typename CurveType::g2_type::value_type &> &t) {
                                      ip_ab =
                                          ip_ab * algebra::pair<CurveType>(t.template get<0>(), t.template get<1>());
                                  });
                    ip_ab = algebra::final_exponentiation<CurveType>(ip_ab);
                    // compute C^r for the verifier
                    typename CurveType::g1_type::value_type agg_c =
                        algebra::multiexp<algebra::policies::multiexp_method_bos_coster>(c.begin(), c.end(),
                                                                                         r_vec.begin(), r_vec.end(), 1);
                    tr.template write<typename CurveType::gt_type>(ip_ab);
                    tr.template write<typename CurveType::g1_type>(agg_c);

                    // w^{r^{-1}}
                    r1cs_gg_ppzksnark_ipp2_commitment_key<typename CurveType::g1_type> wkey_r_inv =
                        srs.wkey.scale(r_inv.begin(), r_inv.end());

                    // we prove tipp and mipp using the same recursive loop
                    tipp_mipp_proof<CurveType> proof =
                        prove_tipp_mipp(srs, tr, a.begin(), a.end(), b_r.begin(), b_r.end(), c.begin(), c.end(),
                                        wkey_r_inv, r_vec.begin(), r_vec.end());

                    // debug assert
                    BOOST_ASSERT(com_ab == r1cs_gg_ppzksnark_ipp2_commitment<CurveType>::pair(
                                               srs.vkey, wkey_r_inv, a.begin(), a.end(), b_r.begin(), b_r.end()));

                    return {com_ab, com_c, ip_ab, agg_c, proof};
                }

                template<typename CurveType, typename BasicProver>
                class r1cs_gg_ppzksnark_aggregate_prover {
                    typedef detail::r1cs_gg_ppzksnark_basic_policy<CurveType, ProvingMode::Aggregate> policy_type;

                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::g1_type g1_type;
                    typedef typename CurveType::g2_type g2_type;
                    typedef typename CurveType::gt_type gt_type;

                public:
                    typedef BasicProver basic_prover;

                    typedef typename policy_type::constraint_system_type constraint_system_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;

                    typedef typename policy_type::srs_type srs_type;
                    typedef typename policy_type::proving_srs_type proving_srs_type;
                    typedef typename policy_type::verification_srs_type verification_srs_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::srs_pair_type srs_pair_type;

                    typedef typename policy_type::proof_type proof_type;
                    typedef typename policy_type::aggregate_proof_type aggregate_proof_type;

                    // Aggregate prove
                    template<typename Hash, typename InputTranscriptIncludeIterator, typename InputProofIterator>
                    static inline aggregate_proof_type process(const proving_srs_type &srs,
                                                               InputTranscriptIncludeIterator transcript_include_first,
                                                               InputTranscriptIncludeIterator transcript_include_last,
                                                               InputProofIterator proofs_first,
                                                               InputProofIterator proofs_last) {
                        return aggregate_proofs<CurveType, Hash>(srs, transcript_include_first, transcript_include_last,
                                                                 proofs_first, proofs_last);
                    }

                    // Basic prove
                    static inline proof_type process(const proving_key_type &pk,
                                                     const primary_input_type &primary_input,
                                                     const auxiliary_input_type &auxiliary_input) {

                        return BasicProver::process(pk, primary_input, auxiliary_input);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
