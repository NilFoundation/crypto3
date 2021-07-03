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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_VERIFY_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_VERIFY_HPP

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/detail/basic_policy.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/verification_key.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/prover.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /// Keeps track of the variables that have been sent by the prover and must
                /// be multiplied together by the verifier. Both MIPP and TIPP are merged
                /// together.
                template<typename CurveType>
                struct gipa_tuz {
                    typedef CurveType curve_type;

                    typename curve_type::gt_type::value_type tab;
                    typename curve_type::gt_type::value_type uab;
                    typename curve_type::gt_type::value_type zab;
                    typename curve_type::gt_type::value_type tc;
                    typename curve_type::gt_type::value_type uc;
                    typename curve_type::g1_type::value_type zc;

                    inline gipa_tuz() :
                        tab(curve_type::gt_type::value_type::one()), uab(curve_type::gt_type::value_type::one()),
                        zab(curve_type::gt_type::value_type::one()), tc(curve_type::gt_type::value_type::one()),
                        uc(curve_type::gt_type::value_type::one()), zc(curve_type::g1_type::value_type::zero()) {
                    }

                    inline gipa_tuz(const typename curve_type::gt_type::value_type &tab,
                                    const typename curve_type::gt_type::value_type &uab,
                                    const typename curve_type::gt_type::value_type &zab,
                                    const typename curve_type::gt_type::value_type &tc,
                                    const typename curve_type::gt_type::value_type &uc,
                                    const typename curve_type::g1_type::value_type &zc) :
                        tab(tab),
                        uab(uab), zab(zab), tc(tc), uc(uc), zc(zc) {
                    }

                    inline void merge(const gipa_tuz &other) {
                        tab = tab * other.tab;
                        uab = uab * other.uab;
                        zab = zab * other.zab;
                        tc = tc * other.tc;
                        uc = uc * other.uc;
                        zc = zc + other.zc;
                    }
                };

                /// TODO: optimize this simple version of pairing checker
                /// PairingCheck represents a check of the form e(A,B)e(C,D)... = T. Checks can
                /// be aggregated together using random linear combination. The efficiency comes
                /// from keeping the results from the miller loop output before proceding to a final
                /// exponentiation when verifying if all checks are verified.
                /// It is a tuple:
                /// - a miller loop result that is to be multiplied by other miller loop results
                /// before going into a final exponentiation result
                /// - a right side result which is already in the right subgroup Gt which is to
                /// be compared to the left side when "final_exponentiatiat"-ed
                template<typename CurveType, typename DistributionType, typename GeneratorType>
                struct pairing_check {
                    typedef CurveType curve_type;

                    typedef typename curve_type::g1_type g1_type;
                    typedef typename curve_type::g2_type g2_type;
                    typedef typename curve_type::gt_type gt_type;
                    typedef typename curve_type::scalar_field_type scalar_field_type;

                    typedef typename g1_type::value_type g1_value_type;
                    typedef typename g2_type::value_type g2_value_type;
                    typedef typename gt_type::value_type gt_value_type;
                    typedef typename scalar_field_type::value_type scalar_field_value_type;

                    gt_value_type left;
                    gt_value_type right;
                    bool non_random_check_done;
                    bool valid;

                    inline pairing_check() :
                        left(gt_value_type::one()), right(gt_value_type::one()), non_random_check_done(false),
                        valid(true) {
                    }

                    /// returns a pairing tuple that is scaled by a random element.
                    /// When aggregating pairing checks, this creates a random linear
                    /// combination of all checks so that it is secure. Specifically
                    /// we have e(A,B)e(C,D)... = out <=> e(g,h)^{ab + cd} = out
                    /// We rescale using a random element $r$ to give
                    /// e(rA,B)e(rC,D) ... = out^r <=>
                    /// e(A,B)^r e(C,D)^r = out^r <=> e(g,h)^{abr + cdr} = out^r
                    /// (e(g,h)^{ab + cd})^r = out^r
                    template<typename InputG1Iterator, typename InputG2Iterator,
                             typename std::enable_if<
                                 std::is_same<g1_value_type,
                                              typename std::iterator_traits<InputG1Iterator>::value_type>::value &&
                                     std::is_same<g2_value_type,
                                                  typename std::iterator_traits<InputG2Iterator>::value_type>::value,
                                 bool>::type = true>
                    inline pairing_check(InputG1Iterator a_first, InputG1Iterator a_last, InputG2Iterator b_first,
                                         InputG2Iterator b_last, const gt_value_type &out) :
                        left(gt_value_type::one()),
                        right(gt_value_type::one()), non_random_check_done(false), valid(true) {
                        merge_random(a_first, a_last, b_first, b_last, out);
                    }

                    void merge() {
                    }

                    template<typename InputG1Iterator, typename InputG2Iterator>
                    inline typename std::enable_if<
                        std::is_same<g1_value_type,
                                     typename std::iterator_traits<InputG1Iterator>::value_type>::value &&
                        std::is_same<g2_value_type,
                                     typename std::iterator_traits<InputG2Iterator>::value_type>::value>::type
                        merge_random(InputG1Iterator a_first, InputG1Iterator a_last, InputG2Iterator b_first,
                                     InputG2Iterator b_last, const gt_value_type &out) {
                        std::size_t len = std::distance(a_first, a_last);
                        BOOST_ASSERT(len > 0);
                        BOOST_ASSERT(len == std::distance(b_first, b_last));

                        if (!valid) {
                            return;
                        }

                        scalar_field_value_type coeff = derive_non_zero();
                        std::for_each(boost::make_zip_iterator(boost::make_tuple(a_first, b_first)),
                                      boost::make_zip_iterator(boost::make_tuple(a_last, b_last)),
                                      [&](const boost::tuple<const g1_value_type &, const g2_value_type &> &t) {
                                          left = left * algebra::pair<curve_type>(coeff * t.template get<0>(),
                                                                                  t.template get<1>());
                                      });
                        right = right * (out == CurveType::gt_type::value_type::one() ? out : out.pow(coeff.data));
                    }

                    template<typename InputGTIterator>
                    inline typename std::enable_if<std::is_same<
                        gt_value_type, typename std::iterator_traits<InputGTIterator>::value_type>::value>::type
                        merge_nonrandom(InputGTIterator a_first, InputGTIterator a_last, const gt_value_type &out) {
                        BOOST_ASSERT(!non_random_check_done);
                        BOOST_ASSERT(std::distance(a_first, a_last) > 0);

                        if (!valid) {
                            return;
                        }

                        for (auto a_it = a_first; a_it != a_last; ++a_it) {
                            left = left * (*a_it);
                        }
                        right = right * out;

                        non_random_check_done = true;
                    }

                    inline bool verify() {
                        return valid && (algebra::final_exponentiation<curve_type>(left) == right);
                    }

                    inline scalar_field_value_type derive_non_zero() {
                        scalar_field_value_type coeff =
                            algebra::random_element<scalar_field_type, DistributionType, GeneratorType>();
                        while (coeff.is_zero()) {
                            coeff = algebra::random_element<scalar_field_type, DistributionType, GeneratorType>();
                        }
                        return coeff;
                    }

                    inline void invalidate() {
                        valid = false;
                    }
                };

                /// verify_kzg_opening_g2 takes a KZG opening, the final commitment key, SRS and
                /// any shift (in TIPP we shift the v commitment by r^-1) and returns a pairing
                /// tuple to check if the opening is correct or not.
                template<typename CurveType, typename DistributionType, typename GeneratorType,
                         typename InputScalarIterator>
                inline typename std::enable_if<
                    std::is_same<typename CurveType::scalar_field_type::value_type,
                                 typename std::iterator_traits<InputScalarIterator>::value_type>::value>::type
                    verify_kzg_v(const r1cs_gg_ppzksnark_aggregate_verification_srs<CurveType> &v_srs,
                                 const std::pair<typename CurveType::g2_type::value_type,
                                                 typename CurveType::g2_type::value_type> &final_vkey,
                                 const kzg_opening<typename CurveType::g2_type> &vkey_opening,
                                 InputScalarIterator challenges_first, InputScalarIterator challenges_last,
                                 const typename CurveType::scalar_field_type::value_type &kzg_challenge,
                                 pairing_check<CurveType, DistributionType, GeneratorType> &pc) {
                    // f_v(z)
                    typename CurveType::scalar_field_type::value_type vpoly_eval_z =
                        polynomial_evaluation_product_form_from_transcript<typename CurveType::scalar_field_type>(
                            challenges_first, challenges_last, kzg_challenge,
                            CurveType::scalar_field_type::value_type::one());

                    // TODO:: parallel
                    // -g such that when we test a pairing equation we only need to check if
                    // it's equal 1 at the end:
                    // e(a,b) = e(c,d) <=> e(a,b)e(-c,d) = 1
                    // e(A,B) = e(C,D) <=> e(A,B)e(-C,D) == 1 <=> e(A,B)e(C,D)^-1 == 1
                    // verify first part of opening - v1
                    // e(-g, v1-(f_v(z)}*h)) ==> e(g^-1,h^{f_v(a)} * h^{-f_v(z)})
                    // e(g^{a - z}, opening_1) ==> e(g^{a-z}, h^q(a))
                    std::vector<typename CurveType::g1_type::value_type> a_input1 {
                        -v_srs.g,
                        v_srs.g_alpha - (v_srs.g * kzg_challenge),
                    };
                    std::vector<typename CurveType::g2_type::value_type> b_input1 {
                        // in additive notation: final_vkey = uH,
                        // uH - f_v(z)H = (u - f_v)H --> v1h^{-af_v(z)}
                        final_vkey.first - (v_srs.h * vpoly_eval_z),
                        vkey_opening.first,
                    };
                    pc.merge_random(a_input1.begin(), a_input1.end(), b_input1.begin(), b_input1.end(),
                                    CurveType::gt_type::value_type::one());

                    // verify second part of opening - v2 - similar but changing secret exponent
                    // e(g, v2 h^{-bf_v(z)})
                    std::vector<typename CurveType::g1_type::value_type> a_input2 {
                        -v_srs.g,
                        v_srs.g_beta - (v_srs.g * kzg_challenge),
                    };
                    std::vector<typename CurveType::g2_type::value_type> b_input2 {
                        // in additive notation: final_vkey = uH,
                        // uH - f_v(z)H = (u - f_v)H --> v1h^{-f_v(z)}
                        final_vkey.second - (v_srs.h * vpoly_eval_z),
                        vkey_opening.second,
                    };
                    pc.merge_random(a_input2.begin(), a_input2.end(), b_input2.begin(), b_input2.end(),
                                    CurveType::gt_type::value_type::one());
                }

                /// Similar to verify_kzg_opening_g2 but for g1.
                template<typename CurveType, typename DistributionType, typename GeneratorType,
                         typename InputScalarIterator>
                inline typename std::enable_if<
                    std::is_same<typename CurveType::scalar_field_type::value_type,
                                 typename std::iterator_traits<InputScalarIterator>::value_type>::value>::type
                    verify_kzg_w(const r1cs_gg_ppzksnark_aggregate_verification_srs<CurveType> &v_srs,
                                 const std::pair<typename CurveType::g1_type::value_type,
                                                 typename CurveType::g1_type::value_type> &final_wkey,
                                 const kzg_opening<typename CurveType::g1_type> &wkey_opening,
                                 InputScalarIterator challenges_first, InputScalarIterator challenges_last,
                                 const typename CurveType::scalar_field_type::value_type &r_shift,
                                 const typename CurveType::scalar_field_type::value_type &kzg_challenge,
                                 pairing_check<CurveType, DistributionType, GeneratorType> &pc) {
                    // TODO: parallel
                    // compute in parallel f(z) and z^n and then combines into f_w(z) = z^n * f(z)
                    typename CurveType::scalar_field_type::value_type fwz =
                        polynomial_evaluation_product_form_from_transcript<typename CurveType::scalar_field_type>(
                            challenges_first, challenges_last, kzg_challenge, r_shift) *
                        kzg_challenge.pow(v_srs.n);

                    // TODO: parallel
                    // first check on w1
                    // e(w_1 / g^{f_w(z)},h) == e(\pi_{w,1},h^a/h^z) \\
                    // e(g^{f_w(a) - f_w(z)},
                    std::vector<typename CurveType::g1_type::value_type> a_input1 {
                        final_wkey.first - (v_srs.g * fwz),
                        // e(opening, h^{a - z})
                        wkey_opening.first,
                    };
                    std::vector<typename CurveType::g2_type::value_type> b_input1 {
                        -v_srs.h,
                        v_srs.h_alpha - (v_srs.h * kzg_challenge),
                    };
                    pc.merge_random(a_input1.begin(), a_input1.end(), b_input1.begin(), b_input1.end(),
                                    CurveType::gt_type::value_type::one());

                    // then do second check
                    // e(w_2 / g^{f_w(z)},h) == e(\pi_{w,2},h^b/h^z)
                    std::vector<typename CurveType::g1_type::value_type> a_input2 {
                        final_wkey.second - (v_srs.g * fwz),
                        wkey_opening.second,
                    };
                    std::vector<typename CurveType::g2_type::value_type> b_input2 {
                        -v_srs.h,
                        v_srs.h_beta - (v_srs.h * kzg_challenge),
                    };
                    pc.merge_random(a_input2.begin(), a_input2.end(), b_input2.begin(), b_input2.end(),
                                    CurveType::gt_type::value_type::one());
                }

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
                inline std::tuple<gipa_tuz<CurveType>, typename CurveType::scalar_field_type::value_type,
                                  std::vector<typename CurveType::scalar_field_type::value_type>,
                                  std::vector<typename CurveType::scalar_field_type::value_type>>
                    gipa_verify_tipp_mipp(transcript<CurveType, Hash> &tr,
                                          const r1cs_gg_ppzksnark_aggregate_proof<CurveType> &proof,
                                          const typename CurveType::scalar_field_type::value_type &r_shift) {
                    std::vector<typename CurveType::scalar_field_type::value_type> challenges;
                    std::vector<typename CurveType::scalar_field_type::value_type> challenges_inv;

                    constexpr std::array<std::uint8_t, 4> domain_separator = {'g', 'i', 'p', 'a'};
                    tr.write_domain_separator(domain_separator.begin(), domain_separator.end());

                    // We first generate all challenges as this is the only consecutive process
                    // that can not be parallelized then we scale the commitments in a
                    // parallelized way
                    std::for_each(
                        boost::make_zip_iterator(
                            boost::make_tuple(proof.tmipp.gipa.comms_ab.begin(), proof.tmipp.gipa.z_ab.begin(),
                                              proof.tmipp.gipa.comms_c.begin(), proof.tmipp.gipa.z_c.begin())),
                        boost::make_zip_iterator(
                            boost::make_tuple(proof.tmipp.gipa.comms_ab.end(), proof.tmipp.gipa.z_ab.end(),
                                              proof.tmipp.gipa.comms_c.end(), proof.tmipp.gipa.z_c.end())),
                        [&](const boost::tuple<const std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>,
                                                               r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>> &,
                                               const std::pair<typename CurveType::gt_type::value_type,
                                                               typename CurveType::gt_type::value_type> &,
                                               const std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>,
                                                               r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>> &,
                                               const std::pair<typename CurveType::g1_type::value_type,
                                                               typename CurveType::g1_type::value_type> &> &t) {
                            // .write(&zab_l)
                            tr.template write<typename CurveType::gt_type>(t.template get<1>().first);
                            // .write(&zab_r)
                            tr.template write<typename CurveType::gt_type>(t.template get<1>().second);
                            // .write(&zc_l)
                            tr.template write<typename CurveType::g1_type>(t.template get<3>().first);
                            // .write(&zc_r)
                            tr.template write<typename CurveType::g1_type>(t.template get<3>().second);
                            // .write(&tab_l.0)
                            tr.template write<typename CurveType::gt_type>(t.template get<0>().first.first);
                            // .write(&tab_l.1)
                            tr.template write<typename CurveType::gt_type>(t.template get<0>().first.second);
                            // .write(&tab_r.0)
                            tr.template write<typename CurveType::gt_type>(t.template get<0>().second.first);
                            // .write(&tab_r.1)
                            tr.template write<typename CurveType::gt_type>(t.template get<0>().second.second);
                            // .write(&tc_l.0)
                            tr.template write<typename CurveType::gt_type>(t.template get<2>().first.first);
                            // .write(&tc_l.1)
                            tr.template write<typename CurveType::gt_type>(t.template get<2>().first.second);
                            // .write(&tc_r.0)
                            tr.template write<typename CurveType::gt_type>(t.template get<2>().second.first);
                            // .write(&tc_r.1)
                            tr.template write<typename CurveType::gt_type>(t.template get<2>().second.second);
                            challenges_inv.emplace_back(tr.read_challenge());
                            challenges.emplace_back(challenges_inv.back().inversed());
                        });

                    gipa_tuz<CurveType> final_res {// output of the pair commitment T and U in TIPP -> COM((v,w),A,B)
                                                   proof.com_ab.first, proof.com_ab.second,
                                                   // in the end must be equal to Z = A^r * B
                                                   proof.ip_ab,
                                                   // COM(v,C)
                                                   proof.com_c.first, proof.com_c.second,
                                                   // in the end must be equal to Z = C^r
                                                   proof.agg_c};

                    // we first multiply each entry of the Z U and L vectors by the respective
                    // challenges independently
                    // Since at the end we want to multiple all "t" values together, we do
                    // multiply all of them in parrallel and then merge then back at the end.
                    // same for u and z.
                    gipa_tuz<CurveType> res;
                    std::for_each(
                        boost::make_zip_iterator(
                            boost::make_tuple(proof.tmipp.gipa.comms_ab.begin(), proof.tmipp.gipa.z_ab.begin(),
                                              proof.tmipp.gipa.comms_c.begin(), proof.tmipp.gipa.z_c.begin(),
                                              challenges.begin(), challenges_inv.begin())),
                        boost::make_zip_iterator(
                            boost::make_tuple(proof.tmipp.gipa.comms_ab.end(), proof.tmipp.gipa.z_ab.end(),
                                              proof.tmipp.gipa.comms_c.end(), proof.tmipp.gipa.z_c.end(),
                                              challenges.end(), challenges_inv.end())),
                        [&](const boost::tuple<const std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>,
                                                               r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>> &,
                                               const std::pair<typename CurveType::gt_type::value_type,
                                                               typename CurveType::gt_type::value_type> &,
                                               const std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>,
                                                               r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>> &,
                                               const std::pair<typename CurveType::g1_type::value_type,
                                                               typename CurveType::g1_type::value_type> &,
                                               const typename CurveType::scalar_field_type::value_type &,
                                               const typename CurveType::scalar_field_type::value_type &> &t) {
                            // Op::TAB::<E>(tab_l, c_repr),
                            res.tab = res.tab * t.template get<0>().first.first.pow(t.template get<4>().data);
                            // Op::TAB(tab_r, c_inv_repr),
                            res.tab = res.tab * t.template get<0>().second.first.pow(t.template get<5>().data);
                            // Op::UAB(uab_l, c_repr),
                            res.uab = res.uab * t.template get<0>().first.second.pow(t.template get<4>().data);
                            // Op::UAB(uab_r, c_inv_repr),
                            res.uab = res.uab * t.template get<0>().second.second.pow(t.template get<5>().data);
                            // Op::ZAB(zab_l, c_repr),
                            res.zab = res.zab * t.template get<1>().first.pow(t.template get<4>().data);
                            // Op::ZAB(zab_r, c_inv_repr),
                            res.zab = res.zab * t.template get<1>().second.pow(t.template get<5>().data);
                            // Op::TC::<E>(tc_l, c_repr),
                            res.tc = res.tc * t.template get<2>().first.first.pow(t.template get<4>().data);
                            // Op::TC(tc_r, c_inv_repr),
                            res.tc = res.tc * t.template get<2>().second.first.pow(t.template get<5>().data);
                            // Op::UC(uc_l, c_repr),
                            res.uc = res.uc * t.template get<2>().first.second.pow(t.template get<4>().data);
                            // Op::UC(uc_r, c_inv_repr),
                            res.uc = res.uc * t.template get<2>().second.second.pow(t.template get<5>().data);
                            // Op::ZC(zc_l, c_repr),
                            res.zc = res.zc + (t.template get<4>() * t.template get<3>().first);
                            // Op::ZC(zc_r, c_inv_repr),
                            res.zc = res.zc + (t.template get<5>() * t.template get<3>().second);
                        });

                    // we reverse the order because the polynomial evaluation routine expects
                    // the challenges in reverse order.Doing it here allows us to compute the final_r
                    // in log time. Challenges are used as well in the KZG verification checks.
                    std::reverse(challenges.begin(), challenges.end());
                    std::reverse(challenges_inv.begin(), challenges_inv.end());

                    final_res.merge(res);
                    typename CurveType::scalar_field_type::value_type final_r =
                        polynomial_evaluation_product_form_from_transcript<typename CurveType::scalar_field_type>(
                            challenges_inv.begin(), challenges_inv.end(), r_shift,
                            CurveType::scalar_field_type::value_type::one());

                    return std::make_tuple(final_res, final_r, challenges, challenges_inv);
                }

                /// verify_tipp_mipp returns a pairing equation to check the tipp proof.  $r$ is
                /// the randomness used to produce a random linear combination of A and B and
                /// used in the MIPP part with C
                template<typename CurveType, typename DistributionType, typename GeneratorType,
                         typename Hash = hashes::sha2<256>>
                inline void verify_tipp_mipp(transcript<CurveType, Hash> &tr,
                                             const r1cs_gg_ppzksnark_aggregate_verification_srs<CurveType> &v_srs,
                                             const r1cs_gg_ppzksnark_aggregate_proof<CurveType> &proof,
                                             const typename CurveType::scalar_field_type::value_type &r_shift,
                                             pairing_check<CurveType, DistributionType, GeneratorType> &pc) {
                    // (T,U), Z for TIPP and MIPP  and all challenges
                    auto [final_res, final_r, challenges, challenges_inv] =
                        gipa_verify_tipp_mipp<CurveType, Hash>(tr, proof, r_shift);

                    // Verify commitment keys wellformed
                    // KZG challenge point
                    constexpr std::array<std::uint8_t, 8> domain_separator {'r', 'a', 'n', 'd', 'o', 'm', '-', 'z'};
                    tr.write_domain_separator(domain_separator.begin(), domain_separator.end());
                    tr.template write<typename CurveType::scalar_field_type>(challenges.front());
                    tr.template write<typename CurveType::g2_type>(proof.tmipp.gipa.final_vkey.first);
                    tr.template write<typename CurveType::g2_type>(proof.tmipp.gipa.final_vkey.second);
                    tr.template write<typename CurveType::g1_type>(proof.tmipp.gipa.final_wkey.first);
                    tr.template write<typename CurveType::g1_type>(proof.tmipp.gipa.final_wkey.second);
                    typename CurveType::scalar_field_type::value_type c = tr.read_challenge();

                    // TODO: parallel
                    // check the opening proof for v
                    verify_kzg_v<CurveType, DistributionType, GeneratorType>(
                        v_srs, proof.tmipp.gipa.final_vkey, proof.tmipp.vkey_opening, challenges_inv.begin(),
                        challenges_inv.end(), c, pc);
                    // check the opening proof for w - note that w has been rescaled by $r^{-1}$
                    verify_kzg_w<CurveType, DistributionType, GeneratorType>(
                        v_srs, proof.tmipp.gipa.final_wkey, proof.tmipp.wkey_opening, challenges.begin(),
                        challenges.end(), r_shift.inversed(), c, pc);
                    //
                    // We create a sequence of pairing tuple that we aggregate together at
                    // the end to perform only once the final exponentiation.
                    //
                    // TIPP
                    // z = e(A,B)
                    std::vector<typename CurveType::g1_type::value_type> a_input1 {
                        proof.tmipp.gipa.final_a,
                    };
                    std::vector<typename CurveType::g2_type::value_type> b_input1 {
                        proof.tmipp.gipa.final_b,
                    };
                    pc.merge_random(a_input1.begin(), a_input1.end(), b_input1.begin(), b_input1.end(), final_res.zab);

                    //  final_aB.0 = T = e(A,v1)e(w1,B)
                    a_input1.template emplace_back(proof.tmipp.gipa.final_wkey.first);
                    b_input1.template emplace(b_input1.begin(), proof.tmipp.gipa.final_vkey.first);
                    pc.merge_random(a_input1.begin(), a_input1.end(), b_input1.begin(), b_input1.end(), final_res.tab);

                    //  final_aB.1 = U = e(A,v2)e(w2,B)
                    a_input1.pop_back();
                    a_input1.template emplace_back(proof.tmipp.gipa.final_wkey.second);
                    b_input1.erase(b_input1.begin());
                    b_input1.template emplace(b_input1.begin(), proof.tmipp.gipa.final_vkey.second);
                    pc.merge_random(a_input1.begin(), a_input1.end(), b_input1.begin(), b_input1.end(), final_res.uab);

                    // MIPP
                    // Verify base inner product commitment
                    // Z ==  c ^ r
                    typename CurveType::g1_type::value_type final_z = final_r * proof.tmipp.gipa.final_c;

                    // Check commiment correctness
                    // T = e(C,v1)
                    std::vector<typename CurveType::g1_type::value_type> a_input2 {
                        proof.tmipp.gipa.final_c,
                    };
                    std::vector<typename CurveType::g2_type::value_type> b_input2 {
                        proof.tmipp.gipa.final_vkey.first,
                    };
                    pc.merge_random(a_input2.begin(), a_input2.end(), b_input2.begin(), b_input2.end(), final_res.tc);

                    // U = e(A,v2)
                    b_input2.pop_back();
                    b_input2.template emplace_back(proof.tmipp.gipa.final_vkey.second);
                    pc.merge_random(a_input2.begin(), a_input2.end(), b_input2.begin(), b_input2.end(), final_res.uc);

                    if (final_z != final_res.zc) {
                        pc.invalidate();
                    }
                }

                /// Verifies the aggregated proofs thanks to the Groth16 verifying key, the
                /// verifier SRS from the aggregation scheme, all the public inputs of the
                /// proofs and the aggregated proof.
                /// WARNING: transcript_include represents everything that should be included in
                /// the transcript from outside the boundary of this function. This is especially
                /// relevant for ALL public inputs of ALL individual proofs. In the regular case,
                /// one should input ALL public inputs from ALL proofs aggregated. However, IF ALL the
                /// public inputs are **fixed, and public before the aggregation time**, then there is
                /// no need to hash those. The reason we specify this extra assumption is because hashing
                /// the public inputs from the decoded form can take quite some time depending on the
                /// number of proofs and public inputs (+100ms in our case). In the case of Filecoin, the only
                /// non-fixed part of the public inputs are the challenges derived from a seed. Even though this
                /// seed comes from a random beeacon, we are hashing this as a safety precaution.
                template<typename CurveType,
                         typename DistributionType = boost::random::uniform_int_distribution<
                             typename CurveType::scalar_field_type::modulus_type>,
                         typename GeneratorType = boost::random::mt19937, typename Hash = hashes::sha2<256>,
                         typename InputRangesRange, typename InputIterator>
                inline typename std::enable_if<
                    std::is_same<typename CurveType::scalar_field_type::value_type,
                                 typename std::iterator_traits<typename std::iterator_traits<
                                     typename InputRangesRange::iterator>::value_type::iterator>::value_type>::value &&
                        std::is_same<std::uint8_t, typename std::iterator_traits<InputIterator>::value_type>::value,
                    bool>::type
                    verify_aggregate_proof(
                        const r1cs_gg_ppzksnark_aggregate_verification_srs<CurveType> &ip_verifier_srs,
                        const r1cs_gg_ppzksnark_aggregate_verification_key<CurveType> &pvk,
                        const InputRangesRange &public_inputs,
                        const r1cs_gg_ppzksnark_aggregate_proof<CurveType> &proof,
                        InputIterator transcript_include_first,
                        InputIterator transcript_include_last) {
                    for (const auto &public_input : public_inputs) {
                        BOOST_ASSERT((public_input.size()) == pvk.gamma_ABC_g1.size());
                    }

                    // Random linear combination of proofs
                    constexpr std::array<std::uint8_t, 9> application_tag = {'s', 'n', 'a', 'r', 'k',
                                                                             'p', 'a', 'c', 'k'};
                    constexpr std::array<std::uint8_t, 8> domain_separator {'r', 'a', 'n', 'd', 'o', 'm', '-', 'r'};
                    transcript<CurveType, Hash> tr(application_tag.begin(), application_tag.end());
                    tr.write_domain_separator(domain_separator.begin(), domain_separator.end());
                    tr.template write<typename CurveType::gt_type>(proof.com_ab.first);
                    tr.template write<typename CurveType::gt_type>(proof.com_ab.second);
                    tr.template write<typename CurveType::gt_type>(proof.com_c.first);
                    tr.template write<typename CurveType::gt_type>(proof.com_c.second);
                    tr.write(transcript_include_first, transcript_include_last);
                    typename CurveType::scalar_field_type::value_type r = tr.read_challenge();
                    tr.template write<typename CurveType::gt_type>(proof.ip_ab);
                    tr.template write<typename CurveType::g1_type>(proof.agg_c);

                    pairing_check<CurveType, DistributionType, GeneratorType> pc;

                    // TODO: parallel
                    // 1.Check TIPA proof ab
                    // 2.Check TIPA proof c
                    verify_tipp_mipp<CurveType, DistributionType, GeneratorType, Hash>(
                        tr,
                        ip_verifier_srs,
                        proof,
                        // we give the extra r as it's not part of the proof itself - it is simply used on top for the
                        // groth16 aggregation
                        r,
                        pc);

                    // Check aggregate pairing product equation
                    // SUM of a geometric progression
                    // SUM a^i = (1 - a^n) / (1 - a) = -(1-a^n)/-(1-a)
                    // = (a^n - 1) / (a - 1)
                    typename CurveType::scalar_field_type::value_type r_sum =
                        (r.pow(public_inputs.size()) - CurveType::scalar_field_type::value_type::one()) *
                        (r - CurveType::scalar_field_type::value_type::one()).inversed();

                    // The following parts 3 4 5 are independently computing the parts of the Groth16
                    // verification equation
                    // NOTE From this point on, we are only checking *one* pairing check (the Groth16
                    // verification equation) so we don't need to randomize as all other checks are being
                    // randomized already. When merging all pairing checks together, this will be the only one
                    // non-randomized.
                    //
                    // now we do the multi exponentiation
                    std::vector<typename CurveType::scalar_field_type::value_type> powers =
                        structured_scalar_power<typename CurveType::scalar_field_type>(public_inputs.size(), r);
                    std::vector<typename CurveType::scalar_field_type::value_type> multi_r_vec;
                    // i denotes the column of the public input, and j denotes which public input
                    for (std::size_t i = 0; i < public_inputs[0].size(); ++i) {
                        typename CurveType::scalar_field_type::value_type c = public_inputs[0][i];
                        for (std::size_t j = 1; j < public_inputs.size(); ++j) {
                            c = c + public_inputs[j][i] * powers[j];
                        }
                        multi_r_vec.emplace_back(c);
                    }

                    // 3. Compute left part of the final pairing equation
                    typename CurveType::gt_type::value_type left =
                        algebra::pair<CurveType>(pvk.alpha_g1 * r_sum, pvk.beta_g2);

                    // 4. Compute right part of the final pairing equation
                    typename CurveType::gt_type::value_type right = algebra::pair<CurveType>(proof.agg_c, pvk.delta_g2);

                    // 5. compute the middle part of the final pairing equation, the one
                    //    with the public inputs
                    // We want to compute MUL(i:0 -> l) S_i ^ (SUM(j:0 -> n) ai,j * r^j)
                    // this table keeps tracks of incremental computation of each i-th
                    // exponent to later multiply with S_i
                    // The index of the table is i, which is an index of the public
                    // input element
                    // We incrementally build the r vector and the table
                    // NOTE: in this version it's not r^2j but simply r^j
                    typename CurveType::g1_type::value_type g_ic = pvk.gamma_ABC_g1.first * r_sum;
                    // TODO: do without using of accumulation_vector
                    typename CurveType::g1_type::value_type totsi =
                        pvk.gamma_ABC_g1.accumulate_chunk(multi_r_vec.begin(), multi_r_vec.end(), 0).first -
                        pvk.gamma_ABC_g1.first;
                    g_ic = g_ic + totsi;
                    typename CurveType::gt_type::value_type middle = algebra::pair<CurveType>(g_ic, pvk.gamma_g2);

                    std::vector<typename CurveType::gt_type::value_type> a_input {left, middle, right};
                    pc.merge_nonrandom(a_input.begin(), a_input.end(), proof.ip_ab);
                    return pc.verify();
                }

                template<typename CurveType, typename BasicVerifier>
                class r1cs_gg_ppzksnark_aggregate_verifier {
                    typedef detail::r1cs_gg_ppzksnark_basic_policy<CurveType, ProvingMode::Aggregate> policy_type;

                    typedef typename CurveType::pairing pairing_policy;
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::g1_type g1_type;
                    typedef typename CurveType::gt_type gt_type;
                    typedef typename pairing_policy::g1_precomp g1_precomp;
                    typedef typename pairing_policy::g2_precomp g2_precomp;
                    typedef typename pairing_policy::fqk_type fqk_type;

                public:
                    typedef BasicVerifier basic_verifier;

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

                    // Aggregate verify
                    template<typename DistributionType, typename GeneratorType, typename Hash,
                             typename InputPrimaryInputRange, typename InputIterator>
                    static inline typename std::enable_if<
                        std::is_same<primary_input_type,
                                     typename std::iterator_traits<
                                         typename InputPrimaryInputRange::iterator>::value_type>::value,
                        bool>::type
                        process(const verification_srs_type &ip_verifier_srs,
                                const verification_key_type &pvk,
                                const InputPrimaryInputRange &public_inputs,
                                const aggregate_proof_type &proof,
                                InputIterator transcript_include_first,
                                InputIterator transcript_include_last) {
                        return verify_aggregate_proof<CurveType, DistributionType, GeneratorType, Hash>(
                            ip_verifier_srs, pvk, public_inputs, proof, transcript_include_first,
                            transcript_include_last);
                    }

                    // Basic verify
                    template<typename VerificationKey>
                    static inline bool process(const VerificationKey &vk,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        return BasicVerifier::process(vk, primary_input, proof);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
