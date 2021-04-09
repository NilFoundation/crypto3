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

#include <memory>
#include <vector>
#include <tuple>

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/proof.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/srs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /// Aggregate `n` zkSnark proofs, where `n` must be a power of two.
                template<typename CurveType, typename InputProofIterator>
                typename std::enable_if<std::is_same<typename std::iterator_traits<InputProofIterator>::value_type,
                                                     r1cs_gg_ppzksnark_aggregate_proof<CurveType>>::value,
                                        r1cs_gg_ppzksnark_aggregate_proof<CurveType>>::type
                    aggregate_proofs(const r1cs_gg_ppzksnark_srs_proving_key<CurveType> &srs, InputProofIterator first,
                                     InputProofIterator last) {
                    std::size_t size = std::distance(first, last);
                    BOOST_ASSERT((size & (size - 1)) == 0);
                    BOOST_ASSERT(srs.valid(size));

                    // We first commit to A B and C - these commitments are what the verifier
                    // will use later to verify the TIPP and MIPP proofs
                    par ! {let a = proofs.iter().map(| proof | proof.a).collect::<Vec<_>>(),
                           let b = proofs.iter().map(| proof | proof.b).collect::<Vec<_>>(),
                           let c = proofs.iter().map(| proof | proof.c).collect::<Vec<_>>()};

                    // A and B are committed together in this scheme
                    // we need to take the reference so the macro doesn't consume the value
                    // first
                    let refa = &a;
                    let refb = &b;
                    let refc = &c;
                    par ! {let com_ab = commit::pair::<E>(&srs.vkey, &srs.wkey, refa, refb),
                           let com_c = commit::single_g1::<E>(&srs.vkey, refc)};

                    // Random linear combination of proofs
                    let r = oracle !(&com_ab .0, &com_ab .1, &com_c .0, &com_c .1);
                    // r, r^2, r^3, r^4 ...
                    let r_vec = structured_scalar_power(proofs.len(), &r);
                    // r^-1, r^-2, r^-3
                    let r_inv = r_vec.par_iter().map(| ri | ri.inverse().unwrap()).collect::<Vec<_>>();

                    // B^{r}
                    let b_r = b.par_iter()
                                  .zip(r_vec.par_iter())
                                  .map(| (bi, ri) | mul !(bi.into_projective(), ri.into_repr()).into_affine())
                                  .collect::<Vec<_>>();
                    let refb_r = &b_r;
                    // w^{r^{-1}}
                    let wkey_r_inv = srs.wkey.scale(&r_inv);

                    // we prove tipp and mipp using the same recursive loop
                    let proof = prove_tipp_mipp::<E>(&srs, &a, &b_r, &c, &wkey_r_inv, &r_vec) ? ;
                    par ! {// compute A * B^r for the verifier
                           let ip_ab = inner_product::pairing::<E>(&refa, &refb_r),
                           // compute C^r for the verifier
                           let agg_c = inner_product::multiexponentiation::<E::G1Affine>(&refc, &r_vec)};

                    debug_assert !({
                        let computed_com_ab = commit::pair::<E>(&srs.vkey, &wkey_r_inv, &a, &b_r);
                        com_ab == computed_com_ab
                    });

                    Ok(AggregateProof {
                        com_ab,
                        com_c,
                        ip_ab,
                        agg_c,
                        tmipp : proof,
                    })
                }

                /// Proves a TIPP relation between A and B as well as a MIPP relation with C and
                /// r. Commitment keys must be of size of A, B and C. In the context of Groth16
                /// aggregation, we have that B = B^r and wkey is scaled by r^{-1}. The
                /// commitment key v is used to commit to A and C recursively in GIPA such that
                /// only one KZG proof is needed for v. In the original paper version, since the
                /// challenges of GIPA would be different, two KZG proofs would be needed.
                template<typename CurveType, typename InputG1Iterator, typename InputG2Iterator,
                         typename InputScalarIterator>
                tipp_mipp_proof<CurveType> prove_tipp_mipp(const r1cs_gg_ppzksnark_srs_proving_key<CurveType> &srs,
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
                               std::vector<typename CurveType::scalar_field_type::value_type>> =
                        gipa_tipp_mipp(afirst, alast, bfirst, blast, cfirst, clast, rfirst, rlast, srs.vkey, wkey);

                    // Prove final commitment keys are wellformed
                    // we reverse the transcript so the polynomial in kzg opening is constructed
                    // correctly - the formula indicates x_{l-j}. Also for deriving KZG
                    // challenge point, input must be the last challenge.
                    challenges.reverse();
                    challenges_inv.reverse();
                    typename std::iterator_traits<InputScalarIterator>::value_type r_inverse = r_shift.inverse();

                    // KZG challenge point
                    let z = oracle !(&challenges[0],
                                     &proof.final_vkey .0,
                                     &proof.final_vkey .1,
                                     &proof.final_wkey .0,
                                     &proof.final_wkey .1);

                    // Complete KZG proofs
                    par ! {let vkey_opening =
                               prove_commitment_key_kzg_opening(&srs.h_alpha_powers_table, &srs.h_beta_powers_table,
                                                                srs.n, &challenges_inv, &<E::Fr>::one(), &z, ),
                           let wkey_opening =
                               prove_commitment_key_kzg_opening(&srs.g_alpha_powers_table, &srs.g_beta_powers_table,
                                                                srs.n, &challenges, &r_inverse, &z, )};

    Ok(TippMippProof {
        gipa: proof,
        vkey_opening: vkey_opening?,
        wkey_opening: wkey_opening?,
    })
                }

                /*
                 * @brief gipa_tipp_mipp peforms the recursion of the GIPA protocol for TIPP and MIPP.
                 * It returns a proof containing all intermdiate committed values, as well as
                 * the challenges generated necessary to do the polynomial commitment proof
                 * later in TIPP.
                 * @param wkey scaled key w^r^-1
                 */
                template<typename CurveType, typename InputG1Iterator, typename InputG2Iterator,
                         typename InputScalarIterator>
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
                    let mut comms_ab = Vec::new ();
                    let mut comms_c = Vec::new ();
                    let mut z_ab = Vec::new ();
                    let mut z_c = Vec::new ();
                    let mut challenges : Vec<E::Fr> = Vec::new ();
                    let mut challenges_inv : Vec<E::Fr> = Vec::new ();

                    while (m_a.size() > 1) {
                        // recursive step
                        // Recurse with problem of half size
                        std::size_t split = m_a.size() / 2;

                        // TIPP ///
                        let(a_left, a_right) = m_a.split_at_mut(split);
                        let(b_left, b_right) = m_b.split_at_mut(split);
                        // MIPP ///
                        // c[:n']   c[n':]
                        let(c_left, c_right) = m_c.split_at_mut(split);
                        // r[:n']   r[:n']
                        let(r_left, r_right) = m_r.split_at_mut(split);

                        let(vk_left, vk_right) = vkey.split(split);
                        let(wk_left, wk_right) = wkey.split(split);

                        // since we do this in parallel we take reference first so it can be
                        // moved within the macro's rayon scope.
                        let(rvk_left, rvk_right) = (&vk_left, &vk_right);
                        let(rwk_left, rwk_right) = (&wk_left, &wk_right);
                        let(ra_left, ra_right) = (&a_left, &a_right);
                        let(rb_left, rb_right) = (&b_left, &b_right);
                        let(rc_left, rc_right) = (&c_left, &c_right);
                        let(rr_left, rr_right) = (&r_left, &r_right);
                        // See section 3.3 for paper version with equivalent names
                        par ! {// TIPP part
                               let tab_l = commit::pair::<E>(&rvk_left, &rwk_right, &ra_right, &rb_left),
                               let tab_r = commit::pair::<E>(&rvk_right, &rwk_left, &ra_left, &rb_right),
                               let zab_l = inner_product::pairing::<E>(&ra_right, &rb_left),
                               let zab_r = inner_product::pairing::<E>(&ra_left, &rb_right),

                               // MIPP part
                               // z_l = c[n':] ^ r[:n']
                               let zc_l = inner_product::multiexponentiation::<E::G1Affine>(rc_right, rr_left),
                               // Z_r = c[:n'] ^ r[n':]
                               let zc_r = inner_product::multiexponentiation::<E::G1Affine>(rc_left, rr_right),
                               // u_l = c[n':] * v[:n']
                               let tuc_l = commit::single_g1::<E>(&rvk_left, rc_right),
                               // u_r = c[:n'] * v[n':]
                               let tuc_r = commit::single_g1::<E>(&rvk_right, rc_left)};

                        // Fiat-Shamir challenge
                        let default_transcript = E::Fr::zero();
                        let transcript = challenges.last().unwrap_or(&default_transcript);

                        // combine both TIPP and MIPP transcript
                        let c_inv = oracle !(&transcript,
                                             &tab_l .0,
                                             &tab_l .1,
                                             &tab_r .0,
                                             &tab_r .1,
                                             &zab_l,
                                             &zab_r,
                                             &zc_l,
                                             &zc_r,
                                             &tuc_l .0,
                                             &tuc_l .1,
                                             &tuc_r .0,
                                             &tuc_r .1);
                        // Optimization for multiexponentiation to rescale G2 elements with
                        // 128-bit challenge Swap 'c' and 'c_inv' since can't control bit size
                        // of c_inv
                        let c = c_inv.inverse().unwrap();

                        // Set up values for next step of recursion
                        // A[:n'] + A[n':] ^ x
                        compress(&mut m_a, split, &c);
                        // B[:n'] + B[n':] ^ x^-1
                        compress(&mut m_b, split, &c_inv);

                        // c[:n'] + c[n':]^x
                        compress(&mut m_c, split, &c);
                        r_left.par_iter_mut().zip(r_right.par_iter_mut()).for_each(| (r_l, r_r) | {
                            // r[:n'] + r[n':]^x^-1
                            r_r.mul_assign(&c_inv);
                            r_l.add_assign(r_r);
                        });
                        let len = r_left.len();
                        m_r.resize(len, E::Fr::zero());    // shrink to new size

                        // v_left + v_right^x^-1
                        vkey = vk_left.compress(&vk_right, &c_inv);
                        // w_left + w_right^x
                        wkey = wk_left.compress(&wk_right, &c);

                        comms_ab.push((tab_l, tab_r));
                        comms_c.push((tuc_l, tuc_r));
                        z_ab.push((zab_l, zab_r));
                        z_c.push((zc_l, zc_r));
                        challenges.push(c);
                        challenges_inv.push(c_inv);
                    }

                    BOOST_ASSERT(m_a.size() == 1 && m_b.size() == 1);
                    BOOST_ASSERT(m_c.size() == 1 && m_r.size() == 1);
                    BOOST_ASSERT(vkey.a.size() == 1 && vkey.b.size() == 1);
                    BOOST_ASSERT(wkey.a.size() == 1 && wkey.b.size() == 1);

                    let(final_a, final_b, final_c, final_r) = (m_a[0], m_b[0], m_c[0], m_r[0]);
                    let(final_vkey, final_wkey) = (vkey.first(), wkey.first());
                    (GipaProof {
                        nproofs : a.len() as u32,    // TODO: ensure u32
                        comms_ab,
                        comms_c,
                        z_ab,
                        z_c,
                        final_a,
                        final_b,
                        final_c,
                        final_r,
                        final_vkey,
                        final_wkey,
                    },
                     challenges, challenges_inv)
                }

                /// Returns the KZG opening proof for the given commitment key. Specifically, it
                /// returns $g^{f(alpha) - f(z) / (alpha - z)}$ for $a$ and $b$.
                template<typename CurveType>
                kzg_opening<CurveType> prove_commitment_key_kzg_opening(srs_powers_alpha_table
                                                                        : &dyn MultiscalarPrecomp<G>,
                                                                          srs_powers_beta_table
                                                                        : &dyn MultiscalarPrecomp<G>, srs_powers_len
                                                                        : usize, transcript
                                                                        : &[G::Scalar], r_shift
                                                                        : &G::Scalar, kzg_challenge
                                                                        : &G::Scalar) {
                    // f_v
                    let vkey_poly =
                        DensePolynomial::from_coeffs(polynomial_coefficients_from_transcript(transcript, r_shift));

                    if (srs_powers_len != vkey_poly.coeffs().size()) {
                        return Err(SynthesisError::MalformedSrs);
                    }

                    // f_v(z)
                    let vkey_poly_z =
                        polynomial_evaluation_product_form_from_transcript(&transcript, kzg_challenge, &r_shift);

                    let mut neg_kzg_challenge = *kzg_challenge;
                    neg_kzg_challenge.negate();

                    // f_v(X) - f_v(z) / (X - z)
                    let quotient_polynomial =
                        &(&vkey_poly - &DensePolynomial::from_coeffs(vec ![vkey_poly_z])) /
                        &(DensePolynomial::from_coeffs(vec ![ neg_kzg_challenge, G::Scalar::one() ]));

                    let quotient_polynomial_coeffs = quotient_polynomial.into_coeffs();

                    // multiexponentiation inner_product, inlined to optimize
                    let zero = G::Scalar::zero().into_repr();
                    let quotient_polynomial_coeffs_len = quotient_polynomial_coeffs.len();
                    let getter = | i : usize |-><G::Scalar as PrimeField>::Repr {
                        if i
                            >= quotient_polynomial_coeffs_len {
                                return zero;
                            }
                        quotient_polynomial_coeffs[i].into_repr()
                    };

                    // we do one proof over h^a and one proof over h^b (or g^a and g^b depending
                    // on the curve we are on). that's the extra cost of the commitment scheme
                    // used which is compatible with Groth16 CRS insteaf of the original paper
                    // of Bunz'19
                    Ok(rayon::join(
                        || {par_multiscalar::<_, G>(&ScalarList::Getter(getter, srs_powers_len), srs_powers_alpha_table,
                                                    std::mem::size_of:: << G::Scalar as PrimeField > ::Repr > () * 8, )
                                .into_affine()},
                        || {par_multiscalar::<_, G>(&ScalarList::Getter(getter, srs_powers_len), srs_powers_beta_table,
                                                    std::mem::size_of:: << G::Scalar as PrimeField > ::Repr > () * 8, )
                                .into_affine()}, ))
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
                        typename FieldType::value_type::one() + (*transcript_first * power_zr);
                    power_zr *= power_zr;
                    ++transcript_first;

                    // the rest
                    while (transcript_first != transcript_last) {
                        res *= typename FieldType::value_type::one() + (*transcript_first * power_zr);
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
                typename std::enable_if<std::is_same<typename std::iterator_traits<InputFieldIterator>::value_type,
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
                            corfficients.emplace_back(coefficients[j] * (*transcript_first * power_2_r));
                        }
                        power_2_r *= power_2_r;

                        ++transcript_first;
                    }

                    return coefficients;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
