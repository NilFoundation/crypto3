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

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/verification_key.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/proof.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/srs.hpp>

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

                    std::pair<typename curve_type::pairing::fqk_type, fr_type> tab;
                    std::pair<typename curve_type::pairing::fqk_type, fr_type> uab;
                    std::pair<typename curve_type::pairing::fqk_type, fr_type> zab;
                    std::pair<typename curve_type::pairing::fqk_type, fr_type> tc;
                    std::pair<typename curve_type::pairing::fqk_type, fr_type> uc;
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
                                             const std::pair<typename CurveType::pairing::fqk_type,
                                                             typename CurveType::pairing::fqk_type> &,
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
                                             const std::pair<typename CurveType::pairing::fqk_type,
                                                             typename CurveType::pairing::fqk_type> &,
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
    let res = comms_ab
        .par_iter()
        .zip(zs_ab.par_iter())
        .zip(comms_c.par_iter().zip(zs_c.par_iter()))
        .zip(challenges.par_iter().zip(challenges_inv.par_iter()))
        .flat_map(|(((comm_ab, z_ab), (comm_c, z_c)), (c, c_inv))| {
                        // T and U values for right and left for AB part
                        let((tab_l, uab_l), (tab_r, uab_r)) = comm_ab;
                        let(zab_l, zab_r) = z_ab;
                        // T and U values for right and left for C part
                        let((tc_l, uc_l), (tc_r, uc_r)) = comm_c;
                        let(zc_l, zc_r) = z_c;

                        let c_repr = c.into_repr();
                        let c_inv_repr = c_inv.into_repr();

                        // we multiple left side by x and right side by x^-1
                        vec ![
                            Op::TAB::<E>(tab_l, c_repr),
                            Op::TAB(tab_r, c_inv_repr),
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
        })
        .fold(GipaTUZ::<E>::default, |mut res, op: Op<E>| {
            match op {
                Op::TAB(tx, c) => {
                    let tx: E::Fqk = tx.pow(c);
                    res.tab.mul_assign(&tx);
                }
                Op::UAB(ux, c) = > {
                    let ux : E::Fqk = ux.pow(c);
                    res.uab.mul_assign(&ux);
                }
                Op::ZAB(zx, c) = > {
                    let zx : E::Fqk = zx.pow(c);
                    res.zab.mul_assign(&zx);
                }
                Op::TC(tx, c) = > {
                    let tx : E::Fqk = tx.pow(c);
                    res.tc.mul_assign(&tx);
                }
                Op::UC(ux, c) = > {
                    let ux : E::Fqk = ux.pow(c);
                    res.uc.mul_assign(&ux);
                }
                Op::ZC(zx, c) = > {
                    let mut zx = *zx;
                    zx.mul_assign(c);
                    res.zc.add_assign(&zx);
                }
            }    // namespace snark
            res
        }    // namespace zk
)
        .reduce(GipaTUZ::default, |mut acc_res, res| {
            acc_res.merge(&res);
            acc_res
        });

final_res.merge(&res);
debug !("TIPP verify: gipa prep and accumulate took {}ms", now.elapsed().as_millis());
(final_res, challenges, challenges_inv)
    }    // namespace crypto3

    /// verify_tipp_mipp returns a pairing equation to check the tipp proof.  $r$ is
    /// the randomness used to produce a random linear combination of A and B and
    /// used in the MIPP part with C
    template<typename CurveType>
    PairingCheck<CurveType> verify_tipp_mipp(const r1cs_gg_ppzksnark_srs_verification_key<CurveType> &v_srs,
                                             const r1cs_gg_ppzksnark_aggregate_proof<CurveType> &proof,
                                             const typename CurveType::scalar_field_type &r_shift) {
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
        // KZG challenge point
        let c = oracle !(&challenges.first().unwrap(), &fvkey .0, &fvkey .1, &fwkey .0, &fwkey .1);

        // we take reference so they are able to be copied in the par! macro
        let final_a = &proof.tmipp.gipa.final_a;
        let final_b = &proof.tmipp.gipa.final_b;
        let final_c = &proof.tmipp.gipa.final_c;
        let final_r = &proof.tmipp.gipa.final_r;
        let final_zab = &final_res.zab;
        let final_tab = &final_res.tab;
        let final_uab = &final_res.uab;
        let final_tc = &final_res.tc;
        let final_uc = &final_res.uc;

        let now = Instant::now();
        par ! {// check the opening proof for v
               let vtuple = verify_kzg_opening_g2(v_srs, &fvkey, &proof.tmipp.vkey_opening, &challenges_inv,
                                                  &E::Fr::one(), &c, ),
               // check the opening proof for w - note that w has been rescaled by $r^{-1}$
               let wtuple = verify_kzg_opening_g1(v_srs, &fwkey, &proof.tmipp.wkey_opening, &challenges,
                                                  &r_shift.inverse().unwrap(), &c, ),
               //
               // We create a sequence of pairing tuple that we aggregate together at
               // the end to perform only once the final exponentiation.
               //
               // TIPP
               // z = e(A,B)
               let check_z = PairingCheck::<E>::from_miller_inputs(&[(final_a, final_b)], final_zab),
               //  final_aB.0 = T = e(A,v1)e(w1,B)
               let check_ab0 =
                   PairingCheck::<E>::from_miller_inputs(&[ (final_a, &fvkey .0), (&fwkey .0, final_b) ], final_tab),

               //  final_aB.1 = U = e(A,v2)e(w2,B)
               let check_ab1 =
                   PairingCheck::<E>::from_miller_inputs(&[ (final_a, &fvkey .1), (&fwkey .1, final_b) ], final_uab),

               // MIPP
               // Verify base inner product commitment
               // Z ==  c ^ r
               let final_z = algebra::inner_product<E::G1Affine>(&[final_c.clone()], &[final_r.clone()]),
               // Check commiment correctness
               // T = e(C,v1)
               let check_t = PairingCheck::<E>::from_miller_inputs(&[(final_c, &fvkey .0)], final_tc),
               // U = e(A,v2)
               let check_u = PairingCheck::<E>::from_miller_inputs(&[(final_c, &fvkey .1)], final_uc)};

        debug !("TIPP verify: parallel checks before merge: {}ms", now.elapsed().as_millis(), );

        let b = final_z == final_res.zc;
        // only check that doesn't require pairing so we can give a tuple that will
        // render the equation wrong in case it's false
        if (!b) {
            return PairingCheck::new_invalid();
        }

        let mut acc = vtuple;
        acc.merge(&check_z);
        acc.merge(&check_ab0);
        acc.merge(&check_ab1);
        acc.merge(&check_t);
        acc.merge(&check_u);
        acc.merge(&wtuple);

        acc
    }

    template<typename CurveType, typename InputPublicInputsIterator>
    bool verify_aggregate_proof(const r1cs_gg_ppzksnark_srs_verification_key<CurveType> &ip_verifier_srs,
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
        auto tipa_ab = verify_tipp_mipp<CurveType>(ip_verifier_srs,
                                                   proof,
                                                   r    // we give the extra r as it's not part of the proof itself
                                                        // - it is simply used on top for the groth16 aggregation
        );

        // Check aggregate pairing product equation
        // SUM of a geometric progression
        // SUM a^i = (1 - a^n) / (1 - a) = -(1-a^n)/-(1-a)
        // = (a^n - 1) / (a - 1)
        info !("checking aggregate pairing");
        let mut r_sum = r.pow(&[public_inputs.len() as u64]);
        r_sum.sub_assign(&E::Fr::one());
        let b = sub !(r, &E::Fr::one()).inverse().unwrap();
        r_sum.mul_assign(&b);

        // 3. Compute left part of the final pairing equation
        //
        // NOTE From this point on, we are only checking *one* pairing check so
        // we don't need to randomize as all other checks are being randomized
        // already so this is the "base check" so to speak.
        let p1 = send_tuple.clone();
        s.spawn(move | _ | {
            let mut alpha_g1_r_sum = pvk.alpha_g1;
            alpha_g1_r_sum.mul_assign(r_sum);
            let tuple = PairingCheck::<E>::from_miller_one(
                E::miller_loop(&[(&alpha_g1_r_sum.into_affine().prepare(), &pvk.beta_g2, )]));

            p1.send(tuple).unwrap();
        });

        // 4. Compute right part of the final pairing equation
        let p3 = send_tuple.clone();
        s.spawn(move | _ | {
            let tuple = PairingCheck::from_miller_one(E::miller_loop(&[(
                // e(c^r vector form, h^delta)
                // let agg_c = algebra::inner_product<E::G1Affine>(&c, r_vec)
                &proof.agg_c.into_affine().prepare(), &pvk.delta_g2, )]));
            p3.send(tuple).unwrap();
        });

        let(r_vec_sender, r_vec_receiver) = bounded(1);
        s.spawn(move | _ | {
            let now = Instant::now();
            r_vec_sender.send(structured_scalar_power(public_inputs.len(), &r)).unwrap();
            let elapsed = now.elapsed().as_millis();
            debug !("generation of r vector: {}ms", elapsed);
        });

        // 5. compute the middle part of the final pairing equation, the one
        //    with the public inputs
        // let p2 = send_tuple.clone();
        s.spawn(move | _ | {
            // We want to compute MUL(i:0 -> l) S_i ^ (SUM(j:0 -> n) ai,j * r^j)
            // this table keeps tracks of incremental computation of each i-th
            // exponent to later multiply with S_i
            // The index of the table is i, which is an index of the public
            // input element
            // We incrementally build the r vector and the table
            // NOTE: in this version it's not r^2j but simply r^j

            let l = public_inputs[0].len();
            let mut g_ic = pvk.ic_projective[0];
            g_ic.mul_assign(r_sum);

            let powers = r_vec_receiver.recv().unwrap();

            let now = Instant::now();
            // now we do the multi exponentiation
            let getter = | i : usize |-><E::Fr as PrimeField>::Repr {
                // i denotes the column of the public input, and j denotes which public input
                let mut c = public_inputs[0][i];
                for (int j = 1; j < public_inputs.size(); j++) {
                    let mut ai = public_inputs[j][i];
                    ai.mul_assign(&powers[j]);
                    c.add_assign(&ai);
                }
                c.into_repr()
            };

            let totsi =
                par_multiscalar::<_, E::G1Affine>(&ScalarList::Getter(getter, l), &pvk.multiscalar.at_point(1),
                                                  std::mem::size_of:: << E::Fr as PrimeField > ::Repr > () * 8, );

            g_ic.add_assign(&totsi);

            let tuple =
                PairingCheck::from_miller_one(E::miller_loop(&[(&g_ic.into_affine().prepare(), &pvk.gamma_g2, )]));
            let elapsed = now.elapsed().as_millis();
            debug !("table generation: {}ms", elapsed);

            send_tuple.send(tuple).unwrap();
        });

        s.spawn(move | _ | {
            // final value ip_ab is what we want to compare in the groth16
            // aggregated equation A * B
            let mut acc = PairingCheck::from_pair(E::Fqk::one(), proof.ip_ab.clone());
            while
                let Ok(tuple) = rcv_tuple.recv() {
                    acc.merge(&tuple);
                }
            valid_send.send(acc.verify()).unwrap();
        });

        let res = valid_rcv.recv().unwrap();
        info !("aggregate verify done");

        Ok(res)
    }

    /// verify_kzg_opening_g2 takes a KZG opening, the final commitment key, SRS and
    /// any shift (in TIPP we shift the v commitment by r^-1) and returns a pairing
    /// tuple to check if the opening is correct or not.
    template<typename CurveType>
    PairingCheck<CurveType> verify_kzg_opening_g2(v_srs
                                                  : &VerifierSRS<E>, final_vkey
                                                  : &(E::G2Affine, E::G2Affine), vkey_opening
                                                  : &KZGOpening<E::G2Affine>, challenges
                                                  : &[E::Fr], r_shift
                                                  : &E::Fr, kzg_challenge
                                                  : &E::Fr) {
        // f_v(z)
        let vpoly_eval_z = polynomial_evaluation_product_form_from_transcript(challenges, kzg_challenge, r_shift);
        // -g such that when we test a pairing equation we only need to check if
        // it's equal 1 at the end:
        // e(a,b) = e(c,d) <=> e(a,b)e(-c,d) = 1
        let mut ng = v_srs.g.clone();
        ng.negate();
        par ! {
            // verify first part of opening - v1
            // e(g, v1 h^{-af_v(z)})
            let p1 = E::miller_loop(&[(&ng.into_affine().prepare(),
                                       // in additive notation: final_vkey = uH,
                                       // uH - f_v(z)H = (u - f_v)H --> v1h^{-af_v(z)}
                                       &sub !(final_vkey .0.into_projective(), &mul !(v_srs.h_alpha, vpoly_eval_z))
                                            .into_affine()
                                            .prepare(), )]),
            // e(g^{a - z}, opening_1) ==> (aG) - (zG)
            let p2 =
                E::miller_loop(&[(&sub !(v_srs.g_alpha, &mul !(v_srs.g, kzg_challenge.clone())).into_affine().prepare(),
                                  &vkey_opening .0.prepare(), )]),

            // verify second part of opening - v2 - similar but changing secret exponent
            // e(g, v2 h^{-bf_v(z)})
            let q1 = E::miller_loop(&[(&ng.into_affine().prepare(),
                                       // in additive notation: final_vkey = uH,
                                       // uH - f_v(z)H = (u - f_v)H --> v1h^{-f_v(z)}
                                       &sub !(final_vkey .1.into_projective(), &mul !(v_srs.h_beta, vpoly_eval_z))
                                            .into_affine()
                                            .prepare(), )]),
            // e(g^{b - z}, opening_1)
            let q2 =
                E::miller_loop(&[(&sub !(v_srs.g_beta, &mul !(v_srs.g, kzg_challenge.clone())).into_affine().prepare(),
                                  &vkey_opening .1.prepare(), )])};

        // this pair should be one when multiplied
        let(l, r) = rayon::join(|| mul !(q1, &q2), || mul !(p1, &p2));
        PairingCheck::from_miller_one(mul !(l, &r))
    }

    /// Similar to verify_kzg_opening_g2 but for g1.
    template<typename CurveType>
    PairingCheck<CurveType> verify_kzg_opening_g1(v_srs
                                                  : &VerifierSRS<E>, final_wkey
                                                  : &(E::G1Affine, E::G1Affine), wkey_opening
                                                  : &KZGOpening<E::G1Affine>, challenges
                                                  : &[E::Fr], r_shift
                                                  : &E::Fr, kzg_challenge
                                                  : &E::Fr) {
        let wkey_poly_eval = polynomial_evaluation_product_form_from_transcript(challenges, kzg_challenge, r_shift);

        // -h such that when we test a pairing equation we only need to check if
        // it's equal 1 at the end:
        // e(a,b) = e(c,d) <=> e(a,b)e(c,-d) = 1
        let mut nh = v_srs.h.clone();
        nh.negate();

        par ! {
            // first check on w1
            // let K = g^{a^{n+1}}
            // e(w1 K^{-f_w(z)},h)
            let p1 = E::miller_loop(&[(&sub !(final_wkey .0.into_projective(), &mul !(v_srs.g_alpha_n1, wkey_poly_eval))
                                            .into_affine()
                                            .prepare(),
                                       &nh.into_affine().prepare(), )]),
            // e(opening, h^{a - z})
            let p2 =
                E::miller_loop(&[(&wkey_opening .0.prepare(),
                                  &sub !(v_srs.h_alpha, &mul !(v_srs.h, *kzg_challenge)).into_affine().prepare(), )]),
            // then do second check
            // let K = g^{b^{n+1}}
            // e(w2 K^{-f_w(z)},h)
            let q1 = E::miller_loop(&[(&sub !(final_wkey .1.into_projective(), &mul !(v_srs.g_beta_n1, wkey_poly_eval))
                                            .into_affine()
                                            .prepare(),
                                       &nh.into_affine().prepare(), )]),
            // e(opening, h^{b - z})
            let q2 =
                E::miller_loop(&[(&wkey_opening .1.prepare(),
                                  &sub !(v_srs.h_beta, &mul !(v_srs.h, *kzg_challenge)).into_affine().prepare(), )])};
        let(l, r) = rayon::join(|| mul !(q1, &q2), || mul !(p1, &p2));
        PairingCheck::from_miller_one(mul !(l, &r))
    }

}    // namespace nil
}    // namespace zk
}    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
