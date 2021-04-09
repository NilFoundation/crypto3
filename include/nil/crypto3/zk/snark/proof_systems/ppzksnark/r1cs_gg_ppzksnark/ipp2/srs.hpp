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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_SRS_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_SRS_HPP

#include <memory>
#include <vector>
#include <tuple>

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /// ProverSRS is the specialized SRS version for the prover for a specific number of proofs to
                /// aggregate. It contains as well the commitment keys for this specific size.
                /// Note the size must be a power of two for the moment - if it is not, padding must be
                /// applied.
                template<typename CurveType>
                struct r1cs_gg_pp_zksnark_prover_srs {
                    typedef CurveType curve_type;
                    typedef r1cs_gg_ppzksnark_ipp2_commitment<CurveType> commitment_type;
                    typedef typename commitment_type::vkey_type vkey_type;
                    typedef typename commitment_type::wkey_type wkey_type;

                    /// number of proofs to aggregate
                    std::size_t n;
                    /// $\{g^a^i\}_{i=n+1}^{2n}$ where n is the number of proofs to be aggregated table starts
                    /// at i=n+1 since base is offset with commitment keys. Specially, during the KZG opening
                    /// proof, we need the vector of the SRS for g to start at $g^{a^{n+1}}$ because the
                    /// commitment key $w$ starts at the same power.
                    MultiscalarPrecompOwned<typename CurveType::g1_type::value_type> g_alpha_powers_table;
                    /// $\{h^a^i\}_{i=1}^{n}$
                    MultiscalarPrecompOwned<typename CurveType::g2_type::value_type> h_alpha_powers_table;
                    /// $\{g^b^i\}_{i=n+1}^{2n}$
                    MultiscalarPrecompOwned<typename CurveType::g1_type::value_type> g_beta_powers_table;
                    /// $\{h^b^i\}_{i=1}^{n}$
                    MultiscalarPrecompOwned<typename CurveType::g2_type::value_type> h_beta_powers_table;
                    /// commitment key using in MIPP and TIPP
                    vkey_type vkey;
                    /// commitment key using in TIPP
                    wkey_type wkey;
                };

                /// Contains the necessary elements to verify an aggregated Groth16 proof; it is of fixed size
                /// regardless of the number of proofs aggregated. However, a verifier SRS will be determined by
                /// the number of proofs being aggregated.
                template<typename CurveType>
                struct r1cs_gg_pp_zksnark_verifier_srs {
                    typedef CurveType curve_type;
                    std::size_t n;
                    typename CurveType::g1_type::value_type g;
                    typename CurveType::g2_type::value_type h;
                    typename CurveType::g1_type::value_type g_alpha;
                    typename CurveType::g1_type::value_type g_beta;
                    typename CurveType::g2_type::value_type h_alpha;
                    typename CurveType::g2_type::value_type h_beta;
                    /// equals to $g^{alpha^{n+1}}$
                    typename CurveType::g1_type::value_type g_alpha_n1;
                    /// equals to $g^{beta^{n+1}}$
                    typename CurveType::g1_type::value_type g_beta_n1;
                };

                /// It contains the maximum number of raw elements of the SRS needed to aggregate and verify
                /// Groth16 proofs. One can derive specialized prover and verifier key for _specific_ size of
                /// aggregations by calling `srs.specialize(n)`. The specialized prover key also contains
                /// precomputed tables that drastically increase prover's performance.
                /// This GenericSRS is usually formed from the transcript of two distinct power of taus ceremony
                /// ,in other words from two distinct Groth16 CRS.
                /// See [there](https://github.com/nikkolasg/taupipp) a way on how to generate this GenesisSRS.
                template<typename CurveType>
                struct r1cs_gg_pp_zksnark_srs {
                    typedef CurveType curve_type;

                    /// $\{g^a^i\}_{i=0}^{N}$ where N is the smallest size of the two Groth16 CRS.
                    std::vector<typename CurveType::g1_type::value_type> g_alpha_powers;
                    /// $\{h^a^i\}_{i=0}^{N}$ where N is the smallest size of the two Groth16 CRS.
                    std::vector<typename CurveType::g2_type::value_type> h_alpha_powers;
                    /// $\{g^b^i\}_{i=n}^{N}$ where N is the smallest size of the two Groth16 CRS.
                    std::vector<typename CurveType::g1_type::value_type> g_beta_powers;
                    /// $\{h^b^i\}_{i=0}^{N}$ where N is the smallest size of the two Groth16 CRS.
                    std::vector<typename CurveType::g2_type::value_type> h_beta_powers;
                };

                /// specializes returns the prover and verifier SRS for a specific number of
                /// proofs to aggregate. The number of proofs MUST BE a power of two, it
                /// panics otherwise. The number of proofs must be inferior to half of the
                /// size of the generic srs otherwise it panics.
                template<typename CurveType>
                std::pair<r1cs_gg_pp_zksnark_prover_srs<CurveType>, r1cs_gg_pp_zksnark_verifier_srs<CurveType>>
                    specialize(const r1cs_gg_pp_zksnark_srs<CurveType> &srs, std::size_t num_proofs) {
                    BOOST_ASSERT((num_proofs & (num_proofs - 1)) == 0);

                    std::size_t tn = 2 * num_proofs + 1;    // size of the CRS we need
                    assert(srs.g_alpha_powers.size() >= tn);
                    BOOST_ASSERT(srs.h_alpha_powers.size() >= tn);
                    assert(srs.g_beta_powers.size() >= tn);
                    assert(srs.h_beta_powers.size() >= tn);

                    std::size_t n = num_proofs;
                    // we skip the first one since g^a^0 = g which is not part of the commitment
                    // key (i.e. we don't use it in the prover's code) so for g we skip directly to
                    // g^a^{n+1}
                    std::size_t g_low = n + 1;
                    // we need powers up to 2n
                    std::size_t g_up = g_low + n;
                    std::size_t h_low = 1;
                    std::size_t h_up = h_low + n;
                    window_table g_alpha_powers_table = precompute_fixed_window(
                        srs.g_alpha_powers.begin() + g_low, srs.g_alpha_powers.begin() + g_up, WINDOW_SIZE);
                    window_table g_beta_powers_table = precompute_fixed_window(
                        srs.g_beta_powers.begin() + g_low, srs.g_beta_powers.begin() + g_up, WINDOW_SIZE);
                    window_table h_alpha_powers_table = precompute_fixed_window(
                        srs.h_alpha_powers.begin() + h_low, srs.h_alpha_powers.begin() + h_up, WINDOW_SIZE);
                    window_table h_beta_powers_table = precompute_fixed_window(
                        srs.h_beta_powers.begin() + h_low, srs.h_beta_powers.begin() + h_up, WINDOW_SIZE);
                    std::vector<typename CurveType::g2_type::value_type> v1 = {srs.h_alpha_powers.begin() + h_low,
                                                                               srs.h_alpha_powers.begin() + h_up};
                    std::vector<typename CurveType::g2_type::value_type> v2 = {srs.h_beta_powers.begin() + h_low,
                                                                               srs.h_beta_powers.begin() + h_up};
                    typename r1cs_gg_pp_zksnark_srs<CurveType>::vkey_type vkey = {v1, v2};
                    BOOST_ASSERT(vkey.has_correct_len(n));

                    std::vector<typename CurveType::g1_type::value_type> w1 = {srs.g_alpha_powers.begin() + g_low,
                                                                               srs.g_alpha_powers.begin() + g_up};
                    std::vector<typename CurveType::g1_type::value_type> w2 = {srs.g_beta_powers.begin() + g_low,
                                                                               srs.g_beta_powers.begin() + g_up};
                    // needed by the verifier to check KZG opening with a shifted base point for
                    // the w commitment
                    typename CurveType::g1_type::value_type g_alpha_n1 = w1[0].to_projective();
                    typename CurveType::g1_type::value_type g_beta_n1 = w2[0].to_projective();

                    typename r1cs_gg_pp_zksnark_srs<CurveType>::wkey_type wkey = {w1, w2};
                    BOOST_ASSERT(wkey.has_correct_len(n));
                    r1cs_gg_pp_zksnark_prover_srs<CurveType> pk = {g_alpha_powers_table,
                                                                   g_beta_powers_table,
                                                                   h_alpha_powers_table,
                                                                   h_beta_powers_table,
                                                                   vkey,
                                                                   wkey,
                                                                   n};
                    r1cs_gg_pp_zksnark_verifier_srs<CurveType> vk = {n,
                                                                     srs.g_alpha_powers[0].to_projective(),
                                                                     srs.h_alpha_powers[0].to_projective(),
                                                                     srs.g_alpha_powers[1].to_projective(),
                                                                     srs.g_beta_powers[1].to_projective(),
                                                                     srs.h_alpha_powers[1].to_projective(),
                                                                     srs.h_beta_powers[1].to_projective(),
                                                                     g_alpha_n1,
                                                                     g_beta_n1};
                    return {pk, vk};
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
