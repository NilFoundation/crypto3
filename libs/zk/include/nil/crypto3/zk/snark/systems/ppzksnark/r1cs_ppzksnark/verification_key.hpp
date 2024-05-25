//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_R1CS_PPZKSNARK_VERIFICATION_KEY_HPP
#define CRYPTO3_R1CS_PPZKSNARK_VERIFICATION_KEY_HPP

#include <nil/crypto3/container/accumulation_vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using namespace algebra;

                /**
                 * A verification key for the R1CS ppzkSNARK.
                 */
                template<typename CurveType>
                class r1cs_ppzksnark_verification_key {

                    using g1_type = typename CurveType::template g1_type<>;
                    using g2_type = typename CurveType::template g2_type<>;

                public:
                    typename g2_type::value_type alphaA_g2;
                    typename g1_type::value_type alphaB_g1;
                    typename g2_type::value_type alphaC_g2;
                    typename g2_type::value_type gamma_g2;
                    typename g1_type::value_type gamma_beta_g1;
                    typename g2_type::value_type gamma_beta_g2;
                    typename g2_type::value_type rC_Z_g2;

                    container::accumulation_vector<g1_type> encoded_IC_query;

                    r1cs_ppzksnark_verification_key() = default;
                    r1cs_ppzksnark_verification_key(const typename g2_type::value_type &alphaA_g2,
                                                    const typename g1_type::value_type &alphaB_g1,
                                                    const typename g2_type::value_type &alphaC_g2,
                                                    const typename g2_type::value_type &gamma_g2,
                                                    const typename g1_type::value_type &gamma_beta_g1,
                                                    const typename g2_type::value_type &gamma_beta_g2,
                                                    const typename g2_type::value_type &rC_Z_g2,
                                                    const container::accumulation_vector<g1_type> &eIC) :
                        alphaA_g2(alphaA_g2),
                        alphaB_g1(alphaB_g1), alphaC_g2(alphaC_g2), gamma_g2(gamma_g2), gamma_beta_g1(gamma_beta_g1),
                        gamma_beta_g2(gamma_beta_g2), rC_Z_g2(rC_Z_g2), encoded_IC_query(eIC) {};

                    std::size_t G1_size() const {
                        return 2 + encoded_IC_query.size();
                    }

                    std::size_t G2_size() const {
                        return 5;
                    }

                    std::size_t size_in_bits() const {
                        return (2 * g1_type::value_bits + encoded_IC_query.size_in_bits() + 5 * g2_type::value_bits);
                    }

                    bool operator==(const r1cs_ppzksnark_verification_key &other) const {
                        return (this->alphaA_g2 == other.alphaA_g2 && this->alphaB_g1 == other.alphaB_g1 &&
                                this->alphaC_g2 == other.alphaC_g2 && this->gamma_g2 == other.gamma_g2 &&
                                this->gamma_beta_g1 == other.gamma_beta_g1 &&
                                this->gamma_beta_g2 == other.gamma_beta_g2 && this->rC_Z_g2 == other.rC_Z_g2 &&
                                this->encoded_IC_query == other.encoded_IC_query);
                    }
                };

                /**
                 * A processed verification key for the R1CS ppzkSNARK.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename CurveType>
                class r1cs_ppzksnark_processed_verification_key {

                    using pairing_policy = pairing::pairing_policy<CurveType>;

                public:
                    typename pairing_policy::g2_precomputed_type pp_G2_one_precomp;
                    typename pairing_policy::g2_precomputed_type vk_alphaA_g2_precomp;
                    typename pairing_policy::g1_precomputed_type vk_alphaB_g1_precomp;
                    typename pairing_policy::g2_precomputed_type vk_alphaC_g2_precomp;
                    typename pairing_policy::g2_precomputed_type vk_rC_Z_g2_precomp;
                    typename pairing_policy::g2_precomputed_type vk_gamma_g2_precomp;
                    typename pairing_policy::g1_precomputed_type vk_gamma_beta_g1_precomp;
                    typename pairing_policy::g2_precomputed_type vk_gamma_beta_g2_precomp;

                    container::accumulation_vector<typename CurveType::template g1_type<>> encoded_IC_query;

                    bool operator==(const r1cs_ppzksnark_processed_verification_key &other) const {
                        return (this->pp_G2_one_precomp == other.pp_G2_one_precomp &&
                                this->vk_alphaA_g2_precomp == other.vk_alphaA_g2_precomp &&
                                this->vk_alphaB_g1_precomp == other.vk_alphaB_g1_precomp &&
                                this->vk_alphaC_g2_precomp == other.vk_alphaC_g2_precomp &&
                                this->vk_rC_Z_g2_precomp == other.vk_rC_Z_g2_precomp &&
                                this->vk_gamma_g2_precomp == other.vk_gamma_g2_precomp &&
                                this->vk_gamma_beta_g1_precomp == other.vk_gamma_beta_g1_precomp &&
                                this->vk_gamma_beta_g2_precomp == other.vk_gamma_beta_g2_precomp &&
                                this->encoded_IC_query == other.encoded_IC_query);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP
