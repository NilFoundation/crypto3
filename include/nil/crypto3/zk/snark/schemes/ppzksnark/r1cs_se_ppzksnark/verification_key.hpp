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

#ifndef CRYPTO3_R1CS_SE_PPZKSNARK_VERIFICATION_KEY_HPP
#define CRYPTO3_R1CS_SE_PPZKSNARK_VERIFICATION_KEY_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A verification key for the R1CS SEppzkSNARK.
                 */
                template<typename CurveType>
                struct r1cs_se_ppzksnark_verification_key {
                    typedef CurveType curve_type;

                    // H
                    typename curve_type::g2_type::value_type H;

                    // G^{alpha}
                    typename curve_type::g1_type::value_type G_alpha;

                    // H^{beta}
                    typename curve_type::g2_type::value_type H_beta;

                    // G^{gamma}
                    typename curve_type::g1_type::value_type G_gamma;

                    // H^{gamma}
                    typename curve_type::g2_type::value_type H_gamma;

                    // G^{gamma * A_i(t) + (alpha + beta) * A_i(t)}
                    // for 0 <= i <= sap.num_inputs()
                    std::vector<typename CurveType::g1_type::value_type> query;

                    r1cs_se_ppzksnark_verification_key() = default;
                    r1cs_se_ppzksnark_verification_key(const typename CurveType::g2_type::value_type &H,
                                                       const typename CurveType::g1_type::value_type &G_alpha,
                                                       const typename CurveType::g2_type::value_type &H_beta,
                                                       const typename CurveType::g1_type::value_type &G_gamma,
                                                       const typename CurveType::g2_type::value_type &H_gamma,
                                                       std::vector<typename CurveType::g1_type::value_type> &&query) :
                        H(H),
                        G_alpha(G_alpha), H_beta(H_beta), G_gamma(G_gamma), H_gamma(H_gamma),
                        query(std::move(query)) {};

                    std::size_t G1_size() const {
                        return 2 + query.size();
                    }

                    std::size_t G2_size() const {
                        return 3;
                    }

                    std::size_t size_in_bits() const {
                        return (G1_size() * CurveType::g1_type::value_bits +
                                G2_size() * CurveType::g2_type::value_bits);
                    }

                    bool operator==(const r1cs_se_ppzksnark_verification_key &other) const {
                        return (this->H == other.H && this->G_alpha == other.G_alpha && this->H_beta == other.H_beta &&
                                this->G_gamma == other.G_gamma && this->H_gamma == other.H_gamma &&
                                this->query == other.query);
                    }
                };

                /**
                 * A processed verification key for the R1CS SEppzkSNARK.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename CurveType>
                class r1cs_se_ppzksnark_processed_verification_key {
                    typedef typename CurveType::pairing pairing_policy;

                public:
                    typedef CurveType curve_type;

                    typename CurveType::g1_type::value_type G_alpha;
                    typename CurveType::g2_type::value_type H_beta;
                    typename pairing_policy::fqk_type::value_type G_alpha_H_beta_ml;
                    typename pairing_policy::g1_precomp G_gamma_pc;
                    typename pairing_policy::g2_precomp H_gamma_pc;
                    typename pairing_policy::g2_precomp H_pc;

                    std::vector<typename CurveType::g1_type::value_type> query;

                    bool operator==(const r1cs_se_ppzksnark_processed_verification_key &other) const {
                        return (this->G_alpha == other.G_alpha && this->H_beta == other.H_beta &&
                                this->G_alpha_H_beta_ml == other.G_alpha_H_beta_ml &&
                                this->G_gamma_pc == other.G_gamma_pc && this->H_gamma_pc == other.H_gamma_pc &&
                                this->H_pc == other.H_pc && this->query == other.query);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP
