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

#ifndef CRYPTO3_USCS_PPZKSNARK_VERIFICATION_KEY_HPP
#define CRYPTO3_USCS_PPZKSNARK_VERIFICATION_KEY_HPP

#include <memory>
#include <vector>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * A verification key for the USCS ppzkSNARK.
                 */
                template<typename CurveType>
                struct uscs_ppzksnark_verification_key {
                    typedef CurveType curve_type;

                    typename CurveType::g2_type::value_type tilde_g2;
                    typename CurveType::g2_type::value_type alpha_tilde_g2;
                    typename CurveType::g2_type::value_type Z_g2;

                    accumulation_vector<typename CurveType::g1_type> encoded_IC_query;

                    uscs_ppzksnark_verification_key() = default;
                    uscs_ppzksnark_verification_key(const typename CurveType::g2_type::value_type &tilde_g2,
                                                    const typename CurveType::g2_type::value_type &alpha_tilde_g2,
                                                    const typename CurveType::g2_type::value_type &Z_g2,
                                                    const accumulation_vector<typename CurveType::g1_type> &eIC) :
                        tilde_g2(tilde_g2),
                        alpha_tilde_g2(alpha_tilde_g2), Z_g2(Z_g2), encoded_IC_query(eIC) {};

                    std::size_t G1_size() const {
                        return encoded_IC_query.size();
                    }

                    std::size_t G2_size() const {
                        return 3;
                    }

                    std::size_t size_in_bits() const {
                        return encoded_IC_query.size_in_bits() + 3 * CurveType::g2_type::value_bits;
                    }

                    bool operator==(const uscs_ppzksnark_verification_key &other) const {
                        return (this->tilde_g2 == other.tilde_g2 && this->alpha_tilde_g2 == other.alpha_tilde_g2 &&
                                this->Z_g2 == other.Z_g2 && this->encoded_IC_query == other.encoded_IC_query);
                    }
                };

                /**
                 * A processed verification key for the USCS ppzkSNARK.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename CurveType>
                class uscs_ppzksnark_processed_verification_key {
                    typedef typename CurveType::pairing pairing_policy;

                public:
                    typedef CurveType curve_type;

                    typename pairing_policy::g1_precomp pp_G1_one_precomp;
                    typename pairing_policy::g2_precomp pp_G2_one_precomp;
                    typename pairing_policy::g2_precomp vk_tilde_g2_precomp;
                    typename pairing_policy::g2_precomp vk_alpha_tilde_g2_precomp;
                    typename pairing_policy::g2_precomp vk_Z_g2_precomp;
                    typename CurveType::gt_type::value_type pairing_of_g1_and_g2;

                    accumulation_vector<typename CurveType::g1_type> encoded_IC_query;

                    bool operator==(const uscs_ppzksnark_processed_verification_key &other) const {
                        return (this->pp_G1_one_precomp == other.pp_G1_one_precomp &&
                                this->pp_G2_one_precomp == other.pp_G2_one_precomp &&
                                this->vk_tilde_g2_precomp == other.vk_tilde_g2_precomp &&
                                this->vk_alpha_tilde_g2_precomp == other.vk_alpha_tilde_g2_precomp &&
                                this->vk_Z_g2_precomp == other.vk_Z_g2_precomp &&
                                this->pairing_of_g1_and_g2 == other.pairing_of_g1_and_g2 &&
                                this->encoded_IC_query == other.encoded_IC_query);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP

