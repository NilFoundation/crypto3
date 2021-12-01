//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_VERIFICATION_KEY_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_VERIFICATION_KEY_HPP

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/verification_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                struct r1cs_gg_ppzksnark_verification_key<CurveType, ProvingMode::EncryptedInput> {
                    typedef CurveType curve_type;
                    static constexpr ProvingMode mode = ProvingMode::EncryptedInput;

                    typedef typename CurveType::template g2_type<> g2_type;

                    typename g2_type::value_type rho_g2;
                    std::vector<typename g2_type::value_type> rho_sv_g2;
                    std::vector<typename g2_type::value_type> rho_rhov_g2;

                    r1cs_gg_ppzksnark_verification_key() = default;
                    r1cs_gg_ppzksnark_verification_key(const typename g2_type::value_type &rho_g2,
                                                       const std::vector<typename g2_type::value_type> &rho_sv_g2,
                                                       const std::vector<typename g2_type::value_type> &rho_rhov_g2) :
                        rho_g2(rho_g2),
                        rho_sv_g2(rho_sv_g2), rho_rhov_g2(rho_rhov_g2) {
                    }

                    std::size_t size_in_bits() const {
                        return (1 + rho_sv_g2.size() + rho_rhov_g2.size()) * g2_type::value_bits;
                    }

                    bool operator==(const r1cs_gg_ppzksnark_verification_key &other) const {
                        return rho_g2 == other.rho_g2 && rho_sv_g2 == other.rho_sv_g2 &&
                               rho_rhov_g2 == other.rho_rhov_g2;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
