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

#ifndef CRYPTO3_R1CS_SE_PPZKSNARK_PROVING_KEY_HPP
#define CRYPTO3_R1CS_SE_PPZKSNARK_PROVING_KEY_HPP

#include <memory>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * A proving key for the R1CS ppzkSNARK.
                 */
                template<typename CurveType, typename ConstraintSystem>
                struct r1cs_se_ppzksnark_proving_key {
                    typedef CurveType curve_type;
                    typedef ConstraintSystem constraint_system_type;

                    // G^{gamma * A_i(t)} for 0 <= i <= sap.num_variables()
                    std::vector<typename CurveType::g1_type::value_type> A_query;

                    // H^{gamma * A_i(t)} for 0 <= i <= sap.num_variables()
                    std::vector<typename CurveType::g2_type::value_type> B_query;

                    // G^{gamma^2 * C_i(t) + (alpha + beta) * gamma * A_i(t)}
                    // for sap.num_inputs() + 1 < i <= sap.num_variables()
                    std::vector<typename CurveType::g1_type::value_type> C_query_1;

                    // G^{2 * gamma^2 * Z(t) * A_i(t)} for 0 <= i <= sap.num_variables()
                    std::vector<typename CurveType::g1_type::value_type> C_query_2;

                    // G^{gamma * Z(t)}
                    typename CurveType::g1_type::value_type G_gamma_Z;

                    // H^{gamma * Z(t)}
                    typename CurveType::g2_type::value_type H_gamma_Z;

                    // G^{(alpha + beta) * gamma * Z(t)}
                    typename CurveType::g1_type::value_type G_ab_gamma_Z;

                    // G^{gamma^2 * Z(t)^2}
                    typename CurveType::g1_type::value_type G_gamma2_Z2;

                    // G^{gamma^2 * Z(t) * t^i} for 0 <= i < sap.degree
                    std::vector<typename CurveType::g1_type::value_type> G_gamma2_Z_t;

                    constraint_system_type constraint_system;

                    r1cs_se_ppzksnark_proving_key() {};
                    r1cs_se_ppzksnark_proving_key &operator=(const r1cs_se_ppzksnark_proving_key &other) = default;
                    r1cs_se_ppzksnark_proving_key(const r1cs_se_ppzksnark_proving_key &other) = default;
                    r1cs_se_ppzksnark_proving_key(r1cs_se_ppzksnark_proving_key &&other) = default;
                    r1cs_se_ppzksnark_proving_key(std::vector<typename CurveType::g1_type::value_type> &&A_query,
                                                  std::vector<typename CurveType::g2_type::value_type> &&B_query,
                                                  std::vector<typename CurveType::g1_type::value_type> &&C_query_1,
                                                  std::vector<typename CurveType::g1_type::value_type> &&C_query_2,
                                                  typename CurveType::g1_type::value_type &G_gamma_Z,
                                                  typename CurveType::g2_type::value_type &H_gamma_Z,
                                                  typename CurveType::g1_type::value_type &G_ab_gamma_Z,
                                                  typename CurveType::g1_type::value_type &G_gamma2_Z2,
                                                  std::vector<typename CurveType::g1_type::value_type> &&G_gamma2_Z_t,
                                                  constraint_system_type &&constraint_system) :
                        A_query(std::move(A_query)),
                        B_query(std::move(B_query)), C_query_1(std::move(C_query_1)), C_query_2(std::move(C_query_2)),
                        G_gamma_Z(G_gamma_Z), H_gamma_Z(H_gamma_Z), G_ab_gamma_Z(G_ab_gamma_Z),
                        G_gamma2_Z2(G_gamma2_Z2), G_gamma2_Z_t(std::move(G_gamma2_Z_t)), constraint_system(std::move(constraint_system)) {};

                    std::size_t G1_size() const {
                        return A_query.size() + C_query_1.size() + C_query_2.size() + 3 + G_gamma2_Z_t.size();
                    }

                    std::size_t G2_size() const {
                        return B_query.size() + 1;
                    }

                    std::size_t size_in_bits() const {
                        return G1_size() * CurveType::g1_type::value_bits + G2_size() * CurveType::g2_type::value_bits;
                    }

                    bool operator==(const r1cs_se_ppzksnark_proving_key &other) const {
                        return (this->A_query == other.A_query && this->B_query == other.B_query &&
                                this->C_query_1 == other.C_query_1 && this->C_query_2 == other.C_query_2 &&
                                this->G_gamma_Z == other.G_gamma_Z && this->H_gamma_Z == other.H_gamma_Z &&
                                this->G_ab_gamma_Z == other.G_ab_gamma_Z && this->G_gamma2_Z2 == other.G_gamma2_Z2 &&
                                this->G_gamma2_Z_t == other.G_gamma2_Z_t && this->constraint_system == other.constraint_system);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP
