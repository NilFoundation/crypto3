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

#ifndef CRYPTO3_USCS_PPZKSNARK_PROVING_KEY_HPP
#define CRYPTO3_USCS_PPZKSNARK_PROVING_KEY_HPP

#include <memory>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * A proving key for the USCS ppzkSNARK.
                 */
                template<typename CurveType, typename ConstraintSystem>
                struct uscs_ppzksnark_proving_key {
                    typedef CurveType curve_type;
                    typedef ConstraintSystem constraint_system_type;

                    std::vector<typename CurveType::g1_type::value_type> V_g1_query;
                    std::vector<typename CurveType::g1_type::value_type> alpha_V_g1_query;
                    std::vector<typename CurveType::g1_type::value_type> H_g1_query;
                    std::vector<typename CurveType::g2_type::value_type> V_g2_query;

                    constraint_system_type constraint_system;

                    uscs_ppzksnark_proving_key() {};
                    uscs_ppzksnark_proving_key &operator=(const uscs_ppzksnark_proving_key &other) = default;
                    uscs_ppzksnark_proving_key(const uscs_ppzksnark_proving_key &other) = default;
                    uscs_ppzksnark_proving_key(uscs_ppzksnark_proving_key &&other) = default;
                    uscs_ppzksnark_proving_key(std::vector<typename CurveType::g1_type::value_type> &&V_g1_query,
                                               std::vector<typename CurveType::g1_type::value_type> &&alpha_V_g1_query,
                                               std::vector<typename CurveType::g1_type::value_type> &&H_g1_query,
                                               std::vector<typename CurveType::g2_type::value_type> &&V_g2_query,
                                               constraint_system_type &&constraint_system) :
                        V_g1_query(std::move(V_g1_query)),
                        alpha_V_g1_query(std::move(alpha_V_g1_query)), H_g1_query(std::move(H_g1_query)),
                        V_g2_query(std::move(V_g2_query)), constraint_system(std::move(constraint_system)) {};

                    std::size_t G1_size() const {
                        return V_g1_query.size() + alpha_V_g1_query.size() + H_g1_query.size();
                    }

                    std::size_t G2_size() const {
                        return V_g2_query.size();
                    }

                    std::size_t G1_sparse_size() const {
                        return G1_size();
                    }

                    std::size_t G2_sparse_size() const {
                        return G2_size();
                    }

                    std::size_t size_in_bits() const {
                        return CurveType::g1_type::value_bits * G1_size() + CurveType::g2_type::value_bits * G2_size();
                    }

                    bool operator==(const uscs_ppzksnark_proving_key &other) const {
                        return (this->V_g1_query == other.V_g1_query &&
                                this->alpha_V_g1_query == other.alpha_V_g1_query &&
                                this->H_g1_query == other.H_g1_query && this->V_g2_query == other.V_g2_query &&
                                this->constraint_system == other.constraint_system);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP
