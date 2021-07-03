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

#ifndef CRYPTO3_TBCS_PPZKSNARK_PROVING_KEY_HPP
#define CRYPTO3_TBCS_PPZKSNARK_PROVING_KEY_HPP

#include <memory>
#include <vector>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/uscs_ppzksnark.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * A proving key for the R1CS ppzkSNARK.
                 */
                template<typename CurveType, typename CircuitType>
                struct tbcs_ppzksnark_proving_key {

                    typedef CurveType curve_type;
                    typedef CircuitType circuit_type;
                    typedef typename curve_type::scalar_field_type field_type;

                    circuit_type circuit;
                    uscs_ppzksnark_proving_key<CurveType, circuit_type> uscs_pk;

                    tbcs_ppzksnark_proving_key() {};
                    tbcs_ppzksnark_proving_key(const tbcs_ppzksnark_proving_key &other) = default;
                    tbcs_ppzksnark_proving_key(tbcs_ppzksnark_proving_key &&other) = default;
                    tbcs_ppzksnark_proving_key(const circuit_type &circuit,
                                               const uscs_ppzksnark_proving_key<CurveType, circuit_type> &uscs_pk) :
                        circuit(circuit),
                        uscs_pk(uscs_pk) {
                    }
                    tbcs_ppzksnark_proving_key(circuit_type &&circuit,
                                               uscs_ppzksnark_proving_key<CurveType, circuit_type> &&uscs_pk) :
                        circuit(std::move(circuit)),
                        uscs_pk(std::move(uscs_pk)) {
                    }

                    tbcs_ppzksnark_proving_key &operator=(const tbcs_ppzksnark_proving_key &other) = default;

                    std::size_t G1_size() const {
                        return uscs_pk.G1_size();
                    }

                    std::size_t G2_size() const {
                        return uscs_pk.G2_size();
                    }

                    std::size_t G1_sparse_size() const {
                        return uscs_pk.G1_sparse_size();
                    }

                    std::size_t G2_sparse_size() const {
                        return uscs_pk.G2_sparse_size();
                    }

                    std::size_t size_in_bits() const {
                        return uscs_pk.size_in_bits();
                    }

                    bool operator==(const tbcs_ppzksnark_proving_key &other) const {
                        return (this->circuit == other.circuit && this->uscs_pk == other.uscs_pk);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP
