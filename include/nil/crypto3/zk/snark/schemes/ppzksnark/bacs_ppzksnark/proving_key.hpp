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

#ifndef CRYPTO3_ZK_BACS_PPZKSNARK_PROVING_KEY_HPP
#define CRYPTO3_ZK_BACS_PPZKSNARK_PROVING_KEY_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_ppzksnark.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType, typename CircuitType>
                struct bacs_ppzksnark_proving_key {
                    typedef CurveType curve_type;
                    typedef CircuitType circuit_type;
                    typedef typename r1cs_ppzksnark<CurveType>::proving_key_type r1cs_proving_key_type;

                    circuit_type circuit;
                    r1cs_proving_key_type r1cs_pk;

                    bacs_ppzksnark_proving_key() {};

                    bacs_ppzksnark_proving_key(const bacs_ppzksnark_proving_key &other) = default;

                    bacs_ppzksnark_proving_key(bacs_ppzksnark_proving_key &&other) = default;

                    bacs_ppzksnark_proving_key(const circuit_type &circuit, 
                                               const r1cs_proving_key_type &r1cs_pk) :
                        circuit(circuit), r1cs_pk(r1cs_pk) {
                    }

                    bacs_ppzksnark_proving_key(circuit_type &&circuit, 
                                               r1cs_proving_key_type &&r1cs_pk) :
                        circuit(std::move(circuit)), r1cs_pk(std::move(r1cs_pk)) {
                    }

                    bacs_ppzksnark_proving_key &operator=(const bacs_ppzksnark_proving_key &other) = default;

                    std::size_t G1_size() const {
                        return r1cs_pk.G1_size();
                    }

                    std::size_t G2_size() const {
                        return r1cs_pk.G2_size();
                    }

                    std::size_t G1_sparse_size() const {
                        return r1cs_pk.G1_sparse_size();
                    }

                    std::size_t G2_sparse_size() const {
                        return r1cs_pk.G2_sparse_size();
                    }

                    std::size_t size_in_bits() const {
                        return r1cs_pk.size_in_bits();
                    }

                    bool operator==(const bacs_ppzksnark_proving_key &other) const {
                        return (this->circuit == other.circuit && this->r1cs_pk == other.r1cs_pk);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif
