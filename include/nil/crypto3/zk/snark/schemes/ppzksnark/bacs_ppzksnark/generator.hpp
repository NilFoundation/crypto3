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

#ifndef CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_GENERATOR_HPP
#define CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_GENERATOR_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs.hpp>
#include <nil/crypto3/zk/snark/reductions/bacs_to_r1cs.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/bacs_ppzksnark/detail/basic_policy.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A generator algorithm for the BACS ppzkSNARK.
                 *
                 * Given a BACS circuit C, this algorithm produces proving and verification keys for C.
                 */
                template<typename CurveType>
                class bacs_ppzksnark_generator {
                    typedef detail::bacs_ppzksnark_policy<CurveType> policy_type;

                public:
                    typedef typename policy_type::circuit_type circuit_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    static inline keypair_type process(const circuit_type &circuit) {
                        typedef typename CurveType::scalar_field_type field_type;

                        const r1cs_constraint_system<field_type> r1cs_cs =
                            reductions::bacs_to_r1cs<field_type>::instance_map(circuit);
                        const typename r1cs_ppzksnark<CurveType>::keypair_type r1cs_keypair =
                            generate<r1cs_ppzksnark<CurveType>>(r1cs_cs);

                        return keypair_type(proving_key_type(circuit, r1cs_keypair.first), r1cs_keypair.second);
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_GENERATOR_HPP
