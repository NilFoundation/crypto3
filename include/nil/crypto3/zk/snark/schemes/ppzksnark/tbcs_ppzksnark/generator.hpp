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

#ifndef CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_GENERATOR_HPP
#define CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_GENERATOR_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/uscs_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/reductions/tbcs_to_uscs.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/tbcs_ppzksnark/detail/basic_policy.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/tbcs_ppzksnark/proving_key.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * A generator algorithm for the TBCS ppzkSNARK.
                 *
                 * Given a TBCS circuit C, this algorithm produces proving and verification keys for C.
                 */
                template<typename CurveType>
                class tbcs_ppzksnark_generator {
                    typedef detail::tbcs_ppzksnark_policy<CurveType> policy_type;

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

                        const uscs_constraint_system<field_type> uscs_cs =
                            reductions::tbcs_to_uscs<field_type>::instance_map(circuit);
                        const typename uscs_ppzksnark<CurveType>::keypair_type uscs_keypair =
                            generate<uscs_ppzksnark<CurveType>>(uscs_cs);

                        proving_key_type pk = proving_key_type(std::move(circuit), std::move(uscs_keypair.first));

                        return keypair_type(std::move(pk), std::move(uscs_keypair.second));
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_GENERATOR_HPP
