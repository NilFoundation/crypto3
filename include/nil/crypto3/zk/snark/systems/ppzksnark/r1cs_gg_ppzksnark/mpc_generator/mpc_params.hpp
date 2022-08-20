//---------------------------------------------------------------------------//
// Copyright (c) 2022 Noam Y <@NoamDev>
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

#ifndef CRYPTO3_R1CS_MPC_GENERATOR_MPC_PARAMS_HPP
#define CRYPTO3_R1CS_MPC_GENERATOR_MPC_PARAMS_HPP

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/mpc_generator/public_key.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>
#include<vector>
#include <nil/crypto3/container/accumulation_vector.hpp>
#include <nil/crypto3/zk/commitments/polynomial/knowledge_commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                struct r1cs_gg_ppzksnark_mpc_params {
                    typedef CurveType curve_type;
                    typedef r1cs_gg_ppzksnark<curve_type> proving_scheme_type;

                    typename proving_scheme_type::keypair_type keypair;
                };
            }   // snarks
        }   // zk
    }   // crypto3
}   // nil

#endif  // CRYPTO3_R1CS_MPC_GENERATOR_MPC_PARAMS_HPP
