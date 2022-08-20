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

#ifndef CRYPTO3_R1CS_POWERS_OF_TAU_BASIC_POLICY_HPP
#define CRYPTO3_R1CS_POWERS_OF_TAU_BASIC_POLICY_HPP

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/private_key.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/public_key.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/accumulator.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType, unsigned TauPowersLength>
                    struct powers_of_tau_basic_policy
                    {
                        // The maximum number of multiplication gates supported
                        static constexpr unsigned tau_powers_length = TauPowersLength;

                        // More tau powers are needed in G1 because the Groth16 H query
                        // includes terms of the form tau^i * (tau^m - 1) = tau^(i+m) - tau^i
                        // where the largest i = m - 2, requiring the computation of tau^(2m - 2)
                        // and thus giving us a vector length of 2m - 1.
                        static constexpr unsigned tau_powers_g1_length = (tau_powers_length << 1) - 1;

                        typedef powers_of_tau_private_key<CurveType> private_key_type;
                        typedef powers_of_tau_public_key<CurveType> public_key_type;
                        typedef powers_of_tau_accumulator<CurveType, TauPowersLength> accumulator_type;
                    };
                    
                }   // detail
            }   // snarks
        }   // zk
    }   // crypto3
}   // nil

#endif  // CRYPTO3_R1CS_POWERS_OF_TAU_BASIC_POLICY_HPP
