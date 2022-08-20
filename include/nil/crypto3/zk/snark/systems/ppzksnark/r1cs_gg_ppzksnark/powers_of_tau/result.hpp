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

#ifndef CRYPTO3_R1CS_POWERS_OF_TAU_RESULT_HPP
#define CRYPTO3_R1CS_POWERS_OF_TAU_RESULT_HPP

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/detail/basic_policy.hpp>
#include<vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                struct powers_of_tau_result {
                    typedef CurveType curve_type;
                    using g1_type = typename CurveType::template g1_type<>;
                    using g2_type = typename CurveType::template g2_type<>;
                    using g1_value_type = typename g1_type::value_type;
                    using g2_value_type = typename g2_type::value_type;
                    using field_value_type = typename curve_type::scalar_field_type::value_type; 

                    g1_value_type alpha_g1;
                    g1_value_type beta_g1;
                    g2_value_type beta_g2;
                    std::vector<g1_value_type> coeffs_g1;
                    std::vector<g2_value_type> coeffs_g2;
                    std::vector<g1_value_type> alpha_coeffs_g1;
                    std::vector<g1_value_type> beta_coeffs_g1;
                    std::vector<g1_value_type> h;
                };
            }   // snarks
        }   // zk
    }   // crypto3
}   // nil

#endif  // CRYPTO3_R1CS_POWERS_OF_TAU_ACCUMULATOR_HPP
