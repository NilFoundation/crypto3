//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ZK_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_GENERATOR_HPP
#define CRYPTO3_ZK_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_GENERATOR_HPP

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/generator.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                class r1cs_gg_ppzksnark_generator<CurveType, proving_mode::encrypted_input> {

                    typedef detail::r1cs_gg_ppzksnark_basic_policy<CurveType, proving_mode::encrypted_input>
                        policy_type;
                    typedef r1cs_gg_ppzksnark_generator<CurveType, proving_mode::basic> basic_generator_type;

                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::template g1_type<> g1_type;
                    typedef typename CurveType::template g2_type<> g2_type;
                    typedef typename CurveType::gt_type gt_type;

                public:
                    typedef typename policy_type::constraint_system_type constraint_system_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    template<typename KeyPairType,
                             typename DistributionType =
                                 boost::random::uniform_int_distribution<typename scalar_field_type::integral_type>,
                             typename GeneratorType = boost::random::mt19937>
                    static inline
                        typename std::enable_if<std::is_same<keypair_type, KeyPairType>::value, KeyPairType>::type
                        process(const constraint_system_type &constraint_system) {

                        return basic_generator_type::template process<keypair_type, DistributionType, GeneratorType>(
                            constraint_system);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_GENERATOR_HPP
