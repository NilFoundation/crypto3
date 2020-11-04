//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_POLICY_HPP

#include <nil/crypto3/algebra/pairing/detail/alt_bn128/functions.hpp>
#include <nil/crypto3/algebra/pairing/policy.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                template<std::size_t ModulusBits>
                struct alt_bn128;
            }    // namespace curves
            namespace pairing {

                using namespace nil::crypto3::algebra;

                template<std::size_t ModulusBits>
                class pairing_policy<curves::alt_bn128<ModulusBits>>
                    : public detail::alt_bn128_pairing_functions<ModulusBits> {
                    using policy_type = detail::alt_bn128_pairing_functions<ModulusBits>;
                    using basic_policy = detail::alt_bn128_basic_policy<ModulusBits>;

                public:
                    using number_type = typename basic_policy::number_type;

                    constexpr static const typename basic_policy::number_type pairing_loop_count =
                        basic_policy::ate_loop_count;

                    using Fp_type = typename basic_policy::Fp_field;
                    using G1_type = typename basic_policy::g1;
                    using G2_type = typename basic_policy::g2;
                    using Fq_type = typename basic_policy::Fq_field;
                    using Fqe_type = typename basic_policy::Fqe_field;
                    using Fqk_type = typename basic_policy::Fqk_field;
                    using GT_type = typename basic_policy::gt;

                    using G1_precomp = typename policy_type::ate_g1_precomp;
                    using G2_precomp = typename policy_type::ate_g2_precomp;

                    using policy_type::precompute_g1;
                    using policy_type::precompute_g2;

                    using policy_type::pairing;
                    using policy_type::reduced_pairing;

                    using policy_type::double_miller_loop;
                    using policy_type::final_exponentiation;
                    using policy_type::miller_loop;
                };

                template<std::size_t ModulusBits>
                constexpr typename pairing_policy<curves::alt_bn128<ModulusBits>>::number_type const
                    pairing_policy<curves::alt_bn128<ModulusBits>>::pairing_loop_count;
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_POLICY_HPP