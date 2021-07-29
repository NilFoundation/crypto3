//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_PAIRING_BLS12_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_BLS12_POLICY_HPP

#include <numeric>

#include <nil/crypto3/algebra/curves/jubjub.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12/381/ate_double_miller_loop.hpp>
#include <nil/crypto3/algebra/pairing/bls12/381/ate_miller_loop.hpp>
#include <nil/crypto3/algebra/pairing/bls12/381/ate_precompute_g1.hpp>
#include <nil/crypto3/algebra/pairing/bls12/381/ate_precompute_g2.hpp>
#include <nil/crypto3/algebra/pairing/bls12/381/final_exponentiation.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<typename PairingCurveType, 
                         typename PrecomputeG1 = pairing::ate_precompute_g1<PairingCurveType>, 
                         typename PrecomputeG2 = pairing::ate_precompute_g2<PairingCurveType>, 
                         typename MillerLoop = pairing::ate_miller_loop<PairingCurveType>, 
                         typename DoubleMillerLoop = pairing::ate_double_miller_loop<PairingCurveType>, 
                         typename FinalExponentiation = pairing::final_exponentiation<PairingCurveType>
                         >
                class pairing_policy {

                    using curve_type = PairingCurveType;

                    using types_policy = detail::types_policy<curve_type>;

                    using g1_type = typename curve_type::g1_type<>;
                    using g2_type = typename curve_type::g2_type<>;
                public:
                    using chained_curve_type = curves::jubjub;

                    typedef typename types_policy::integral_type integral_type;

                    using g1_precomputed_type = typename types_policy::g1_precomputed_type;
                    using g2_precomputed_type = typename types_policy::g2_precomputed_type;

                    using precompute_g1 = PrecomputeG1;
                    using precompute_g2 = PrecomputeG2;
                    using miller_loop = MillerLoop;
                    using double_miller_loop = DoubleMillerLoop;
                    using final_exponentiation = FinalExponentiation;
                };

                // template<std::size_t Version, typename PairingFunctions>
                // constexpr typename pairing_policy<curves::bls12<Version>, PairingFunctions>::number_type const
                //     pairing_policy<curves::bls12<Version>, PairingFunctions>::pairing_loop_count;
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_BLS12_POLICY_HPP
