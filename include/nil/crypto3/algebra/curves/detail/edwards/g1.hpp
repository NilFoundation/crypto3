//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_EDWARDS_G1_HPP
#define CRYPTO3_ALGEBRA_CURVES_EDWARDS_G1_HPP

#include <nil/crypto3/algebra/curves/detail/edwards/edwards183/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/edwards183/element_g1.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/jubjub/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/babyjubjub/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/babyjubjub/element_g1.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<std::size_t Version>
                struct edwards;

                struct jubjub;

                struct babyjubjub;

                namespace detail {
                    /** @brief A struct representing a group G1 of Edwards curve.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version>
                    struct edwards_g1;

                    template<>
                    struct edwards_g1<183> {
                        constexpr static const std::size_t version = 183;

                        using policy_type = edwards_basic_policy<version>;

                        using curve_type = edwards<version>;

                        using underlying_field_type = typename policy_type::g1_field_type;

                        constexpr static const std::size_t value_bits =
                            underlying_field_type::value_bits + 1;    ///< size of the base field in bits

                        using value_type = element_edwards_g1<version>;
                    };

                    // JubJub
                    template<>
                    struct edwards_g1<255> {
                        constexpr static const std::size_t version = 255;

                        using policy_type = edwards_basic_policy<version>;

                        using curve_type = jubjub;

                        using underlying_field_type = typename policy_type::g1_field_type;

                        constexpr static const std::size_t value_bits =
                            underlying_field_type::value_bits + 1;    ///< size of the base field in bits

                        using value_type = element_twisted_edwards_g1<version>;
                    };

                    // BabyJubJub
                    template<>
                    struct edwards_g1<254> {
                        constexpr static const std::size_t version = 254;

                        using policy_type = edwards_basic_policy<version>;

                        using curve_type = babyjubjub;

                        using underlying_field_type = typename policy_type::g1_field_type;

                        constexpr static const std::size_t value_bits =
                            underlying_field_type::value_bits + 1;    ///< size of the base field in bits

                        using value_type = element_twisted_edwards_g1<version>;
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_G1_HPP
