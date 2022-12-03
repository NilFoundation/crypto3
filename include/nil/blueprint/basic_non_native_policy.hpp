//---------------------------------------------------------------------------//
// Copyright (c) 2020-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_BASIC_NON_NATIVE_POLICY_HPP
#define CRYPTO3_BLUEPRINT_BASIC_NON_NATIVE_POLICY_HPP

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {
            template<typename BlueprintFieldType, typename OperatingFieldType>
            struct basic_non_native_policy_field_type;

            template<>
            struct basic_non_native_policy_field_type<typename crypto3::algebra::curves::pallas::base_field_type,
                                                      typename crypto3::algebra::curves::ed25519::base_field_type> {

                constexpr static const std::uint32_t ratio = 4;    // 66,66,66,66 bits

                typedef std::array<
                    crypto3::zk::snark::plonk_variable<typename crypto3::algebra::curves::pallas::base_field_type>,
                    ratio>
                    value_type;
            };

            /*
             * Native element type.
             */
            template<typename BlueprintFieldType>
            struct basic_non_native_policy_field_type<BlueprintFieldType, BlueprintFieldType> {

                constexpr static const std::uint32_t ratio = 1;

                typedef crypto3::zk::snark::plonk_variable<BlueprintFieldType> value_type;
            };
        }    // namespace detail

        template<typename BlueprintFieldType>
        class basic_non_native_policy;

        template<>
        class basic_non_native_policy<typename crypto3::algebra::curves::pallas::base_field_type> {

            using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

        public:
            template<typename OperatingFieldType>
            using field = typename detail::basic_non_native_policy_field_type<BlueprintFieldType, OperatingFieldType>;
        };

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_BASIC_NON_NATIVE_POLICY_HPP
