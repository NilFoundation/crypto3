//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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
// @file Declaration of types for Placeholder PLONK scheme.
//
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PLONK_PLACEHOLDER_TYPES_POLICY_HPP
#define CRYPTO3_PLONK_PLACEHOLDER_TYPES_POLICY_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/detail/field_utils.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {
                    template<typename FieldType, typename PlaceholderParams>
                    struct placeholder_policy {
                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        typedef plonk_constraint_system<FieldType> constraint_system_type;

                        typedef FieldType field_type;
                        typedef PlaceholderParams placeholder_params_type;

                        typedef plonk_assignment_table<FieldType> variable_assignment_type;

                        typedef detail::plonk_evaluation_map<plonk_variable<typename FieldType::value_type>> evaluation_map;

                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PLONK_PLACEHOLDER_TYPES_POLICY_HPP
