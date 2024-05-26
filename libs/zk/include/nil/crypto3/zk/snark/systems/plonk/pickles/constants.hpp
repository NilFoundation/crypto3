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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_CONSTANTS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_CONSTANTS_HPP

#include <cstdint>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                
                struct kimchi_constant {
                    constexpr static const std::size_t CHALLENGE_LENGTH_IN_LIMBS = 2;
                    constexpr static const std::size_t PERMUTES = 7;
                    constexpr static const std::size_t CONSTRAINTS = 3;
                    constexpr static const std::size_t COLUMNS = 15;
                    constexpr static const std::size_t SPONGE_CAPACITY = 1;
                    constexpr static const std::size_t SPONGE_RATE = 2;
                    constexpr static const std::size_t ZK_ROWS = 3;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_CONSTANTS_HPP