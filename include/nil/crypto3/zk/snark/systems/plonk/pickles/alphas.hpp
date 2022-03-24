//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_BATCHED_PICKLES_ALPHAS_HPP
#define CRYPTO3_ZK_PLONK_BATCHED_PICKLES_ALPHAS_HPP

#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <map>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType>
                struct Alphas {
                    /// The next power of alpha to use
                    /// the end result will be [1, alpha^{next_power - 1}]
                    uint32_t next_power;
                    /// The mapping between constraint types and powers of alpha
                    //                    std::map<ArgumentType, std::pair<uint32_t, uint32_t>> mapping;
                    /// The powers of alpha: 1, alpha, alpha^2, etc.
                    /// If set to [Some], you can't register new constraints.
                    std::vector<FieldType> alphas;

                    // Create alphas from 0 to next_power - 1
                    void instantiate(FieldType alpha) {
                        FieldType last_power = FieldType::one();
                        alphas.resize(next_power);
                        alphas[0] = last_power;
                        for (size_t i = 0; i < next_power; ++i) {
                            last_power *= alpha;
                            alphas[i + 1] = last_power;
                        }
                    }

                    // Return num alphas
                    std::vector<FieldType> get_alphas(uint32_t num) {
                        BOOST_ASSERT_MSG(num <= alphas.size(), "Not enough alphas to return");
                        return std::vector(alphas.begin(), alphas.begin() + num);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
};               // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_ALPHAS_HPP
