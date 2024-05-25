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

#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <unordered_map>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                enum argument_type;

                template<typename FieldType>
                struct Alphas {
                    /// The next power of alpha to use
                    /// the end result will be [1, alpha^{next_power - 1}]
                    int next_power;
                    /// The mapping between constraint types and powers of alpha
                    //                    std::map<argument_type, std::pair<uint32_t, uint32_t>> mapping;
                    /// The powers of alpha: 1, alpha, alpha^2, etc.
                    /// If set to [Some], you can't register new constraints.
                    std::vector<typename FieldType::value_type> alphas;
                    std::unordered_map<argument_type, std::pair<int, int>> mapping; 

                    Alphas() : next_power(0) {}
                    // Create alphas from 0 to next_power - 1

                    void register_(argument_type arg, int power){
                        if(mapping.find(arg) == mapping.end()){
                            mapping[arg] = std::make_pair(next_power, power);
                        }
                        
                        next_power += power;
                    }

                    void instantiate(typename FieldType::value_type alpha) {
                        typename FieldType::value_type last_power = FieldType::value_type::one();
                        alphas.clear();
                        alphas.reserve(next_power);
                        alphas.push_back(last_power);
                        for (size_t i = 1; i < next_power; ++i) {
                            alphas.push_back(alphas.back() * alpha);
                            // last_power *= alpha;
                            // alphas[i + 1] = last_power;
                        }
                    }

                    // Return num alphas
                    std::vector<typename FieldType::value_type> get_alphas(argument_type arg, std::size_t num) {
                        if(mapping.find(arg) == mapping.end()){
                            assert(false);
                        }
                        std::pair<int, int> range = mapping[arg];
                        BOOST_ASSERT_MSG(num <= range.second, "Not enough alphas to return");

                        return std::vector(alphas.begin() + range.first, alphas.begin() + range.first + num);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
};               // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_ALPHAS_HPP
