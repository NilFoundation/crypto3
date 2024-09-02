//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <unordered_map>
#include <list>
#include <algorithm>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                // Implementing [https://arxiv.org/pdf/1907.04505.pdf]
                // 11/9 approximation ratio
                std::unordered_map<std::size_t, std::size_t> huang_lu(
                        std::list<std::pair<std::size_t, std::size_t>> &sizes,
                        std::size_t agent_amount) {
                    sizes.sort(
                        [](const std::pair<std::size_t, std::size_t> &a,
                           const std::pair<std::size_t, std::size_t> &b) {
                            return a.second > b.second;
                        }
                    );
                    std::size_t max_item = 0,
                                sum = 0;
                    for (auto [key, item] : sizes) {
                        max_item = std::max(max_item, item);
                        sum += item;
                    }
                    std::size_t left = std::max((sum + agent_amount - 1) / agent_amount,
                                                max_item);
                    std::size_t right = 2 * left;
                    std::unordered_map<std::size_t, std::size_t> best_assignment;
                    std::unordered_map<std::size_t, std::size_t> assignment;
                    std::list<std::pair<std::size_t, std::size_t>> tasks_remaning;
                    while (left < right) {
                        std::size_t threshold = left + (right - left) / 2;
                        tasks_remaning = sizes;

                        for (std::size_t i = 0; i < agent_amount; i++) {
                            std::size_t curr_bundle_size = 0;
                            for (auto it = tasks_remaning.begin();
                                it != tasks_remaning.end();) {

                                if (curr_bundle_size + it->second <= threshold) {
                                    assignment[it->first] = i;
                                    curr_bundle_size += it->second;
                                    it = tasks_remaning.erase(it);
                                } else {
                                    it++;
                                }
                            }
                            if (curr_bundle_size == 0) {
                                break;
                            }
                        }
                        if (tasks_remaning.size() == 0) {
                            right = threshold;
                            best_assignment = assignment;
                        } else {
                            left = threshold + 1;
                        }

                        if (threshold == left) {
                            break;
                        }
                    }
                    return best_assignment;
                }
            }   // namespace detail
        }       // namespace components
    }           // namespace blueprint
}   // namespace nil