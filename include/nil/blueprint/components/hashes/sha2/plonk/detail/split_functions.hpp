//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the SHA512_PROCESS component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA2_SPLIT_FUNCTIONS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA2_SPLIT_FUNCTIONS_HPP

#include <vector>
#include <array>
#include <map>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                template <typename BlueprintFieldType>
                std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> split_and_sparse(
                    const std::vector<bool> &bits, const std::vector<std::size_t> &sizes, std::size_t base) {
                    using integral_type = typename BlueprintFieldType::integral_type;

                    const std::size_t size = sizes.size() - 1;
                    std::array<std::vector<integral_type>, 2> res = {
                        std::vector<integral_type>(size + 1),
                        std::vector<integral_type>(size + 1)
                    };
                    std::size_t k = 0;
                    for (int i = size; i > -1; i--) {
                        res[0][i] = int(bits[k]);
                        res[1][i] = int(bits[k]);
                        for (std::size_t j = 1; j < sizes[i]; j++) {
                            res[0][i] = res[0][i] * 2 + int(bits[k + j]);
                            res[1][i] = res[1][i] * base + int(bits[k + j]);
                        }
                        k = k + sizes[i];
                    }
                    return res;
                }

                template <typename BlueprintFieldType>
                inline typename BlueprintFieldType::integral_type cached_pow(
                        const std::size_t base, const std::size_t k) {

                    using integral_type = typename BlueprintFieldType::integral_type;
                    using value_type = typename BlueprintFieldType::value_type;
                    static std::map<std::pair<std::size_t, std::size_t>, integral_type> cache;
                    const auto pair = std::make_pair(base, k);
                    if (cache.find(pair) == cache.end()) {  [[unlikely]]
                        cache[pair] = integral_type(value_type(base).pow(k).data);
                    }
                    return cache[pair];
                }

                template <typename BlueprintFieldType>
                std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                    reversed_sparse_and_split(const typename BlueprintFieldType::integral_type sparse_value,
                                              const std::vector<std::size_t> &sizes, std::size_t base) {
                    using integral_type = typename BlueprintFieldType::integral_type;
                    using value_type = typename BlueprintFieldType::value_type;
                    std::size_t size = sizes.size();
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> res = {
                        std::vector<integral_type>(size),
                        std::vector<integral_type>(size)
                    };
                    const integral_type sparse_base = base;
                    std::size_t k = -1;
                    for (int i = sizes.size() - 1; i > -1; i--) {
                        k = k + sizes[i];
                    }
                    integral_type tmp = sparse_value;
                    for (int i = sizes.size() - 1; i > -1; i--) {
                        res[0][i] = 0;
                        res[1][i] = 0;
                        for (int j = sizes[i] - 1; j > -1; j--) {
                            const integral_type k_pow = cached_pow<BlueprintFieldType>(base, k);
                            integral_type r;
                            divide_qr(tmp, k_pow, r, tmp);
                            res[0][i] = res[0][i] * 2 + (r&1);
                            res[1][i] = res[1][i] * sparse_base + r;
                            k--;
                        }
                    }
                    return res;
                }

                template <typename BlueprintFieldType>
                std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                    reversed_sparse_and_split_maj(const typename BlueprintFieldType::integral_type sparse_value,
                                              const std::vector<std::size_t> &sizes, std::size_t base) {
                    using integral_type = typename BlueprintFieldType::integral_type;
                    using value_type = typename BlueprintFieldType::value_type;

                    std::size_t size = sizes.size();
                    std::array<std::vector<integral_type>, 2> res = {
                        std::vector<integral_type>(size),
                        std::vector<integral_type>(size)};
                    integral_type sparse_base = base;
                    std::size_t k = -1;
                    for (int i = sizes.size() - 1; i > -1; i--) {
                        k = k + sizes[i];
                    }
                    const std::array<std::size_t, 4> r_values = {0,0,1,1};
                    integral_type tmp = sparse_value;
                    for (int i = sizes.size() - 1; i > -1; i--) {
                        res[0][i] = 0;
                        res[1][i] = 0;
                        for (int j = sizes[i] - 1; j > -1; j--) {
                            const integral_type k_pow = cached_pow<BlueprintFieldType>(base, k);
                            integral_type r;
                            divide_qr(tmp, k_pow, r, tmp);
                            res[0][i] = res[0][i] * 2 + r_values[std::size_t(r)];
                            res[1][i] = res[1][i] * sparse_base + r;
                            k--;
                        }
                    }
                    return res;
                }

                template <typename BlueprintFieldType>
                std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                    reversed_sparse_and_split_ch(const typename BlueprintFieldType::integral_type sparse_value,
                                              const std::vector<std::size_t> &sizes, std::size_t base) {
                    using integral_type = typename BlueprintFieldType::integral_type;
                    using value_type = typename BlueprintFieldType::value_type;

                    std::size_t size = sizes.size();
                    std::array<std::vector<integral_type>, 2> res = {
                        std::vector<integral_type>(size),
                        std::vector<integral_type>(size)};
                    integral_type sparse_base = base;
                    std::size_t k = -1;
                    for (int i = sizes.size() - 1; i > -1; i--) {
                        k = k + sizes[i];
                    }
                    std::array<std::size_t, 7> r_values = {0, 0,0,1,0,1,1};
                    integral_type tmp = sparse_value;
                    for (int i = sizes.size() - 1; i > -1; i--) {
                        res[0][i] = 0;
                        res[1][i] = 0;
                        for (int j = sizes[i] - 1; j > -1; j--) {
                            const integral_type k_pow = cached_pow<BlueprintFieldType>(base, k);
                            integral_type r;
                            divide_qr(tmp, k_pow, r, tmp);
                            res[0][i] = res[0][i] * 2 + r_values[std::size_t(r)];
                            res[1][i] = res[1][i] * sparse_base + r;
                            k--;
                        }
                    }
                    return res;
                }
            }   // namespace detail
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA2_SPLIT_FUNCTIONS_HPP
