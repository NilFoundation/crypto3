//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                template <typename BlueprintFieldType>
                std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> split_and_sparse(
                    std::vector<bool> bits, const std::vector<size_t> &sizes, std::size_t base) {

                    std::size_t size = sizes.size() - 1;
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> res = {std::vector<typename BlueprintFieldType::integral_type>(size + 1),
                                                                std::vector<typename BlueprintFieldType::integral_type>(size + 1)};
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
                std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                    reversed_sparse_and_split(typename BlueprintFieldType::integral_type sparse_value,
                                              const std::vector<size_t> &sizes, std::size_t base) {
                    std::size_t size = sizes.size();
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> res = {
                        std::vector<typename BlueprintFieldType::integral_type>(size),
                        std::vector<typename BlueprintFieldType::integral_type>(size)};
                    typename BlueprintFieldType::integral_type sparse_base = base;
                    typename BlueprintFieldType::value_type value_base = base;
                    std::size_t k = -1;
                    for (int i = sizes.size() - 1; i > -1; i--) {
                        k = k + sizes[i];
                    }
                    typename BlueprintFieldType::integral_type tmp = sparse_value;
                    for (int i = sizes.size() - 1; i > -1; i--) {
                        res[0][i] = 0;
                        res[1][i] = 0;
                        for (int j = sizes[i] - 1; j > -1; j--) {
                            if (tmp > typename BlueprintFieldType::integral_type(value_base.pow(k).data) - 1) {
                                typename BlueprintFieldType::integral_type r = (tmp - (tmp % typename BlueprintFieldType::integral_type(value_base.pow(k).data))) / 
                                typename BlueprintFieldType::integral_type(value_base.pow(k).data);
                                res[0][i] = res[0][i] * 2 + (r&1);
                                res[1][i] = res[1][i] * sparse_base + r;
                            }
                            else {
                                res[0][i] = res[0][i] * 2;
                                res[1][i] = res[1][i] * sparse_base;
                            }
                            tmp = tmp % typename BlueprintFieldType::integral_type(value_base.pow(k).data);
                            k--;
                        }
                    }
                    return res;
                }

                template <typename BlueprintFieldType>
                std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                    reversed_sparse_and_split_maj(typename BlueprintFieldType::integral_type sparse_value,
                                              const std::vector<size_t> &sizes, std::size_t base) {
                    std::size_t size = sizes.size();
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> res = {
                        std::vector<typename BlueprintFieldType::integral_type>(size),
                        std::vector<typename BlueprintFieldType::integral_type>(size)};
                    typename BlueprintFieldType::integral_type sparse_base = base;
                    typename BlueprintFieldType::value_type value_base = base;
                    std::size_t k = -1;
                    for (int i = sizes.size() - 1; i > -1; i--) {
                        k = k + sizes[i];
                    }
                    std::array<std::size_t, 4> r_values = {0,0,1,1};
                    typename BlueprintFieldType::integral_type tmp = sparse_value;
                    for (int i = sizes.size() - 1; i > -1; i--) {
                        res[0][i] = 0;
                        res[1][i] = 0;
                        for (int j = sizes[i] - 1; j > -1; j--) {
                            if (tmp > typename BlueprintFieldType::integral_type(value_base.pow(k).data) - 1) {
                                typename BlueprintFieldType::integral_type r = (tmp - (tmp % typename BlueprintFieldType::integral_type(value_base.pow(k).data))) / 
                                typename BlueprintFieldType::integral_type(value_base.pow(k).data);
                                res[0][i] = res[0][i] * 2 + r_values[std::size_t(r)];
                                res[1][i] = res[1][i] * sparse_base + r;
                            }
                            else {
                                res[0][i] = res[0][i] * 2;
                                res[1][i] = res[1][i] * sparse_base;
                            }
                            tmp = tmp % typename BlueprintFieldType::integral_type(value_base.pow(k).data);
                            k--;
                        }
                    }
                    return res;
                }

                template <typename BlueprintFieldType>
                std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                    reversed_sparse_and_split_ch(typename BlueprintFieldType::integral_type sparse_value,
                                              const std::vector<size_t> &sizes, std::size_t base) {
                    std::size_t size = sizes.size();
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> res = {
                        std::vector<typename BlueprintFieldType::integral_type>(size),
                        std::vector<typename BlueprintFieldType::integral_type>(size)};
                    typename BlueprintFieldType::integral_type sparse_base = base;
                    typename BlueprintFieldType::value_type value_base = base;
                    std::size_t k = -1;
                    for (int i = sizes.size() - 1; i > -1; i--) {
                        k = k + sizes[i];
                    }
                    std::array<std::size_t, 6> r_values = {0,0,1,0,1,1};
                    typename BlueprintFieldType::integral_type tmp = sparse_value;
                    for (int i = sizes.size() - 1; i > -1; i--) {
                        res[0][i] = 0;
                        res[1][i] = 0;
                        for (int j = sizes[i] - 1; j > -1; j--) {
                            if (tmp > typename BlueprintFieldType::integral_type(value_base.pow(k).data) - 1) {
                                typename BlueprintFieldType::integral_type r = (tmp - (tmp % typename BlueprintFieldType::integral_type(value_base.pow(k).data))) / 
                                typename BlueprintFieldType::integral_type(value_base.pow(k).data);
                                res[0][i] = res[0][i] * 2 + r_values[std::size_t(r) - 1];
                                res[1][i] = res[1][i] * sparse_base + r;
                            }
                            else {
                                res[0][i] = res[0][i] * 2;
                                res[1][i] = res[1][i] * sparse_base;
                            }
                            tmp = tmp % typename BlueprintFieldType::integral_type(value_base.pow(k).data);
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
