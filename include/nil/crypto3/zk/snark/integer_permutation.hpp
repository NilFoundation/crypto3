//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ZK_SNARK_INTEGER_PERMUTATION_HPP
#define CRYPTO3_ZK_SNARK_INTEGER_PERMUTATION_HPP

#include <algorithm>
#include <cstddef>
#include <vector>
#include <unordered_set>
#include <numeric>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                class integer_permutation {
                private:
                    std::vector<std::size_t> contents; /* offset by min_element */

                public:
                    std::size_t min_element;
                    std::size_t max_element;

                    integer_permutation(const std::size_t size = 0) : min_element(0), max_element(size - 1) {
                        contents.resize(size);
                        std::iota(contents.begin(), contents.end(), 0);
                    }
                    integer_permutation(const std::size_t min_element, const std::size_t max_element) :
                        min_element(min_element), max_element(max_element) {
                        assert(min_element <= max_element);
                        const std::size_t size = max_element - min_element + 1;
                        contents.resize(size);
                        std::iota(contents.begin(), contents.end(), min_element);
                    }

                    integer_permutation &operator=(const integer_permutation &other) = default;

                    std::size_t size() const {
                        return max_element - min_element + 1;
                    }

                    std::vector<std::size_t> &data() {
                        return contents;
                    }

                    const std::vector<std::size_t> &data() const {
                        return contents;
                    }

                    bool operator==(const integer_permutation &other) const {
                        return (this->min_element == other.min_element && this->max_element == other.max_element &&
                                this->contents == other.contents);
                    }

                    void set(const std::size_t position, const std::size_t value) {
                        assert(min_element <= position && position <= max_element);
                        contents[position - min_element] = value;
                    }
                    std::size_t get(const std::size_t position) const {
                        assert(min_element <= position && position <= max_element);
                        return contents[position - min_element];
                    }

                    bool is_valid() const {
                        std::unordered_set<std::size_t> elems;

                        for (auto &el : contents) {
                            if (el < min_element || el > max_element || elems.find(el) != elems.end()) {
                                return false;
                            }

                            elems.insert(el);
                        }

                        return true;
                    }

                    integer_permutation inverse() const {
                        integer_permutation result(min_element, max_element);

                        for (std::size_t position = min_element; position <= max_element; ++position) {
                            result.contents[this->contents[position - min_element] - min_element] = position;
                        }

#ifdef DEBUG
                        assert(result.is_valid());
#endif

                        return result;
                    }

                    integer_permutation slice(const std::size_t slice_min_element,
                                              const std::size_t slice_max_element) const {
                        assert(min_element <= slice_min_element && slice_min_element <= slice_max_element &&
                               slice_max_element <= max_element);
                        integer_permutation result(slice_min_element, slice_max_element);
                        std::copy(this->contents.begin() + (slice_min_element - min_element),
                                  this->contents.begin() + (slice_max_element - min_element) + 1,
                                  result.contents.begin());
#ifdef DEBUG
                        assert(result.is_valid());
#endif

                        return result;
                    }

                    /* Similarly to std::next_permutation this transforms the current
                    integer permutation into the next lexicographically ordered
                    permutation; returns false if the last permutation was reached and
                    this is now the identity permutation on [min_element .. max_element] */
                    bool next_permutation() {
                        return std::next_permutation(contents.begin(), contents.end());
                    }

                    void random_shuffle() {
                        return std::random_shuffle(contents.begin(), contents.end());
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SNARK_INTEGER_PERMUTATION_HPP
