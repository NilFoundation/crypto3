//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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


#ifndef FILECOIN_VEC_HPP
#define FILECOIN_VEC_HPP

#include <vector>

#include <nil/filecoin/storage/proofs/core/merkle/storage/utilities.hpp>

namespace nil {
    namespace filecoin {
        namespace storage {
            struct VecStore : public Store {
                VecStore(size_t size, size_t branches, utilities::StoreConfig config) {
                    v.resize(size);
                    store_size = size;
                    len = 0;
                }

                VecStore(size_t size) {
                    v.resize(size);
                    store_size = size;
                    len = 0;
                }

                void write(std::pair<uint8_t *, uint8_t *> el, size_t start) {
                    if (this->len < write + (el.second - el.first)) {
                        v.resize(write + (el.second - el.first));
                    }
                    for (auto i = el.first; i < el.second; ++i) {
                        v[write] = i;
                        ++write;
                    }
                    len += (el.second - el.first);
                }

                VecStore(size_t size, size_t branches, std::pair<uint8_t *, uint8_t *> data, utilities::StoreConfig config) {
                    v.resize(size);
                    store_size = size;
                    self->write(data, 0);
                }

                VecStore(size_t size, std::pair<uint8_t *, uint8_t *> data) {
                    v.resize(size);
                    store_size = size;
                    self->write(data, 0);
                }

                void read(std::pair<size_t, size_t> read, uint8_t *buf) {
                    uint8_t *buf_ptr = buf;
                    for (size_t i = read.first; i < read.second; ++i) {
                        buf_ptr = v[i];
                        ++buf_ptr;
                    }
                }

                bool loaded_from_disk() {
                    return false;
                }

                bool compact(size_t branches, utilities::StoreConfig config, uint32_t store_version) {
                    v.resize(len);
                    return true;
                }

                bool is_empty() {
                    return v.empty();
                }

                void push(std::pair<uint8_t *, uint8_t *> data) {
                    self->write(data, len);
                }
            private:
                size_t len;
                size_t store_size;
                std::vector<uint8_t> v;
            };
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_VEC_HPP
