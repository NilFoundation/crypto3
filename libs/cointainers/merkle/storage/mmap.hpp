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


#ifndef FILECOIN_MMAP_HPP
#define FILECOIN_MMAP_HPP

#include <algorithm>
#include <stdio.h>
#include <vector>

#include <boost/filesystem.hpp>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>


#include <nil/filecoin/storage/proofs/core/merkle/processing/storage/utilities.hpp>

namespace nil {
    namespace filecoin {
        namespace storage {
            class MmapStore: public Store {
                MmapStore(size_t size, size_t branches, StoreConfig config, uint8_t *data = nullptr, size_t data_length = 0) {
                    boost::filesystem::path data_path = StoreConfig::data_path(&config.path_, &config.id_);
                    // If the specified file exists, load it from disk.
                    if (!boost::filesystem::exists(data_path)) {
                        std::filebuf fbuf;
                        std::ios_base::openmode open_flags = std::ios_base::in | std::ios_base::out | std::ios_base::binary;
                        fbuf.open(data_path.string().c_str(), open_flags);
                        fbuf.pubseekoff(file_size - 1, std::ios_base::beg);
                        fbuf.sputc(0);
                        fbuf.close();
                        len = 0;
                    }
                    file = boost::interprocess::file_mapping(data_path.string().c_str(), boost::interprocess::read_write);
                    map = boost::interprocess::mapped_region(file, boost::interprocess::read_write);
                    addr = map.get_address();
                    if (!boost::filesystem::exists(data_path)) {
                        len = region_.get_size();
                    }
                    store_size = region_.get_size();

                    if (data != nullptr) {
                        BOOST_ASSERT_MSG(data_length % Element::byte_len() == 0, "data size must be a multiple of {}", Element::byte_len());
                        memcpy(static_cast<char *>(addr), data, data_length);
                        len = data_length / Element::byte_len();
                    }
                }

                MmapStore(size_t size) {
                    size_t store_size = Element::byte_len() * size;
                    BOOST_BOOST_ASSERT_MSG_MSG(false, "Not valid");
                }

                void write_at(Element el, size_t index) {
                    size_t start = index * Element::byte_len();
                    memcpy(static_cast<char *>(addr) + start, el, Element::byte_len());
                    len = std::max(len, index + 1);
                }

                void copy_from_slice(uint8_t *buf, size_t start) {
                    BOOST_ASSERT_MSG(buf.len() % Element::byte_len() == 0, "buf size must be a multiple of {}", Element::byte_len());

                    size_t start = start * Element::byte_len();

                    memcpy(static_cast<char *>(addr) + start, buf, buf.len());
                
                    len = std::max(len, start + (buf.len() / Element::byte_len()));
                }

                MmapStore(size_t size, uint8_t *data) {
                    BOOST_BOOST_ASSERT_MSG_MSG(false, "Not valid");
                }

                void read(std::pair<size_t, size_t> read, uint8_t *buf) {
                    BOOST_ASSERT_MSG(read.first >= len || read.second >= len, "Invalid read range");
                    memcpy(buf, static_cast<char *>(addr) + read.first, read.second - read.first);
                }

                bool loaded_from_disk() {
                    return false;
                }

                void compact(size_t branches, StoreConfig config, uint32_t store_version) {
                    BOOST_ASSERT_MSG("Not required here");
                }

                void reinit() {
                    file = boost::interprocess::file_mapping(data_path.string().c_str(), boost::interprocess::read_write);
                    map = boost::interprocess::mapped_region(file, boost::interprocess::read_write);
                    addr = map.get_address();
                }

                bool is_empty() {
                    return this->len == 0;
                }

                void push(Element el) {
                    BOOST_ASSERT_MSG((len + 1) * Element::byte_len() <= store_size, "not enough space");
                    write_at(el, len)
                }

            private:
                boost::filesystem::path path;
                boost::interprocess::file_mapping file;
                boost::interprocess::mapped_region map;
                size_t len;
                size_t store_size;
                void *addr = nullptr;
            };
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_MMAP_HPP
