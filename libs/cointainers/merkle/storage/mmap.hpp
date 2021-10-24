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

#include <boost/filesystem.hpp>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

namespace nil {
    namespace filecoin {
        namespace storage {
            struct storage {
                virtual uint8_t const *read(uint64_t begin, uint64_t length, uint8_t *memcache = nullptr) = 0;
                virtual void write(uint64_t begin, const uint8_t *memcache, uint64_t length) = 0;
                virtual void resize(uint64_t new_size) = 0;
                virtual std::string name() = 0;
                virtual size_t size() = 0;
                virtual void free() = 0;
                virtual void close() = 0;
                virtual ~storage() = default;
            };

            struct mmap_storage : public storage {
                explicit mmap_storage(const boost::filesystem::path &filename,
                                      boost::interprocess::mode_t mod = boost::interprocess::read_write,
                                      const std::size_t file_size = 0) {
                    filename_ = filename;
                    mod_ = mod;
                    alloc_space(file_size, !boost::filesystem::exists(filename));
                    if (file_size != 0) {
                        open(mod);
                    }
                }

                void alloc_space(const std::size_t file_size, const bool truncate = false) {
                    std::filebuf fbuf;
                    std::ios_base::openmode open_flags = std::ios_base::in | std::ios_base::out | std::ios_base::binary;
                    if (truncate)
                        open_flags |= std::ios_base::trunc;
                    fbuf.open(filename_.string().c_str(), open_flags);
                    if (file_size != 0) {
                        fbuf.pubseekoff(file_size - 1, std::ios_base::beg);
                        fbuf.sputc(0);
                    }
                    fbuf.close();
                }

                void open(boost::interprocess::mode_t mod) {
                    f_ = boost::interprocess::file_mapping(filename_.string().c_str(), mod);
                    region_ = boost::interprocess::mapped_region(f_, mod);
                    addr = region_.get_address();
                    s = region_.get_size();
                    mod_ = mod;
                }

                mmap_storage(mmap_storage &&fd) noexcept {
                    filename_ = std::move(fd.filename_);
                    addr = fd.addr;
                    s = fd.s;
                    f_ = std::move(fd.f_);
                }

                mmap_storage(const mmap_storage &) = delete;

                mmap_storage &operator=(const mmap_storage &) = delete;

                void close() override {
                    region_.flush();
                    munmap(addr, s);
                    addr = nullptr;
                    s = 0;
                }

                ~mmap_storage() {
                    close();
                }

                uint8_t const *read(uint64_t begin, uint64_t length, uint8_t *memcache) override {
                    if (addr == nullptr) {
                        open();
                    }
                    if (begin + length > s) {
                        assert(false);
                        throw invalid_value_exception("Read out of bounds");
                    }
                    memcpy(memcache, static_cast<char *>(addr) + begin, length);
                    return nullptr;
                }

                void write(uint64_t begin, const uint8_t *memcache, uint64_t length) override {
                    if (s < begin + length) {
                        resize(begin + length);
                    }
                    memcpy(static_cast<char *>(addr) + begin, memcache, length);
                }

                std::string name() override {
                    return filename_.string();
                }

                size_t size() override {
                    return s;
                }

                void resize(uint64_t new_size) override {
                    if (s == new_size) {
                        return;
                    }
                    if (new_size < s) {
                        region_.shrink_by(s - new_size, true);
                        addr = region_.get_address();
                        s = region_.get_size();
                        boost::filesystem::resize_file(filename_, new_size);
                    } else {
                        alloc_space(new_size);
                        open();
                    }
                }

                void free() override {
                    region_.flush();
                }

            private:
                boost::filesystem::path filename_;
                boost::interprocess::mod_t mod_;
                boost::interprocess::file_mapping f_;
                boost::interprocess::mapped_region region_;
                void *addr = nullptr;
                std::size_t s = 0;
            };
        }    // namespace storage
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_MMAP_HPP
