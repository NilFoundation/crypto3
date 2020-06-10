//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SECURE_MEMORY_BUFFERS_HPP
#define CRYPTO3_SECURE_MEMORY_BUFFERS_HPP

#include <nil/crypto3/detail/secure_allocator.hpp>

#include <vector>
#include <algorithm>
#include <deque>
#include <type_traits>

namespace nil {
    namespace crypto3 {
        namespace detail {
            template<typename T>
            using secure_vector = std::vector<T, secure_allocator<T>>;
            template<typename T>
            using secure_deque = std::deque<T, secure_allocator<T>>;

            template<typename T>
            std::vector<T> unlock(const secure_vector<T> &in) {
                std::vector<T> out(in.size());
                copy_mem(out.data(), in.data(), in.size());
                return out;
            }

            template<typename T, typename Alloc>
            size_t buffer_insert(std::vector<T, Alloc> &buf, size_t buf_offset, const T input[], size_t input_length) {
                BOOST_ASSERT(buf_offset <= buf.size());
                const size_t to_copy = std::min(input_length, buf.size() - buf_offset);
                if (to_copy > 0) {
                    copy_mem(&buf[buf_offset], input, to_copy);
                }
                return to_copy;
            }

            template<typename T, typename Alloc, typename Alloc2>
            size_t buffer_insert(std::vector<T, Alloc> &buf, size_t buf_offset, const std::vector<T, Alloc2> &input) {
                BOOST_ASSERT(buf_offset <= buf.size());
                const size_t to_copy = std::min(input.size(), buf.size() - buf_offset);
                if (to_copy > 0) {
                    copy_mem(&buf[buf_offset], input.data(), to_copy);
                }
                return to_copy;
            }

            template<typename T, typename Alloc, typename Alloc2>
            std::vector<T, Alloc> &operator+=(std::vector<T, Alloc> &out, const std::vector<T, Alloc2> &in) {
                const size_t copy_offset = out.size();
                out.resize(out.size() + in.size());
                if (in.size() > 0) {
                    copy_mem(&out[copy_offset], in.data(), in.size());
                }
                return out;
            }

            template<typename T, typename Alloc>
            std::vector<T, Alloc> &operator+=(std::vector<T, Alloc> &out, T in) {
                out.push_back(in);
                return out;
            }

            template<typename T, typename Alloc, typename L>
            std::vector<T, Alloc> &operator+=(std::vector<T, Alloc> &out, const std::pair<const T *, L> &in) {
                const size_t copy_offset = out.size();
                out.resize(out.size() + in.second);
                if (in.second > 0) {
                    copy_mem(&out[copy_offset], in.first, in.second);
                }
                return out;
            }

            template<typename T, typename Alloc, typename L>
            std::vector<T, Alloc> &operator+=(std::vector<T, Alloc> &out, const std::pair<T *, L> &in) {
                const size_t copy_offset = out.size();
                out.resize(out.size() + in.second);
                if (in.second > 0) {
                    copy_mem(&out[copy_offset], in.first, in.second);
                }
                return out;
            }

            /**
             * Zeroise the values; length remains unchanged
             * @param vec the vector to zeroise
             */
            template<typename T, typename Alloc>
            void zeroise(std::vector<T, Alloc> &vec) {
                clear_mem(vec.data(), vec.size());
            }

            /**
             * Zeroise the values then free the memory
             * @param vec the vector to zeroise and free
             */
            template<typename T, typename Alloc>
            void zap(std::vector<T, Alloc> &vec) {
                zeroise(vec);
                vec.clear();
                vec.shrink_to_fit();
            }
        }   // namespace detail
    }    // namespace crypto3
}    // namespace nil

#endif
