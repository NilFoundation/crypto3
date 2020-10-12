//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MEMORY_OPERATIONS_HPP
#define CRYPTO3_MEMORY_OPERATIONS_HPP

#include <cstring>
#include <vector>

#ifdef CRYPTO3_HAS_LOCKING_ALLOCATOR

#include <nil/crypto3/block/detail/utilities/locking_allocator.hpp>

#endif

namespace nil {
    namespace crypto3 {

        /**
         * Allocate a memory buffer by some method. This should only be used for
         * primitive types (uint8_t, uint32_t, etc).
         *
         * @param elems the number of elements
         * @param elem_size the size of each element
         * @return pointer to allocated and zeroed memory, or throw std::bad_alloc on failure
         */
        BOOST_ATTRIBUTE_MALLOC_FUNCTION void *allocate_memory(size_t elems, size_t elem_size) {
#if defined(CRYPTO3_HAS_LOCKING_ALLOCATOR)
            if (void *p = mlock_allocator::instance().allocate(elems, elem_size)) {
                return p;
            }
#endif

            void *ptr = std::calloc(elems, elem_size);
            if (!ptr) {
                throw std::bad_alloc();
            }
            return ptr;
        }

        /**
         * Scrub memory contents in a way that a compiler should not elide,
         * using some system specific technique. Note that this function might
         * not zero the memory (for example, in some hypothetical
         * implementation it might combine the memory contents with the output
         * of a system PRNG), but if you can detect any difference in behavior
         * at runtime then the clearing is side-effecting and you can just
         * use `clear_mem`.
         *
         * Use this function to scrub memory just before deallocating it, or on
         * a stack buffer before returning from the function.
         *
         * @param ptr a pointer to memory to scrub
         * @param n the number of bytes pointed to by ptr
         */
        void secure_scrub_memory(void *ptr, size_t n) {
#if defined(CRYPTO3_TARGET_OS_HAS_RTLSECUREZEROMEMORY)
            ::RtlSecureZeroMemory(ptr, n);

#elif defined(CRYPTO3_TARGET_OS_HAS_EXPLICIT_BZERO)
            ::explicit_bzero(ptr, n);

#elif defined(CRYPTO3_USE_VOLATILE_MEMSET_FOR_ZERO) && (CRYPTO3_USE_VOLATILE_MEMSET_FOR_ZERO == 1)
            /*
             * Call memset through a static volatile pointer, which the compiler
             * should not elide. This construct should be safe in conforming
             * compilers, but who knows. I did confirm that on x86-64 GCC 6.1 and
             * Clang 3.8 both create code that saves the memset address in the
             * data segment and uncondtionally loads and jumps to that address.
             */
            static void *(*const volatile memset_ptr)(void *, int, size_t) = std::memset;
            (memset_ptr)(ptr, 0, n);
#else

            volatile uint8_t *p = reinterpret_cast<volatile uint8_t *>(ptr);

            for (size_t i = 0; i != n; ++i) {
                p[i] = 0;
            }
#endif
        }

        /**
         * Free a pointer returned by allocate_memory
         * @param p the pointer returned by allocate_memory
         * @param elems the number of elements, as passed to allocate_memory
         * @param elem_size the size of each element, as passed to allocate_memory
         */
        void deallocate_memory(void *p, size_t elems, size_t elem_size) {
            if (p == nullptr) {
                return;
            }

            secure_scrub_memory(p, elems * elem_size);

#if defined(CRYPTO3_HAS_LOCKING_ALLOCATOR)
            if (mlock_allocator::instance().deallocate(p, elems, elem_size)) {
                return;
            }
#endif

            std::free(p);
        }

        /**
         * Ensure the allocator is initialized
         */
        void initialize_allocator() {
#if defined(CRYPTO3_HAS_LOCKING_ALLOCATOR)
            mlock_allocator::instance();
#endif
        }

        /**
         * Memory comparison, input insensitive
         * @param x a pointer to an array
         * @param y a pointer to another array
         * @param len the number of Ts in x and y
         * @return true iff x[i] == y[i] forall i in [0...n)
         */

        bool constant_time_compare(const uint8_t x[], const uint8_t y[], size_t len) {
            volatile uint8_t difference = 0;

            for (size_t i = 0; i != len; ++i) {
                difference |= (x[i] ^ y[i]);
            }

            return difference == 0;
        }

        /**
         * Zero out some bytes
         * @param ptr a pointer to memory to zero
         * @param bytes the number of bytes to zero in ptr
         */
        inline void clear_bytes(void *ptr, size_t bytes) {
            if (bytes > 0) {
                std::memset(ptr, 0, bytes);
            }
        }

        /**
         * Zero memory before use. This simply calls memset and should not be
         * used in cases where the compiler cannot see the call as a
         * side-effecting operation (for example, if calling clear_mem before
         * deallocating memory, the compiler would be allowed to omit the call
         * to memset entirely under the as-if rule.)
         *
         * @param ptr a pointer to an array of Ts to zero
         * @param n the number of Ts pointed to by ptr
         */
        template<typename T>
        inline void clear_mem(T *ptr, size_t n) {
            clear_bytes(ptr, sizeof(T) * n);
        }

        /**
         * Copy memory
         * @param out the destination array
         * @param in the source array
         * @param n the number of elements of in/out
         */
        template<typename T>
        inline void copy_mem(T *out, const T *in, size_t n) {
            if (n > 0) {
                std::memmove(out, in, sizeof(T) * n);
            }
        }

        /**
         * Set memory to a fixed value
         * @param ptr a pointer to an array
         * @param n the number of Ts pointed to by ptr
         * @param val the value to set each byte to
         */
        template<typename T>
        inline void set_mem(T *ptr, size_t n, uint8_t val) {
            if (n > 0) {
                std::memset(ptr, val, sizeof(T) * n);
            }
        }

        inline const uint8_t *cast_char_ptr_to_uint8(const char *s) {
            return reinterpret_cast<const uint8_t *>(s);
        }

        inline const char *cast_uint8_ptr_to_char(const uint8_t *b) {
            return reinterpret_cast<const char *>(b);
        }

        inline uint8_t *cast_char_ptr_to_uint8(char *s) {
            return reinterpret_cast<uint8_t *>(s);
        }

        inline char *cast_uint8_ptr_to_char(uint8_t *b) {
            return reinterpret_cast<char *>(b);
        }

        /**
         * Memory comparison, input insensitive
         * @param p1 a pointer to an array
         * @param p2 a pointer to another array
         * @param n the number of Ts in p1 and p2
         * @return true iff p1[i] == p2[i] forall i in [0...n)
         */
        template<typename T>
        inline bool same_mem(const T *p1, const T *p2, size_t n) {
            volatile T difference = 0;

            for (size_t i = 0; i != n; ++i) {
                difference |= (p1[i] ^ p2[i]);
            }

            return difference == 0;
        }

        /**
         * XOR arrays. Postcondition out[i] = in[i] ^ out[i] forall i = 0...length
         * @param out the input/output buffer
         * @param in the read-only input buffer
         * @param length the length of the buffers
         */
        inline void xor_buf(uint8_t out[], const uint8_t in[], size_t length) {
            while (length >= 16) {
                uint64_t x0, x1, y0, y1;
                std::memcpy(&x0, in, 8);
                std::memcpy(&x1, in + 8, 8);
                std::memcpy(&y0, out, 8);
                std::memcpy(&y1, out + 8, 8);

                y0 ^= x0;
                y1 ^= x1;
                std::memcpy(out, &y0, 8);
                std::memcpy(out + 8, &y1, 8);
                out += 16;
                in += 16;
                length -= 16;
            }

            while (length > 0) {
                out[0] ^= in[0];
                out += 1;
                in += 1;
                length -= 1;
            }
        }

        /**
         * XOR arrays. Postcondition out[i] = in[i] ^ in2[i] forall i = 0...length
         * @param out the output buffer
         * @param in the first input buffer
         * @param in2 the second output buffer
         * @param length the length of the three buffers
         */
        inline void xor_buf(uint8_t out[], const uint8_t in[], const uint8_t in2[], size_t length) {
            while (length >= 16) {
                uint64_t x0, x1, y0, y1;
                std::memcpy(&x0, in, 8);
                std::memcpy(&x1, in + 8, 8);
                std::memcpy(&y0, in2, 8);
                std::memcpy(&y1, in2 + 8, 8);

                x0 ^= y0;
                x1 ^= y1;
                std::memcpy(out, &x0, 8);
                std::memcpy(out + 8, &x1, 8);
                out += 16;
                in += 16;
                in2 += 16;
                length -= 16;
            }

            for (size_t i = 0; i != length; ++i) {
                out[i] = in[i] ^ in2[i];
            }
        }

        template<typename Alloc, typename Alloc2>
        void xor_buf(std::vector<uint8_t, Alloc> &out, const std::vector<uint8_t, Alloc2> &in, size_t n) {
            xor_buf(out.data(), in.data(), n);
        }

        template<typename Alloc>
        void xor_buf(std::vector<uint8_t, Alloc> &out, const uint8_t *in, size_t n) {
            xor_buf(out.data(), in, n);
        }

        template<typename Alloc, typename Alloc2>
        void xor_buf(std::vector<uint8_t, Alloc> &out, const uint8_t *in, const std::vector<uint8_t, Alloc2> &in2,
                     size_t n) {
            xor_buf(out.data(), in, in2.data(), n);
        }

        template<typename Alloc, typename Alloc2>
        std::vector<uint8_t, Alloc> &operator^=(std::vector<uint8_t, Alloc> &out,
                                                const std::vector<uint8_t, Alloc2> &in) {
            if (out.size() < in.size()) {
                out.resize(in.size());
            }

            xor_buf(out.data(), in.data(), in.size());
            return out;
        }
    }    // namespace crypto3
}    // namespace nil

#endif