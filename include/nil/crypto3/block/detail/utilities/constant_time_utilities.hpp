//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_CONSTANT_TIME_UTILS_HPP
#define CRYPTO3_BLOCK_CONSTANT_TIME_UTILS_HPP

namespace nil {
    namespace crypto3 {
        namespace detail {
            /**
             * Use valgrind to mark the contents of memory as being undefined.
             * Valgrind will accept operations which manipulate undefined values,
             * but will warn if an undefined value is used to decided a conditional
             * jump or a load/store address. So if we poison all of our inputs we
             * can confirm that the operations in question are truly const time
             * when compiled by whatever compiler is in use.
             *
             * Even better, the VALGRIND_MAKE_MEM_* macros work even when the
             * program is not run under valgrind (though with a few cycles of
             * overhead, which is unfortunate in final binaries as these
             * annotations tend to be used in fairly important loops).
             *
             * This approach was first used in ctgrind (https://github.com/agl/ctgrind)
             * but calling the valgrind mecheck API directly works just as well and
             * doesn't require a custom patched valgrind.
             */
            template<typename T>
            inline void poison(const T *p, size_t n) {
#if defined(CRYPTO3_HAS_VALGRIND)
                VALGRIND_MAKE_MEM_UNDEFINED(p, n * sizeof(T));
#endif
            }

            template<typename T>
            inline void unpoison(const T *p, size_t n) {
#if defined(CRYPTO3_HAS_VALGRIND)
                VALGRIND_MAKE_MEM_DEFINED(p, n * sizeof(T));
#endif
            }

            template<typename T>
            inline void unpoison(T &p) {
#if defined(CRYPTO3_HAS_VALGRIND)
                VALGRIND_MAKE_MEM_DEFINED(&p, sizeof(T));
#endif
            }

            /*
             * T should be an unsigned machine integer type
             * Expand to a mask used for other operations
             * @param in an integer
             * @return If n is zero, returns zero. Otherwise
             * returns a T with all bits set for use as a mask with
             * select.
             */
            template<typename T>
            inline T expand_mask(T x) {
                T r = x;
                // First fold r down to a single bit
                for (size_t i = 1; i != sizeof(T) * 8; i *= 2) {
                    r = r | static_cast<T>(r >> i);
                }
                r &= 1;
                r = static_cast<T>(~(r - 1));
                return r;
            }

            template<typename T>
            inline T expand_top_bit(T a) {
                return expand_mask<T>(a >> (sizeof(T) * 8 - 1));
            }

            template<typename T>
            inline T select(T mask, T from0, T from1) {
                return static_cast<T>((from0 & mask) | (from1 & ~mask));
            }

            template<typename PredT, typename ValT>
            inline ValT val_or_zero(PredT pred_val, ValT val) {
                return select(expand_mask<ValT>(pred_val), val, static_cast<ValT>(0));
            }

            template<typename T>
            inline T is_zero(T x) {
                return static_cast<T>(~expand_mask(x));
            }

            template<typename T>
            inline T is_equal(T x, T y) {
                return is_zero<T>(x ^ y);
            }

            template<typename T>
            inline T is_less(T a, T b) {
                return expand_top_bit<T>(a ^ ((a ^ b) | ((a - b) ^ a)));
            }

            template<typename T>
            inline T is_lte(T a, T b) {
                return is_less(a, b) | is_equal(a, b);
            }

            template<typename T>
            inline void conditional_copy_mem(T value, T *to, const T *from0, const T *from1, size_t elems) {
                const T mask = expand_mask(value);

                for (size_t i = 0; i != elems; ++i) {
                    to[i] = select(mask, from0[i], from1[i]);
                }
            }

            template<typename T>
            inline void cond_zero_mem(T cond, T *array, size_t elems) {
                const T mask = expand_mask(cond);
                const T zero(0);

                for (size_t i = 0; i != elems; ++i) {
                    array[i] = select(mask, zero, array[i]);
                }
            }

            template<typename InputIterator, typename OutputIterator>
            inline InputIterator strip_leading_zeros(InputIterator first, InputIterator last) {
                size_t leading_zeros = 0;

                uint8_t only_zeros = 0xFF;

                while (first != last) {
                    only_zeros = only_zeros & is_zero<uint8_t>(*first);
                    leading_zeros += select<uint8_t>(only_zeros, 1, 0);
                    ++first;
                }

                return first + leading_zeros;
            }
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif