#ifndef CRYPTO3_ASSERTION_CHECKING_HPP
#define CRYPTO3_ASSERTION_CHECKING_HPP

#include <nil/crypto3/build.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {

#if defined(CRYPTO3_ENABLE_DEBUG_ASSERTS)

#define CRYPTO3_DEBUG_ASSERT(expr) BOOST_ASSERT(expr)

#else

#define CRYPTO3_DEBUG_ASSERT(expr) \
        do {                           \
        } while (0)

#endif

    /**
     * Mark variable as unused. Takes between 1 and 9 arguments and marks all as unused,
     * e.g. CRYPTO3_UNUSED(a); or CRYPTO3_UNUSED(x, y, z);
     */
    #define _CRYPTO3_UNUSED_IMPL1(a) static_cast<void>(a)
    #define _CRYPTO3_UNUSED_IMPL2(a, b) \
        static_cast<void>(a);           \
        _CRYPTO3_UNUSED_IMPL1(b)
    #define _CRYPTO3_UNUSED_IMPL3(a, b, c) \
        static_cast<void>(a);              \
        _CRYPTO3_UNUSED_IMPL2(b, c)
    #define _CRYPTO3_UNUSED_IMPL4(a, b, c, d) \
        static_cast<void>(a);                 \
        _CRYPTO3_UNUSED_IMPL3(b, c, d)
    #define _CRYPTO3_UNUSED_IMPL5(a, b, c, d, e) \
        static_cast<void>(a);                    \
        _CRYPTO3_UNUSED_IMPL4(b, c, d, e)
    #define _CRYPTO3_UNUSED_IMPL6(a, b, c, d, e, f) \
        static_cast<void>(a);                       \
        _CRYPTO3_UNUSED_IMPL5(b, c, d, e, f)
    #define _CRYPTO3_UNUSED_IMPL7(a, b, c, d, e, f, g) \
        static_cast<void>(a);                          \
        _CRYPTO3_UNUSED_IMPL6(b, c, d, e, f, g)
    #define _CRYPTO3_UNUSED_IMPL8(a, b, c, d, e, f, g, h) \
        static_cast<void>(a);                             \
        _CRYPTO3_UNUSED_IMPL7(b, c, d, e, f, g, h)
    #define _CRYPTO3_UNUSED_IMPL9(a, b, c, d, e, f, g, h, i) \
        static_cast<void>(a);                                \
        _CRYPTO3_UNUSED_IMPL8(b, c, d, e, f, g, h, i)
    #define _CRYPTO3_UNUSED_GET_IMPL(_1, _2, _3, _4, _5, _6, _7, _8, _9, IMPL_NAME, ...) IMPL_NAME

    #define CRYPTO3_UNUSED(...)                                                                                    \
        _CRYPTO3_UNUSED_GET_IMPL(__VA_ARGS__, _CRYPTO3_UNUSED_IMPL9, _CRYPTO3_UNUSED_IMPL8, _CRYPTO3_UNUSED_IMPL7, \
                                 _CRYPTO3_UNUSED_IMPL6, _CRYPTO3_UNUSED_IMPL5, _CRYPTO3_UNUSED_IMPL4,              \
                                 _CRYPTO3_UNUSED_IMPL3, _CRYPTO3_UNUSED_IMPL2, _CRYPTO3_UNUSED_IMPL1,              \
                                 unused dummy rest value)                                                          \
        /* we got an one of _CRYPTO3_UNUSED_IMPL*, now call it */ (__VA_ARGS__)
        }    // namespace detail
    }    // namespace crypto3
}    // namespace nil

#endif
