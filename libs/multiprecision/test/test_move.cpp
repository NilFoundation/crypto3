// Copyright John Maddock 2012.

// Use, modification and distribution are subject to the
// Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt
// or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include <boost/config.hpp>
#include <vector>

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

#include "test.hpp"

unsigned allocation_count = 0;

void* (*alloc_func_ptr)(size_t);
void* (*realloc_func_ptr)(void*, size_t, size_t);
void (*free_func_ptr)(void*, size_t);

void* alloc_func(size_t n) {
    ++allocation_count;
    return (*alloc_func_ptr)(n);
}

void free_func(void* p, size_t n) {
    (*free_func_ptr)(p, n);
}

void* realloc_func(void* p, size_t old, size_t n) {
    ++allocation_count;
    return (*realloc_func_ptr)(p, old, n);
}

template<class T>
void do_something(const T&) {
}

template<class T>
void test_std_lib() {
    std::vector<T> v;
    for (unsigned i = 0; i < 100; ++i)
        v.insert(v.begin(), i);

    T a(2), b(3);
    std::swap(a, b);
    BOOST_TEST(a == 3);
    BOOST_TEST(b == 2);
}

template<class T, class A>
void test_move_and_assign(T x, A val) {
    // move away from x, then assign val to x.
    T z(x);
    T y(std::move(x));
    x.assign(val);
    BOOST_CHECK_EQUAL(x, T(val));
    BOOST_CHECK_EQUAL(z, y);
}

template<class T>
void test_move_and_assign() {
    T x(23);
    test_move_and_assign(x, static_cast<short>(2));
    test_move_and_assign(x, static_cast<int>(2));
    test_move_and_assign(x, static_cast<long>(2));
    test_move_and_assign(x, static_cast<long long>(2));
    test_move_and_assign(x, static_cast<unsigned short>(2));
    test_move_and_assign(x, static_cast<unsigned int>(2));
    test_move_and_assign(x, static_cast<unsigned long>(2));
    test_move_and_assign(x, static_cast<unsigned long long>(2));
    test_move_and_assign(x, static_cast<float>(2));
    test_move_and_assign(x, static_cast<double>(2));
    test_move_and_assign(x, static_cast<long double>(2));
    test_move_and_assign(x, x);
    test_move_and_assign(x, "23");
}

int main() {
    using namespace boost::multiprecision;

    test_std_lib<cpp_int>();
    cpp_int a = 2;
    a <<= 1000;    // Force dynamic allocation.
    void const* p = a.backend().limbs();
    cpp_int b = std::move(a);
    BOOST_TEST(b.backend().limbs() == p);

    //
    // Move assign:
    //
    cpp_int d, e;
    d = 2;
    d <<= 1000;
    e = 3;
    e <<= 1000;
    p = d.backend().limbs();
    BOOST_TEST(p != e.backend().limbs());
    e = std::move(d);
    BOOST_TEST(e.backend().limbs() == p);
    d = 2;
    BOOST_TEST(d == 2);
    d = std::move(e);
    e = d;
    BOOST_TEST(e == d);

    test_move_and_assign<cpp_int>();
    test_move_and_assign<int512_t>();
    
    return boost::report_errors();
}

#else
//
// No rvalue refs, nothing to test:
//
int main() {
    return 0;
}

#endif
