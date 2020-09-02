//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE constexpr_vector_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/algebra/linalg/linalg.hpp>

using namespace nil::algebra;

static_assert(make_vector(1, 2, 3) == vector {1, 2, 3}, "make_vector and uniform initialization deduction guide");

static_assert(make_vector(1, 2, 3) == vector {{1, 2, 3}}, "make_vector and aggregate initialization deduction guide");

static_assert(elementwise([](double x) { return 1 / x; }, vector {1., 2., 4.}) == vector {1., 0.5, 0.25},
              "elementwise");

static_assert(vector {1, 2, 3} == vector {1, 2, 3}, "operator==");

static_assert(vector {1, 2, 3} != vector {3, 2, 1}, "operator!=");

static_assert(vector {1, 2, 3} + vector {1, 2, 3} == vector {2, 4, 6}, "operator+");

static_assert(sum(vector {1, 2, 3}) == 6, "sum");

static_assert(iota<5>(0) == vector {0, 1, 2, 3, 4}, "iota");

static_assert(iota<5, double>() == vector {0., 1., 2., 3., 4.}, "iota");

static_assert(fill<4>(2.) == vector {2., 2., 2., 2.}, "fill");

static_assert(generate<4>([](auto i) { return double(i * i); }) == vector {0., 1., 4., 9.}, "generate");

static_assert(vector {1, 2, 3} == slice<3>(vector {1, 2, 3, 4}), "slice-no offset");

static_assert(vector {2, 3, 4} == slice<3>(vector {1, 2, 3, 4}, 1), "slice with offset");
