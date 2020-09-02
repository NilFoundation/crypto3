//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE constexpr_matrix_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/algebra/matrix/matrix.hpp>
#include <nil/algebra/matrix/math.hpp>
#include <nil/algebra/matrix/operators.hpp>
#include <nil/algebra/matrix/utility.hpp>
#include <nil/algebra/vector/vector.hpp>
#include <nil/algebra/vector/operators.hpp>

using namespace nil::algebra;

// Uniform initialization
constexpr matrix<double, 3, 3> m1 = {1., 2., 3., 4., 5., 6., 7., 8., 9.};

// Type deduction
constexpr matrix m2 = {{{1., 2.}}};

constexpr matrix m22 = {{{1., 3.}, {2., 7.}}};

static_assert(m1[0][2] == 3, "matrix[]");

static_assert(m1.row(2) == vector {7., 8., 9.}, "matrix row");

static_assert(m1.column(2) == vector {3., 6., 9.}, "matrix column");

static_assert(fill<2, 2>(3.) == matrix {{{3., 3.}, {3., 3.}}}, "matrix fill");

static_assert(matmul(m1, m1) == matrix {{{30., 36., 42.}, {66., 81., 96.}, {102., 126., 150.}}},
              "real matrix multiply");

static_assert(identity<double, 3> == matrix {{{1., 0., 0.}, {0., 1., 0.}, {0., 0., 1.}}}, "identity");

static_assert(identity<double, 3> == inverse(identity<double, 3>), "inverse-identity");

static_assert(inverse(m22) == matrix {{{7., -3.}, {-2., 1.}}}, "inverse");

static_assert(matmul(inverse(m22), matrix<double, 2, 1> {{{1.}, {1.}}}) == matrix {{{4.}, {-1.}}}, "A^-1*b = x");

static_assert(horzcat(identity<double, 2>, identity<double, 2>) ==
                  matrix<double, 2, 4> {{{1., 0., 1., 0.}, {0., 1., 0., 1.}}},
              "horzcat");

static_assert(submat<2, 2>(m1, 1, 1) == matrix {{{5., 6.}, {8., 9.}}}, "submat");

static_assert(rref(m1) == matrix {{{1., 0., -1.}, {0., 1., 2.}, {0., 0., 0.}}}, "rref");

static_assert(rank(m1) == 2, "rank");
