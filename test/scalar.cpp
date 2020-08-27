//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE constexpr_scalar_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/algebra/vector/math.hpp>

using namespace nil::algebra;

static_assert(sqrt(625.) == 25, "sqrt");

static_assert(sqrt(625.f) == 25, "sqrt");

static_assert(exponentiate(5, 2) == 25, "exponentiate");

static_assert(nthroot(27, 3) == 3, "nth root");

static_assert(cotila::abs(std::complex(3., 4.)) == 5., "abs");

static_assert(cotila::abs(-4) == 4, "abs");

static_assert(cotila::abs(4) == 4, "abs");

static_assert(cotila::conj(4) == 4, "conj");

static_assert(cotila::conj(-4) == -4, "conj");

static_assert(cotila::conj(std::complex(3., 4.)) == std::complex(3., -4.), "conj");

static_assert(cotila::conj(std::complex(3., -4.)) == std::complex(3., 4.), "conj");