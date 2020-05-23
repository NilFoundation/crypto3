//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <vector>

#include <gtest/gtest.h>
#include <stdint.h>

<<<<<<< HEAD
#include <nil/crypto3/fft/polynomial_arithmetic/basic_operations.hpp>
=======
#include <nil/cas/fft/polynomial_arithmetic/basic_operations.hpp>
>>>>>>> 0d62061d49911d1e9a117ce021ac9568c63471e7

using namespace nil::cas::fft;

<<<<<<< HEAD
    template<typename T>
    class KroneckerSubstitutionTest : public ::testing::Test { };
    typedef ::testing::Types<ff::Double> FieldT; /* List Extend Here */
    TYPED_TEST_CASE(KroneckerSubstitutionTest, FieldT);
=======
/*template<typename T>
class KroneckerSubstitutionTest : public ::testing::Test { };
typedef ::testing::Types<libff::Double> FieldT;*/ /* List Extend Here */
/*TYPED_TEST_CASE(KroneckerSubstitutionTest, FieldT);
>>>>>>> 0d62061d49911d1e9a117ce021ac9568c63471e7

TYPED_TEST(KroneckerSubstitutionTest, StandardPolynomialMultiplication) {

    std::vector<TypeParam> a = {1, 2, 3, 1};
    std::vector<TypeParam> b = {1, 2, 1, 1};
    std::vector<TypeParam> c(1, TypeParam::zero());

    _polynomial_multiplication_on_kronecker(c, a, b);

    std::vector<TypeParam> c_answer(1, TypeParam::zero());
    _polynomial_multiplication(c_answer, a, b);

    for (size_t i = 0; i < c_answer.size(); i++) {
        EXPECT_TRUE(c_answer[i] == c[i]);
    }
}

TYPED_TEST(KroneckerSubstitutionTest, SquaredPolynomialMultiplication) {

    std::vector<TypeParam> a = {1, 2, 3, 1};
    std::vector<TypeParam> b = a;
    std::vector<TypeParam> c(1, TypeParam::zero());

    _polynomial_multiplication_on_kronecker(c, a, b);

    std::vector<TypeParam> c_answer(1, TypeParam::zero());
    _polynomial_multiplication(c_answer, a, b);

    for (size_t i = 0; i < c_answer.size(); i++) {
        EXPECT_TRUE(c_answer[i] == c[i]);
    }
}*/

int main() {
    return 0;
}