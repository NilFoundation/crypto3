//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <vector>

#include <cstdint>

#include <nil/cas/fft/polynomial_arithmetic/basic_operations.hpp>

using namespace nil::cas::fft;

/*template<typename T>
class KroneckerSubstitutionTest : public ::testing::Test { };
typedef ::testing::Types<libff::Double> FieldT;*/ /* List Extend Here */
/*TYPED_TEST_CASE(KroneckerSubstitutionTest, FieldT);

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