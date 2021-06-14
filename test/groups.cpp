//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE groups_algebra_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/edwards/edwards_pp.hpp>
#include <nil/crypto3/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <nil/crypto3/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <nil/crypto3/algebra/curves/bn128/bn128_pp.hpp>
#endif
#include <sstream>

#include <nil/crypto3/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <nil/crypto3/multiprecision/modular/base_params.hpp>

using namespace nil::crypto3::algebra;

template<typename GroupType>
void test_mixed_add() {
    GroupType base, el, result;

    base = GroupType::value_type::zero();
    el = GroupType::value_type::zero();
    el.to_projective();
    result = base.mixed_add(el);
    assert(result == base + el);

    base = GroupType::value_type::zero();
    el = random_element<GroupType>();
    el.to_projective();
    result = base.mixed_add(el);
    assert(result == base + el);

    base = random_element<GroupType>();
    el = GroupType::value_type::zero();
    el.to_projective();
    result = base.mixed_add(el);
    assert(result == base + el);

    base = random_element<GroupType>();
    el = random_element<GroupType>();
    el.to_projective();
    result = base.mixed_add(el);
    assert(result == base + el);

    base = random_element<GroupType>();
    el = base;
    el.to_projective();
    result = base.mixed_add(el);
    assert(result == base.dbl());
}

template<typename GroupType, typename NumberType>
void test_group() {
    NumberType rand1 = NumberType("76749407");
    NumberType rand2 = NumberType("44410867");
    NumberType randsum = NumberType("121160274");

    GroupType zero = GroupType::value_type::zero();
    assert(zero == zero);
    GroupType one = GroupType::value_type::one();
    assert(one == one);
    GroupType two = number_type<1>(2l) * GroupType::value_type::one();
    assert(two == two);
    GroupType five = number_type<1>(5l) * GroupType::value_type::one();

    GroupType three = number_type<1>(3l) * GroupType::value_type::one();
    GroupType four = number_type<1>(4l) * GroupType::value_type::one();

    assert(two + five == three + four);

    GroupType a = random_element<GroupType>();
    GroupType b = random_element<GroupType>();

    assert(one != zero);
    assert(a != zero);
    assert(a != one);

    assert(b != zero);
    assert(b != one);

    assert(a.dbl() == a + a);
    assert(b.dbl() == b + b);
    assert(one.add(two) == three);
    assert(two.add(one) == three);
    assert(a + b == b + a);
    assert(a - a == zero);
    assert(a - b == a + (-b));
    assert(a - b == (-b) + a);

    // handle special cases
    assert(zero + (-a) == -a);
    assert(zero - a == -a);
    assert(a - zero == a);
    assert(a + zero == a);
    assert(zero + a == a);

    assert((a + b).dbl() == (a + b) + (b + a));
    assert(number_type<1>("2") * (a + b) == (a + b) + (b + a));

    assert((rand1 * a) + (rand2 * a) == (randsum * a));

    assert(GroupType::order() * a == zero);
    assert(GroupType::order() * one == zero);
    assert((GroupType::order() * a) - a != zero);
    assert((GroupType::order() * one) - one != zero);

    test_mixed_add<GroupType>();
}

template<typename GroupType>
void test_mul_by_q() {
    GroupType a = random_element<GroupType>();
    assert((GroupType::base_field_char() * a) == a.mul_by_q());
}

template<typename GroupType>
void test_output() {
    GroupType g = GroupType::value_type::zero();

    for (size_t i = 0; i < 1000; ++i) {
        std::stringstream ss;
        ss << g;
        GroupType gg;
        ss >> gg;
        assert(g == gg);
        /* use a random point in next iteration */
        g = random_element<GroupType>();
    }
}

int main(void) {
    edwards_pp::init_public_params();
    test_group<G1<edwards_pp>>();
    test_output<G1<edwards_pp>>();
    test_group<G2<edwards_pp>>();
    test_output<G2<edwards_pp>>();
    test_mul_by_q<G2<edwards_pp>>();

    mnt4_pp::init_public_params();
    test_group<G1<mnt4_pp>>();
    test_output<G1<mnt4_pp>>();
    test_group<G2<mnt4_pp>>();
    test_output<G2<mnt4_pp>>();
    test_mul_by_q<G2<mnt4_pp>>();

    mnt6_pp::init_public_params();
    test_group<G1<mnt6_pp>>();
    test_output<G1<mnt6_pp>>();
    test_group<G2<mnt6_pp>>();
    test_output<G2<mnt6_pp>>();
    test_mul_by_q<G2<mnt6_pp>>();

    alt_bn128_pp::init_public_params();
    test_group<G1<alt_bn128_pp>>();
    test_output<G1<alt_bn128_pp>>();
    test_group<G2<alt_bn128_pp>>();
    test_output<G2<alt_bn128_pp>>();
    test_mul_by_q<G2<alt_bn128_pp>>();

#ifdef CURVE_BN128    // BN128 has fancy dependencies so it may be disabled
    bn128_pp::init_public_params();
    test_group<G1<bn128_pp>>();
    test_output<G1<bn128_pp>>();
    test_group<G2<bn128_pp>>();
    test_output<G2<bn128_pp>>();
#endif
}
