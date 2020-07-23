//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <nil/algebra/curves/edwards/edwards_pp.hpp>
#include <nil/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <nil/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <nil/algebra/curves/bn128/bn128_pp.hpp>
#endif
#include <sstream>

#include <nil/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <boost/multiprecision/modular/base_params.hpp>

using namespace nil::algebra;

template<typename GroupT>
void test_mixed_add() {
    GroupT base, el, result;

    base = GroupT::zero();
    el = GroupT::zero();
    el.to_special();
    result = base.mixed_add(el);
    assert(result == base + el);

    base = GroupT::zero();
    el = GroupT::random_element();
    el.to_special();
    result = base.mixed_add(el);
    assert(result == base + el);

    base = GroupT::random_element();
    el = GroupT::zero();
    el.to_special();
    result = base.mixed_add(el);
    assert(result == base + el);

    base = GroupT::random_element();
    el = GroupT::random_element();
    el.to_special();
    result = base.mixed_add(el);
    assert(result == base + el);

    base = GroupT::random_element();
    el = base;
    el.to_special();
    result = base.mixed_add(el);
    assert(result == base.dbl());
}

template<typename GroupT, typename NumberType>
void test_group() {
    NumberType rand1 = NumberType ("76749407");
    NumberType rand2 = NumberType ("44410867");
    NumberType randsum = NumberType ("121160274");

    GroupT zero = GroupT::zero();
    assert(zero == zero);
    GroupT one = GroupT::one();
    assert(one == one);
    GroupT two = number_type<1>(2l) * GroupT::one();
    assert(two == two);
    GroupT five = number_type<1>(5l) * GroupT::one();

    GroupT three = number_type<1>(3l) * GroupT::one();
    GroupT four = number_type<1>(4l) * GroupT::one();

    assert(two + five == three + four);

    GroupT a = GroupT::random_element();
    GroupT b = GroupT::random_element();

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

    assert(GroupT::order() * a == zero);
    assert(GroupT::order() * one == zero);
    assert((GroupT::order() * a) - a != zero);
    assert((GroupT::order() * one) - one != zero);

    test_mixed_add<GroupT>();
}

template<typename GroupT>
void test_mul_by_q() {
    GroupT a = GroupT::random_element();
    assert((GroupT::base_field_char() * a) == a.mul_by_q());
}

template<typename GroupT>
void test_output() {
    GroupT g = GroupT::zero();

    for (size_t i = 0; i < 1000; ++i) {
        std::stringstream ss;
        ss << g;
        GroupT gg;
        ss >> gg;
        assert(g == gg);
        /* use a random point in next iteration */
        g = GroupT::random_element();
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
