#ifndef ECC_HELPERS_HPP_
#define ECC_HELPERS_HPP_

#include "fuzzers.hpp"
#include <nil/crypto3/pubkey/ec_group/ec_group.hpp>
#include <nil/crypto3/multiprecision/modular_reduce.hpp>

namespace {

    inline std::ostream &operator<<(std::ostream &o, const nil::crypto3::point_gfp &point) {
        o << point.get_affine_x() << "," << point.get_affine_y();
        return o;
    }

    void check_ecc_math(const nil::crypto3::ec_group &group, const uint8_t in[], size_t len) {
        // These depend only on the group, which is also static
        static const nil::crypto3::point_gfp base_point = group.get_base_point();

        // This is shared across runs to reduce overhead
        static std::vector<boost::multiprecision::cpp_int> ws(nil::crypto3::point_gfp::WORKSPACE_SIZE);

        const size_t hlen = len / 2;
        const boost::multiprecision::cpp_int a = boost::multiprecision::cpp_int::decode(in, hlen);
        const boost::multiprecision::cpp_int b = boost::multiprecision::cpp_int::decode(in + hlen, len - hlen);
        const boost::multiprecision::cpp_int c = a + b;

        const nil::crypto3::point_gfp P1 = base_point * a;
        const nil::crypto3::point_gfp Q1 = base_point * b;
        const nil::crypto3::point_gfp R1 = base_point * c;

        const nil::crypto3::point_gfp S1 = P1 + Q1;
        const nil::crypto3::point_gfp T1 = Q1 + P1;

        FUZZER_ASSERT_EQUAL(S1, R1);
        FUZZER_ASSERT_EQUAL(T1, R1);

        const nil::crypto3::point_gfp P2 = group.blinded_base_point_multiply(a, fuzzer_rng(), ws);
        const nil::crypto3::point_gfp Q2 = group.blinded_base_point_multiply(b, fuzzer_rng(), ws);
        const nil::crypto3::point_gfp R2 = group.blinded_base_point_multiply(c, fuzzer_rng(), ws);
        const nil::crypto3::point_gfp S2 = P2 + Q2;
        const nil::crypto3::point_gfp T2 = Q2 + P2;

        FUZZER_ASSERT_EQUAL(S2, R2);
        FUZZER_ASSERT_EQUAL(T2, R2);

        const nil::crypto3::point_gfp P3 = group.blinded_var_point_multiply(base_point, a, fuzzer_rng(), ws);
        const nil::crypto3::point_gfp Q3 = group.blinded_var_point_multiply(base_point, b, fuzzer_rng(), ws);
        const nil::crypto3::point_gfp R3 = group.blinded_var_point_multiply(base_point, c, fuzzer_rng(), ws);
        const nil::crypto3::point_gfp S3 = P3 + Q3;
        const nil::crypto3::point_gfp T3 = Q3 + P3;

        FUZZER_ASSERT_EQUAL(S3, R3);
        FUZZER_ASSERT_EQUAL(T3, R3);

        FUZZER_ASSERT_EQUAL(S1, S2);
        FUZZER_ASSERT_EQUAL(S1, S3);
    }

}

#endif
