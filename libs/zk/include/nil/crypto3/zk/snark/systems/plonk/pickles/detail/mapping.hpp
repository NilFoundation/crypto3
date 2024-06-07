#ifndef CRYPTO3_ZK_SNARK_PICKLES_TO_GROUP_MAP
#define CRYPTO3_ZK_SNARK_PICKLES_TO_GROUP_MAP

#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/coordinates.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/constants.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                struct group_map {
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::base_field_type base_field_type;
                    typedef typename CurveType::template g1_type<algebra::curves::coordinates::affine> group_type;
                    typedef typename base_field_type::value_type value_type;
                    constexpr static const typename base_field_type::integral_type a = CurveType::template g1_type<>::params_type::a;
                    constexpr static const typename base_field_type::integral_type b = CurveType::template g1_type<>::params_type::b;

                    value_type u;
                    value_type fu;
                    value_type sqrt_neg_three_u_squared_minus_u_over_2;
                    value_type sqrt_neg_three_u_squared;
                    value_type inv_three_u_squared;

                    static value_type curve_eqn(value_type x) {
                        value_type res = x;
                        res *= x;
                        res += a;
                        res *= x;
                        res += b;
                        return res;
                    }

                    group_map() {
                        u = value_type(1);
                        while (true) {
                            fu = curve_eqn(u);
                            if (!fu.is_zero()) {
                                break;
                            } else {
                                ++u;
                            }
                        }

                        value_type three_u_squared = value_type(3) * u.squared();
                        inv_three_u_squared = three_u_squared.inversed();
                        sqrt_neg_three_u_squared = (-three_u_squared).sqrt();
                        sqrt_neg_three_u_squared_minus_u_over_2 =
                                (sqrt_neg_three_u_squared - u) * (value_type(2)).inversed();
                    }

                    std::array<value_type, 3> potential_xs_helper(value_type &t2, value_type &alpha) {
                        value_type x1 = sqrt_neg_three_u_squared_minus_u_over_2 -
                                        t2.squared() * alpha * sqrt_neg_three_u_squared;
                        value_type x2 = -u - x1;
                        value_type t2_plus_fu = t2 + fu;
                        value_type x3 = u - t2_plus_fu.squared() * alpha * t2_plus_fu * inv_three_u_squared;
                        return std::array<value_type, 3>({x1, x2, x3});
                    }

                    std::array<value_type, 3> potential_xs(value_type &t) {
                        value_type t2 = t.squared();
                        value_type alpha = ((t2 + fu) * t2).inversed();

                        return potential_xs_helper(t2, alpha);
                    }

                    typename group_type::value_type get_xy(value_type &t) {
                        std::array<value_type, 3> xvec = potential_xs(t);
                        for (auto &x: xvec) {
                            value_type y = curve_eqn(x).sqrt();
                            if (y.squared() == x.pow(3) + a * x + b) {
                                return typename group_type::value_type(x, y);
                            }
                        }
                        return typename group_type::value_type();
                    }

                    typename group_type::value_type to_group(value_type t) {
                        return get_xy(t);
                    }
                };

                template<typename FieldType>
                struct ScalarChallenge {
                    typename FieldType::value_type to_field(const typename FieldType::value_type &endo_coeff) {
                        uint64_t length_in_bits = (64 * kimchi_constant::CHALLENGE_LENGTH_IN_LIMBS);
                        typename FieldType::integral_type rep = typename FieldType::integral_type(_val.data);

                        typename FieldType::value_type a = 2;
                        typename FieldType::value_type b = 2;

                        typename FieldType::value_type one = FieldType::value_type::one();
                        typename FieldType::value_type neg_one = -one;

                        for (int32_t i = length_in_bits / 2 - 1; i >= 0; --i) {
                            a = a.doubled();
                            b = b.doubled();

                            bool r_2i = boost::multiprecision::bit_test(rep, 2 * i);
                            typename FieldType::value_type s;
                            if (r_2i) {
                                s = one;
                            } else {
                                s = neg_one;
                            }
                            if (boost::multiprecision::bit_test(rep, 2 * i + 1) == 0) {
                                b += s;
                            } else {
                                a += s;
                            }
                        }

                        return a * endo_coeff + b;
                    }

                    typename FieldType::value_type value() {
                        return _val;
                    }

                    ScalarChallenge(typename FieldType::value_type _val) : _val(_val) {}

                    ScalarChallenge() = default;

                    typename FieldType::value_type _val;
                };
            }
        }
    }
}


#endif