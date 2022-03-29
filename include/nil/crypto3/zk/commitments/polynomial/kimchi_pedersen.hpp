//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_KIMCHI_PEDERSEN_COMMITMENT_SCHEME_HPP
#define CRYPTO3_ZK_KIMCHI_PEDERSEN_COMMITMENT_SCHEME_HPP

#include <vector>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>

using namespace nil::crypto3;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {

                template<typename CurveType>
                class kimchi_pedersen {
                public:
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::base_field_type base_field_type;
                    typedef typename CurveType::template g1_type<
                        algebra::curves::coordinates::affine> group_type;
                    typedef typename algebra::policies::multiexp_method_BDLO12 multiexp_method;
                    typedef typename algebra::multiexp_with_mixed_addition<multiexp_method> multiexp;

                    struct params_type {
                        // vector of n distinct curve points of unknown discrete logarithm
                        std::vector<typename group_type::value_type> g;
                        // distinct curve point of unknown discrete logarithm for blinding the commitment
                        typename group_type::value_type h;
                        // coefficients for the curve endomorphism
                        typename scalar_field_type::value_type endo_r;
                        typename base_field_type::value_type endo_q;
                    };

                    struct private_key {
                        math::polynomial<scalar_field_type::value_type> F;
                        scalar_field_type::value_type w;
                    };

                    struct proof_type {
                        std::vector<
                            std::tuple<typename group_type::value_type,
                            typename group_type::value_type>> lr;
                        
                        typename group_type::value_type delta;
                        
                        typename scalar_field_type::value_type z1;
                        typename scalar_field_type::value_type z2;

                        typename group_type::value_type sg;
                    };

                    //fake structs
                    struct sponge_type {};
                    struct group_map_type {};

                    struct commitment_type {
                        std::vector<typename group_type::value_type> unshifted;
                        typename group_type::value_type shifted = group_type::value_type::one();
                    };

                    static params_type setup(const int d) {
                        // define parameters of protocol
                        std::vector<typename group_type::value_type> g;
                        typename group_type::value_type h = algebra::random_element<group_type>();
                        for (int i = 0; i < d; ++i) {
                            g.push_back(algebra::random_element<group_type>());
                        }
                        typename scalar_field_type::value_type r = random_element<scalar_field_type>();
                        typename base_field_type::value_type q = random_element<scalar_field_type>();
                        return params_type(g, h, r, q);
                    }

                    static commitment_type commitment(const params_type& params, const private_key& pk) {
                        commitment_type res;
                        auto left = pk.F.begin();

                        // non-hiding part
                        std::size_t len = pk.F.size();
                        while (len > params.d) {
                            res.unshifted.push_back(multiexp(params.g.begin(), params.g.end(), left, left + params.d, 1));
                            left += params.d;
                            len -= params.d;
                        }
                        if (len > 0) {
                            res.unshifted.push_back(multiexp(params.g.begin(), params.g.begin() + len, left, left + len, 1));
                            res.shifted = multiexp(params.g.end() - len, params.g.end(), left, left + len, 1);
                        }

                        // masking part
                        // TODO: is w uniform for all values?
                        pk.w = algebra::random_element<scalar_field_type>();
                        for (auto i : res.unshifted) {
                            i = i + pk.w * params.h;
                        }
                        res.shifted = res.shifted + pk.w * params.h;

                        return res;
                    }

                    static proof_type proof_eval(const params_type& params, const group_map_type& group_map, const poly_type& plms,
                                                const std::vector<typename scalar_field_type::value_type>& elm, const typename scalar_field_type::value_type& polyscale,
                                                const typename scalar_field_type::value_type& evalscale, sponge_type& sponge) {
                        proof_type res;
                        auto g = params.g;
                        std::vector<std::tuple<typename scalar_field_type::value_type,
                            typename scalar_field_type::value_type>> blinders;

                        // making size of vector g = 2^k
                        size_t power_of_two = 1;
                        while (power_of_two < g.size()) {
                            power_of_two *= 2;
                        }
                        auto init_size = g.size();
                        for (int i = 0; i < power_of_two - init_size; ++i) {
                            g.push_back(group_type::value_type::one());
                        }

                        // computing a
                        std::vector<typename scalar_field_type::value_type> a;
                        for (int i = 0; i < power_of_two - a.size(); ++i) {
                            a.push_back(0);
                        }
                        // computing b
                        std::vector<typename scalar_field_type::value_type> b(g.size(), scalar_field_type::value_type::zero());
                        auto scale = typename scalar_field_type::value_type::one();
                        for (auto e : elm) {
                            auto spare = typename scalar_field_type::value_type::one();
                            for (int i = 0; i < g.size(); ++i) {
                                b[i] += scale * spare;
                                spare *= e;
                            }
                            scale *= evalscale;
                        }

                        // challenge - all functions are blueprints
                        sponge.absorb(inner_product(a.begin(), a.end(), b.begin(), b.end(), 1));
                        typename group_type::value_type U = group_map(sponge.squeeze());
                        std::vector<typename scalar_field_type::value_type> chals;
                        std::vector<typename scalar_field_type::value_type> chal_invs;

                        // halving process
                        std::vector<typename group_type::value_type> g_low, g_high;
                        std:vector<typename scalar_field_type::value_type> a_low, a_high, b_low, b_high;
                        while(power_of_two > 1) {
                            power_of_two /= 2;
                            g_low = newVec(g.begin(), g.begin() + power_of_two);
                            g_high = newVec(g.begin() + power_of_two, g.end());
                            a_low = newVec(a.begin(), a.begin() + power_of_two);
                            a_high = newVec(a.begin() + power_of_two, a.end());
                            b_low = newVec(b.begin(), b.begin() + power_of_two);
                            b_high = newVec(b.begin() + power_of_two, b.end());

                            auto rand_l = random_element<scalar_field_type>();
                            auto rand_r = random_element<scalar_field_type>();

                            auto l = multiexp(g_low.begin(), g_low.end(), a_high.begin(), a_high.end(), 1)
                                            + rand_l * params.h + inner_product(a_high.begin(), a_high.end(), b_low.begin(), b_low.end(), 1) * U;
                            auto r = multiexp(g_high.begin(), g_high.end(), a_low.begin(), a_low.end(), 1)
                                            + rand_r * params.h + inner_product(a_low.begin(), a_low.end(), b_high.begin(), b_high.end(), 1) * U;

                            res.lr.push_back(std::make_tuple(l, r));
                            blinders.push_back(std::make_tuple(rand_l, rand_r));

                            //fake funtions again
                            sponge.absorb(l);
                            sponge.absorb(r);
                            auto u_pre = sponge.squeeze_prechallenge();
                            auto u = u_pre //to field using endo_r
                            chals.push_back(u);
                            chal_invs.push_back(u.inverse());

                            a = u.inverse() * a_high + a_low;
                            b = u * b_high + b_low;
                            g = u * g_high + g_low;
                        }

                        // result
                        auto a0 = a[0];
                        auto b0 = b[0];
                        auto g0 = g[0];

                        auto r_prime = random_element<scalar_field_type>(); //smth about blinders, chals and chal_invs
                        auto d = random_element<scalar_field_type>();
                        auto r_delta = random_element<scalar_field_type>();

                        //fake functions
                        sponge.absorb(delta);
                        auto c = sponge.squeeze(); //to field using endo_r

                        res.delta = (g0 + u * b0) * d + params.h * r_delta;
                        res.z1 = a0 * c + d;
                        res.z2 = c * r_prime + r_delta;
                        res.sg = g0;

                        return res;
                    }

                    static bool verify_eval(const params_type& params, const proof_type& proof) {
                        
                    }
                };

            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_KIMCHI_PEDERSEN_COMMITMENT_SCHEME_HPP
