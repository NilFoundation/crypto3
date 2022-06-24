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
                    typedef typename CurveType::template g1_type<algebra::curves::coordinates::affine> group_type;
                    typedef typename algebra::policies::multiexp_method_BDLO12 multiexp_method;
                    // using multiexp = algebra::multiexp_with_mixed_addition<multiexp_method>;

                    struct params_type {
                        // vector of n distinct curve points of unknown discrete logarithm
                        std::vector<typename group_type::value_type> g;
                        // distinct curve point of unknown discrete logarithm for blinding the commitment
                        typename group_type::value_type h;
                        // coefficients for the curve endomorphism
                        typename scalar_field_type::value_type endo_r;
                        typename base_field_type::value_type endo_q;
                    };

                    struct commitment_type {
                        std::vector<typename group_type::value_type> unshifted;
                        typename group_type::value_type shifted = group_type::value_type::zero();
                    };

                    struct blinding_type {
                        std::vector<typename scalar_field_type::value_type> unshifted;
                        typename scalar_field_type::value_type shifted = scalar_field_type::value_type::zero();
                    };

                    struct poly_type {
                        // polynomial itself
                        std::vector<typename scalar_field_type::value_type> coeffs;
                        // optional degree bound - poly degree must not exceed it
                        int bound = -1;
                        // chunked commitment
                        commitment_type commit;
                    };

                    struct proof_type {
                        std::vector<std::tuple<typename group_type::value_type, typename group_type::value_type>> lr;

                        typename group_type::value_type delta;

                        typename scalar_field_type::value_type z1;
                        typename scalar_field_type::value_type z2;

                        typename group_type::value_type sg;
                    };

                    struct evaluation_type {
                        // polycommitment
                        commitment_type commit;
                        // evals of polynomial at a set of points
                        std::vector<std::vector<typename scalar_field_type::value_type>> evaluations;
                        // optional degree bound
                        int bound = -1;
                    };

                    // fake structs
                    struct sponge_type {
                        void absorb(typename scalar_field_type::value_type a) {
                        }
                        void absorb_fr(typename scalar_field_type::value_type a) {
                        }
                        void absorb_g(typename group_type::value_type a) {
                        }

                        typename scalar_field_type::value_type squeeze() {
                            return typename scalar_field_type::value_type::one();
                        }
                        typename group_type::value_type squeeze_prechallenge() {
                            return typename group_type::value_type::zero();
                        }
                        typename scalar_field_type::value_type challenge_fq() {
                            return typename scalar_field_type::value_type::one();
                        }
                    };
                    struct group_map_type {
                        typename group_type::value_type to_group(typename group_type::value_type a) {
                            return typename group_type::value_type::zero();
                        }
                    };

                    struct batchproof_type {
                        sponge_type sponge;
                        std::vector<evaluation_type> evaluation;
                        std::vector<typename scalar_field_type::value_type> evaluation_points;
                        // scaling factor for eval points powers
                        typename scalar_field_type::value_type xi;
                        // scaling factor for polynomials
                        typename scalar_field_type::value_type r;
                        // batched proof
                        proof_type opening;
                    };

                    static params_type setup(const int d) {
                        // define parameters of protocol
                        std::vector<typename group_type::value_type> g;
                        typename group_type::value_type h = algebra::random_element<group_type>();
                        for (int i = 0; i < d; ++i) {
                            g.push_back(algebra::random_element<group_type>());
                        }
                        typename scalar_field_type::value_type r = algebra::random_element<scalar_field_type>();
                        typename base_field_type::value_type q = algebra::random_element<scalar_field_type>();
                        return params_type(g, h, r, q);
                    }

                    static std::tuple<commitment_type, blinding_type>
                        commitment(const params_type &params,
                                   const math::polynomial<typename scalar_field_type::value_type> &poly, int bound) {
                        commitment_type res;
                        blinding_type blind_res;

                        auto left = poly.begin();
                        auto g_len = params.g.size();

                        // non-hiding part
                        std::size_t len = poly.size();
                        while (len > g_len) {
                            res.unshifted.push_back(algebra::multiexp_with_mixed_addition<multiexp_method>(
                                params.g.begin(), params.g.end(), left, left + g_len, 1));
                            left += g_len;
                            len -= g_len;
                        }
                        if (len > 0) {
                            res.unshifted.push_back(algebra::multiexp_with_mixed_addition<multiexp_method>(
                                params.g.begin(), params.g.begin() + len, left, left + len, 1));
                        }

                        if (bound >= 0) {
                            auto start = bound - bound % g_len;
                            if (poly.size() != 0 && start < poly.size()) {
                                res.shifted = algebra::multiexp_with_mixed_addition<multiexp_method>(
                                    params.g.end() - bound % g_len, params.g.end(), poly.begin() + start, poly.end(),
                                    1);
                            }
                        }

                        // masking part
                        auto w = algebra::random_element<scalar_field_type>();
                        for (auto i : res.unshifted) {
                            i = i + w * params.h;
                            blind_res.unshifted.push_back(w);
                            w = algebra::random_element<scalar_field_type>();
                        }
                        if (res.shifted != typename group_type::value_type::zero()) {
                            res.shifted = res.shifted + w * params.h;
                            blind_res.shifted = w;
                        }

                        return std::make_tuple(res, blind_res);
                    }

                    static proof_type proof_eval(const params_type &params, const group_map_type &group_map,
                                                 const poly_type &plms,
                                                 const std::vector<typename scalar_field_type::value_type> &elm,
                                                 const typename scalar_field_type::value_type &polyscale,
                                                 const typename scalar_field_type::value_type &evalscale,
                                                 sponge_type &sponge) {
                        proof_type res;
                        auto g = params.g;
                        std::vector<
                            std::tuple<typename scalar_field_type::value_type, typename scalar_field_type::value_type>>
                            blinders;

                        // making size of vector g = 2^k
                        size_t power_of_two = 1;
                        while (power_of_two < g.size()) {
                            power_of_two *= 2;
                        }
                        auto init_size = g.size();
                        for (int i = 0; i < power_of_two - init_size; ++i) {
                            g.push_back(group_type::value_type::zero());
                        }

                        // computing a and blinding factor
                        std::vector<typename scalar_field_type::value_type> a(
                            params.g.size(), typename scalar_field_type::value_type::zero());
                        auto blinding_factor = typename scalar_field_type::value_type::zero();
                        auto scale = typename scalar_field_type::value_type::one();
                        for (auto polynom : plms) {
                            auto offset = polynom.coeffs.begin();
                            int j = 0;
                            if (polynom.bound >= 0) {
                                while (j < polynom.commit.unshifted.size()) {
                                    auto end_iter =
                                        (offset + params.g.size() > polynom.coeffs.end() ? polynom.coeffs.end() :
                                                                                           offset + params.g.size());
                                    auto segment = newVec(offset, end_iter);
                                    // add unshifted to a
                                    for (int i = 0; i < segment.size(); ++i) {
                                        a[i] += segment[i] * scale;
                                    }
                                    blinding_factor += polynom.commit.unshifted[j] * scale;
                                    j += 1;
                                    scale *= polyscale;
                                    offset += params.g.size();
                                    if (offset - polynom.coeffs.begin() > polynom.bound) {
                                        // add shifted to a
                                        for (int i = 0; i < segment.size(); ++i) {
                                            a[i + params.g.size() - segment.size()] += segment[i] * scale;
                                        }
                                        blinding_factor += polynom.commit.shifted * scale;
                                        scale *= polyscale;
                                    }
                                }
                            } else {
                                while (j < polynom.commit.unshifted.size()) {
                                    auto end_iter =
                                        (offset + params.g.size() > polynom.coeffs.end() ? polynom.coeffs.end() :
                                                                                           offset + params.g.size());
                                    auto segment = newVec(offset, end_iter);
                                    // add unshifted to a
                                    for (int i = 0; i < segment.size(); ++i) {
                                        a[i] += segment[i] * scale;
                                    }
                                    blinding_factor += polynom.commit.unshifted[j] * scale;
                                    j += 1;
                                    scale *= polyscale;
                                    offset += params.g.size();
                                }
                            }
                        }
                        init_size = a.size();
                        for (int i = 0; i < power_of_two - init_size; ++i) {
                            a.push_back(0);
                        }

                        // computing b
                        std::vector<typename scalar_field_type::value_type> b(
                            power_of_two, typename scalar_field_type::value_type::zero());
                        scale = typename scalar_field_type::value_type::one();
                        for (auto e : elm) {
                            auto spare = typename scalar_field_type::value_type::one();
                            for (int i = 0; i < power_of_two; ++i) {
                                b[i] += scale * spare;
                                spare *= e;
                            }
                            scale *= evalscale;
                        }

                        std::vector<typename scalar_field_type::value_type> inner_product = {a[0] * b[0]};
                        for (int i = 1; i < a.size(); ++i) {
                            inner_product.push_back(inner_product[i - 1] + a[i] * b[i]);
                        }

                        // fake functions
                        sponge.absorb_fr(inner_product);
                        typename group_type::value_type u = group_map.to_group(sponge.challenge_fq());

                        std::vector<typename scalar_field_type::value_type> chals;
                        std::vector<typename scalar_field_type::value_type> chal_invs;

                        // halving process
                        std::vector<typename group_type::value_type> g_low, g_high;
                        std::vector<typename scalar_field_type::value_type> a_low, a_high, b_low, b_high;
                        while (power_of_two > 1) {
                            power_of_two /= 2;
                            g_low = newVec(g.begin(), g.begin() + power_of_two);
                            g_high = newVec(g.begin() + power_of_two, g.end());
                            a_low = newVec(a.begin(), a.begin() + power_of_two);
                            a_high = newVec(a.begin() + power_of_two, a.end());
                            b_low = newVec(b.begin(), b.begin() + power_of_two);
                            b_high = newVec(b.begin() + power_of_two, b.end());

                            auto rand_l = algebra::random_element<scalar_field_type>();
                            auto rand_r = algebra::random_element<scalar_field_type>();

                            auto l = algebra::multiexp_with_mixed_addition<multiexp_method>(
                                         g_low.begin(), g_low.end(), a_high.begin(), a_high.end(), 1) +
                                     rand_l * params.h +
                                     inner_product(a_high.begin(), a_high.end(), b_low.begin(), b_low.end(), 1) * u;
                            auto r = algebra::multiexp_with_mixed_addition<multiexp_method>(
                                         g_high.begin(), g_high.end(), a_low.begin(), a_low.end(), 1) +
                                     rand_r * params.h +
                                     inner_product(a_low.begin(), a_low.end(), b_high.begin(), b_high.end(), 1) * u;

                            res.lr.push_back(std::make_tuple(l, r));
                            blinders.push_back(std::make_tuple(rand_l, rand_r));

                            // fake funtions
                            sponge.absorb_g(l);
                            sponge.absorb_g(r);
                            auto u_pre = sponge.squeeze_prechallenge();
                            auto u = typename scalar_field_type::value_type::one();    // u_pre to field using endo_r

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

                        auto r_prime = blinding_factor;
                        for (int i = 0; i < blinders.size(); ++i) {
                            const auto [l, r] = blinders[i];
                            r_prime += l * chal_invs[i] + r * chals[i];
                        }
                        auto d = algebra::random_element<scalar_field_type>();
                        auto r_delta = algebra::random_element<scalar_field_type>();

                        // fake functions
                        sponge.absorb(r_delta);
                        auto c = sponge.squeeze();    // to field using endo_r

                        res.delta = (g0 + u * b0) * d + params.h * r_delta;
                        res.z1 = a0 * c + d;
                        res.z2 = c * r_prime + r_delta;
                        res.sg = g0;

                        return res;
                    }

                    static typename scalar_field_type::value_type combined_inner_product(
                        const std::vector<typename scalar_field_type::value_type> &evaluation_points,
                        typename scalar_field_type::value_type xi, typename scalar_field_type::value_type r,
                        const std::vector<std::tuple<evaluation_type, int>> &polys, int g_size) {
                        auto res = typename scalar_field_type::value_type::zero();
                        auto xi_i = typename scalar_field_type::value_type::one();

                        for (auto poly : polys) {
                            const auto [evals_tr, bound] = poly;
                            std::vector<std::vector<typename scalar_field_type::value_type>> evals;
                            for (int i = 0; i < evals_tr[0].size(); ++i) {
                                std::vector<typename scalar_field_type::value_type> ev;
                                for (int j = 0; j < evals_tr.size(); ++j) {
                                    ev.push_back(evals_tr[j][i]);
                                }
                                evals.push_back(ev);
                            }
                            for (auto eval : evals) {
                                auto term = typename scalar_field_type::value_type::zero();
                                for (auto coef : eval) {
                                    term *= r;
                                    term += coef;
                                }

                                res += xi_i * term;
                                xi_i *= xi;
                            }

                            if (poly.bound != -1) {
                                std::vector<typename scalar_field_type::value_type> last_evals(
                                    evaluation_points.size(), typename scalar_field_type::value_type::zero());
                                if (poly.bound <= evals.size() * g_size) {
                                    last_evals = evals[evals.size() - 1];
                                }

                                std::vector<typename scalar_field_type::value_type> shifted_evals;
                                for (int i = 0; i < last_evals.size(); ++i) {
                                    shifted_evals.push_back(evaluation_points[i].pow(g_size - poly.bound % g_size) *
                                                            last_evals[i]);
                                }

                                auto term = typename scalar_field_type::value_type::zero();
                                for (auto coef : shifted_evals) {
                                    term *= r;
                                    term += coef;
                                }
                                res += xi_i * term;
                                xi_i *= xi;
                            }
                        }

                        return res;
                    }

                    static std::vector<typename scalar_field_type::value_type>
                        b_poly(const std::vector<typename scalar_field_type::value_type> &chals,
                               typename scalar_field_type::value_type x) {
                        auto k = chals.size();
                        std::vector<typename scalar_field_type::value_type> pow_twos;
                        pow_twos.push_back(x);
                        for (int i = 1; i < k; ++i) {
                            pow_twos.push_back(pow_twos[i - 1].squared());
                        }
                        std::vector<typename scalar_field_type::value_type> res;
                        for (int i = 0; i < k; ++i) {
                            res.push_back(typename scalar_field_type::value_type::one() +
                                          chals[i] * pow_twos[k - 1 - i]);
                            return res;
                        }
                    }

                    static std::vector<typename scalar_field_type::value_type>
                        b_poly_coefficients(const std::vector<typename scalar_field_type::value_type> &chals) {
                        auto rounds = chals.size();
                        auto s_len = 1 << rounds;
                        std::vector<typename scalar_field_type::value_type> s(
                            s_len, typename scalar_field_type::value_type::one());
                        int k = 0;
                        int pow = 1;
                        for (int i = 1; i <= s_len; ++i) {
                            (i == pow) ? (k += 1) : (k += 0);
                            (i == pow) ? (pow <<= 1) : (pow <<= 0);
                            s[i] = s[i - (pow >> 1)] * chals[rounds - 1 - (k - 1)];
                        }
                        return s;
                    }

                    static bool verify_eval(const params_type &params, const group_map_type &group_map,
                                            const batchproof_type &batch) {
                        size_t power_of_two = 1;
                        while (power_of_two < params.g.size()) {
                            power_of_two *= 2;
                        }
                        std::vector<typename group_type::value_type> points;
                        points.push_back(params.h);
                        for (auto i : params.g) {
                            points.push_back(i);
                        }
                        for (int i = 0; i < power_of_two - params.g.size() - 1; ++i) {
                            points.push_back(typename group_type::value_type::zero());
                        }

                        std::vector<typename scalar_field_type::value_type> scalars;
                        for (int i = 0; i < power_of_two; ++i) {
                            scalars.push_back(typename scalar_field_type::value_type::zero());
                        }

                        auto rand_base = algebra::random_element<scalar_field_type>();
                        auto sg_rand_base = algebra::random_element<scalar_field_type>();
                        auto rand_base_i = typename scalar_field_type::value_type::one();
                        auto sg_rand_base_i = typename scalar_field_type::value_type::one();

                        std::vector<std::tuple<evaluation_type, int>> es;
                        for (auto eval : batch.evaluations) {
                            int bnd = -1;
                            if (eval.commitment.shifted != 0) {
                                bnd = eval.bound;
                            }
                            es.push_back(std::make_tuple(eval.evaluations, bnd));
                        }
                        auto combined_inner_product0 =
                            combined_inner_product(batch.evaluation_points, batch.xi, batch.r, es, params.g.size());
                        // fake functions
                        batch.sponge.absorb(combined_inner_product0);
                        auto t = batch.sponge.challenge();
                        auto u = group_map.to_group(t);
                        auto [chals, chal_invs] = batch.opening.challenges(params.endo_r, batch.sponge);
                        batch.sponge.absorb_g(batch.opening.delta);
                        auto c = batch.sponge.challenge();    // to field using endo_r

                        typename scalar_field_type::value_type b0;
                        {
                            auto scale = typename scalar_field_type::value_type::one();
                            auto res = typename scalar_field_type::value_type::zero();
                            for (auto e : batch.evaluation_points) {
                                auto term = b_poly(chals, e);
                                res += scale * term;
                                scale *= batch.r;
                            }
                            b0 = res;
                        }

                        auto s = b_poly_coefficients(chals);

                        auto neg_rand_base_i = -rand_base_i;

                        points.push_back(batch.opening.sg);
                        scalars.push_back(neg_rand_base_i * batch.opening.z1 - sg_rand_base_i);

                        {
                            auto terms = sg_rand_base_i * s;
                            for (int i = 0; i < terms.size(); ++i) {
                                scalars[i + 1] += terms[i];
                            }
                        }
                        scalars[0] -= rand_base_i * batch.opening.z2;
                        scalars.push_back(neg_rand_base_i * batch.opening.z1 * b0);
                        points.push_back(u);

                        auto rand_base_i_c_i = c * rand_base_i;
                        for (int i = 0; i < batch.opening.lr.size(); ++i) {
                            const auto [l, r] = batch.opening.lr[i];
                            points.push_back(l);
                            scalars.push_back(rand_base_i_c_i * chal_invs[i]);

                            points.push_back(r);
                            scalars.push_back(rand_base_i_c_i * chals[i]);
                        }

                        {
                            auto xi_i = typename scalar_field_type::value_type::one();
                            for (auto eval : batch.evaluations) {
                                for (auto comm : eval.commitment.unshifted) {
                                    scalars.push_back(rand_base_i_c_i * xi_i);
                                    points.push_back(comm);

                                    xi_i *= batch.xi;
                                }

                                if (eval.bound >= 0) {
                                    if (eval.commitment.shifted != 0) {
                                        scalars.push_back(rand_base_i_c_i * xi_i);
                                        points.push_back(eval.commitment.shifted);

                                        xi_i *= batch.xi;
                                    }
                                }
                            }
                        }

                        scalars.push_back(rand_base_i_c_i * combined_inner_product0);
                        points.push_back(u);
                        scalars.push_back(rand_base_i);
                        points.push_back(batch.opening.delta);

                        rand_base_i *= rand_base;
                        sg_rand_base_i *= sg_rand_base;

                        return (algebra::multiexp_with_mixed_addition<multiexp_method>(
                                    points.begin(), points.end(), scalars.begin(), scalars.end(), 1) ==
                                typename group_type::value_type::zero());
                    }
                };

            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_KIMCHI_PEDERSEN_COMMITMENT_SCHEME_HPP
