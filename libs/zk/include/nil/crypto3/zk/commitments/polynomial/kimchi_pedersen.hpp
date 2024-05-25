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
#include <unordered_map>
#include <algorithm>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/domains/basic_radix2_domain.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>
#include <nil/crypto3/algebra/multiexp/inner_product.hpp>

#include <nil/crypto3/zk/transcript/kimchi_transcript.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail/mapping.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail/kimchi_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {

                template<typename CurveType>
                struct kimchi_pedersen {
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::base_field_type base_field_type;
                    typedef typename CurveType::template g1_type<algebra::curves::coordinates::affine> group_type;

                    typedef algebra::policies::multiexp_method_BDLO12 multiexp_method;

                    typedef zk::transcript::DefaultFqSponge<CurveType> sponge_type;
                    typedef snark::group_map<CurveType> group_map_type;
                    typedef snark::kimchi_functions<CurveType> functions;
                    // using multiexp = algebra::multiexp_with_mixed_addition<multiexp_method>;

                    struct params_type {
                        // vector of n distinct curve points of unknown discrete logarithm
                        std::vector<typename group_type::value_type> g;
                        // distinct curve point of unknown discrete logarithm for blinding the commitment
                        typename group_type::value_type h;
                        // coefficients for the curve endomorphism
                        typename scalar_field_type::value_type endo_r;
                        typename base_field_type::value_type endo_q;
                        std::unordered_map<std::size_t, std::vector<typename group_type::value_type> > lagrange_bases;


                        // define parameters of protocol
                        params_type(std::vector<typename group_type::value_type> &g, typename group_type::value_type &h,
                                    typename scalar_field_type::value_type &endo_r,
                                    typename base_field_type::value_type &endo_q,
                                    std::unordered_map<std::size_t, std::vector<typename group_type::value_type> > &lagrange_bases)
                                :
                                g(g), h(h), endo_r(endo_r), endo_q(endo_q), lagrange_bases(lagrange_bases) {}

                        params_type(std::size_t depth) : h(algebra::random_element<group_type>()),
                                                         endo_r(algebra::random_element<scalar_field_type>()),
                                                         endo_q(algebra::random_element<base_field_type>()) {
                            for (int i = 0; i < depth; ++i) {
                                g.push_back(algebra::random_element<group_type>());
                            }
                        }

                        params_type() = default;

                        void add_lagrange_basis(math::basic_radix2_domain<scalar_field_type> &domain) {
                            std::size_t n = domain.size();
                            BOOST_ASSERT_MSG(n <= g.size(),
                                             "add lagrange basis: Domain size {} larger than SRS size {}");

                            if (lagrange_bases.contains(n)) {
                                return;
                            }

                            // std::vector<typename group_type::value_type> lg(g.begin(), g.begin() + n);
                            lagrange_bases[n] = std::vector<typename group_type::value_type>(g.begin(), g.begin() + n);

                            domain.inverse_fft(lagrange_bases[n]);
                        }
                    };

                    template<typename value_type>
                    struct poly_comm {
                        typedef poly_comm<value_type> poly_comm_type;
                        std::vector<value_type> unshifted;
                        value_type shifted;

                        poly_comm() = default;

                        poly_comm(std::vector<value_type> &unshifted, value_type &shifted) :
                                unshifted(unshifted), shifted(shifted) {}

                        static poly_comm<value_type> multi_scalar_mul(std::vector<poly_comm<value_type>> &commits,
                                                                      std::vector<typename scalar_field_type::value_type> &elm) {

                            if (commits.empty()) {
                                return poly_comm<value_type>();
                            }
                            std::vector<value_type> points;
                            for (auto &commit: commits) {
                                points.push_back(commit.shifted);
                            }
                            value_type shifted = algebra::multiexp_with_mixed_addition<multiexp_method>(
                                    points.begin(), points.end(), elm.begin(), elm.end(), 1);

                            std::vector<value_type> unshifted;
                            std::size_t n = commits.front().unshifted.size();
                            for (auto &commit: commits) {
                                if (n > commit.unshifted.size()) {
                                    n = commit.unshifted.size();
                                }
                            }
                            // *std::max_element(commits.begin(), commits.end(), [](auto &first, auto &second){
                            // return first.unshifted.size() < second.unshifted.size();
                            // });

                            for (int i = 0; i < n; ++i) {
                                std::vector<value_type> points_for_unshifted;
                                std::vector<typename scalar_field_type::value_type> scalars_for_unshifted;
                                for (int j = 0; j < commits.size(); ++j) {
                                    if (i < commits[j].unshifted.size()) {
                                        points_for_unshifted.push_back(commits[j].unshifted[i]);
                                        scalars_for_unshifted.push_back(elm[j]);
                                    }
                                }

                                unshifted.push_back(algebra::multiexp_with_mixed_addition<multiexp_method>(
                                        points_for_unshifted.begin(), points_for_unshifted.end(),
                                        scalars_for_unshifted.begin(), scalars_for_unshifted.end(), 1));
                            }

                            return poly_comm<value_type>(unshifted, shifted);
                        }

                        poly_comm_type chunk_commitment(typename scalar_field_type::value_type &zeta_n) {
                            value_type res;
                            for (auto iter = unshifted.rbegin(); iter < unshifted.rend(); ++iter) {
                                res = res * zeta_n;
                                res = res + (*iter);
                            }

                            std::vector<value_type> unshifted_temp = {res};
                            return poly_comm_type(
                                    unshifted_temp,
                                    shifted
                            );
                        }

                        poly_comm_type operator-(poly_comm_type other) {
                            std::vector<value_type> unshifted_temp;

                            std::size_t n1 = this->unshifted.size();
                            std::size_t n2 = other.unshifted.size();
                            std::size_t min_size = std::min(n1, n2);
                            // std::size_t max_size = std::max(n1, n2);

                            int i = 0;
                            for (; i < min_size; ++i) {
                                unshifted_temp.push_back(this->unshifted[i] - other.unshifted[i]);
                            }
                            for (; i < n1; ++i) {
                                unshifted_temp.push_back(this->unshifted[i]);
                            }
                            for (; i < n2; ++i) {
                                unshifted_temp.push_back(other.unshifted[i]);
                            }

                            value_type shifted_temp;
                            if (this->shifted == value_type::zero()) {
                                shifted_temp = other.shifted;
                            } else if (other.shifted == value_type::zero()) {
                                shifted_temp = this->shifted;
                            } else {
                                shifted_temp = this->shifted - other.shifted;
                            }

                            return poly_comm_type(unshifted_temp, shifted_temp);
                        }

                        poly_comm_type operator+(poly_comm_type other) {
                            std::vector<value_type> unshifted_temp;

                            std::size_t n1 = this->unshifted.size();
                            std::size_t n2 = other.unshifted.size();
                            std::size_t min_size = std::min(n1, n2);
                            // std::size_t max_size = std::max(n1, n2);

                            int i = 0;
                            for (; i < min_size; ++i) {
                                unshifted_temp.push_back(this->unshifted[i] + other.unshifted[i]);
                            }
                            for (; i < n1; ++i) {
                                unshifted_temp.push_back(this->unshifted[i]);
                            }
                            for (; i < n2; ++i) {
                                unshifted_temp.push_back(other.unshifted[i]);
                            }

                            value_type shifted_temp;
                            if (!this->shifted) {
                                shifted_temp = other.shifted;
                            } else if (!other.shifted) {
                                shifted_temp = this->shifted;
                            } else {
                                shifted_temp = this->shifted + other.shifted;
                            }

                            return poly_comm_type(unshifted_temp, shifted_temp);
                        }

                        poly_comm_type scale(typename scalar_field_type::value_type c) {
                            std::vector<value_type> unshifted_temp;

                            for (auto &a: unshifted) {
                                unshifted_temp.push_back(a * c);
                            }

                            value_type shifted_temp = shifted * c;
                            return poly_comm_type(unshifted_temp, shifted_temp);
                        }
                    };

                    typedef poly_comm<typename group_type::value_type> commitment_type;
                    typedef poly_comm<typename scalar_field_type::value_type> blinding_type;
                    typedef std::tuple<commitment_type, blinding_type> blinded_commitment_type;

                    struct poly_type_single {
                        // polynomial itself
                        math::polynomial<typename scalar_field_type::value_type> coeffs;
                        // optional degree bound - poly degree must not exceed it
                        std::size_t bound = -1;
                        // chunked commitment
                        blinding_type commit;

                        poly_type_single(math::polynomial<typename scalar_field_type::value_type> &coeffs, int bound,
                                         blinding_type &commit) : coeffs(coeffs), bound(bound), commit(commit) {}
                    };

                    typedef std::vector<poly_type_single> poly_type;

                    struct proof_type {
                        std::vector<std::tuple<typename group_type::value_type, typename group_type::value_type>> lr;

                        typename group_type::value_type delta;

                        typename scalar_field_type::value_type z1;
                        typename scalar_field_type::value_type z2;

                        typename group_type::value_type sg;

                        std::tuple<std::vector<typename scalar_field_type::value_type>, std::vector<typename scalar_field_type::value_type> >
                        challenges(typename scalar_field_type::value_type &endo_r, sponge_type &sponge) {
                            std::vector<typename scalar_field_type::value_type> chal, chal_invs;
                            for (auto &[l, r]: lr) {
                                sponge.absorb_g(l);
                                sponge.absorb_g(r);
                                chal.push_back(sponge.squeeze_challenge(endo_r));
                                chal_invs.push_back(chal.back().inversed());
                            }

                            return std::make_tuple(chal, chal_invs);
                        }

                    };

                    struct evaluation_type {
                        // polycommitment
                        commitment_type commit;
                        // evals of polynomial at a set of points
                        std::vector<std::vector<typename scalar_field_type::value_type>> evaluations;
                        // optional degree bound
                        int bound = -1;

                        evaluation_type(commitment_type commit,
                                        std::vector<std::vector<typename scalar_field_type::value_type>> &evaluations,
                                        int bound) :
                                commit(commit), evaluations(evaluations), bound(bound) {}
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

                        batchproof_type(sponge_type sponge,
                                        std::vector<evaluation_type> evaluation,
                                        std::vector<typename scalar_field_type::value_type> evaluation_points,
                                        typename scalar_field_type::value_type xi,
                                        typename scalar_field_type::value_type r,
                                        proof_type opening
                        ) : sponge(sponge), evaluation(evaluation), evaluation_points(evaluation_points),
                            xi(xi), r(r), opening(opening) {}

                        batchproof_type() = default;
                    };

                    static params_type setup(const int d) {
                        // define parameters of protocol
                        return params_type(d);
                    }

                    static blinded_commitment_type
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
                            if (!poly.is_zero() && start < poly.size()) {
                                res.shifted = algebra::multiexp_with_mixed_addition<multiexp_method>(
                                        params.g.end() - bound % g_len, params.g.end(), poly.begin() + start,
                                        poly.end(),
                                        1);
                            }
                        }

                        // masking part
                        typename scalar_field_type::value_type w;

                        for (auto &i: res.unshifted) {
                            w = algebra::random_element<scalar_field_type>();
                            i = i + w * params.h;
                            blind_res.unshifted.push_back(w);
                        }

                        w = algebra::random_element<scalar_field_type>();

                        if (res.shifted != group_type::value_type::zero()) {
                            res.shifted = res.shifted + w * params.h;
                            blind_res.shifted = w;
                        }

                        return blinded_commitment_type(res, blind_res);
                    }

                    static proof_type proof_eval(const params_type &params, group_map_type &group_map,
                                                 const poly_type &plms,
                                                 const std::vector<typename scalar_field_type::value_type> &elm,
                                                 const typename scalar_field_type::value_type &polyscale,
                                                 const typename scalar_field_type::value_type &evalscale,
                                                 sponge_type &sponge) {
                        proof_type res;
                        std::vector<typename group_type::value_type> g = params.g;
                        std::vector<
                                std::tuple<typename scalar_field_type::value_type, typename scalar_field_type::value_type>>
                                blinders;

                        // making vector of size g = 2^k
                        std::size_t power_of_two = 1;
                        for (; power_of_two < params.g.size(); power_of_two <<= 1);

                        g.resize(power_of_two, group_type::value_type::zero());

                        // computing a and blinding factor
                        math::polynomial<typename scalar_field_type::value_type> a(
                                params.g.size(), scalar_field_type::value_type::zero());
                        typename scalar_field_type::value_type blinding_factor = scalar_field_type::value_type::zero();
                        typename scalar_field_type::value_type scale = scalar_field_type::value_type::one();

                        for (auto &polynom: plms) {
                            auto offset = polynom.coeffs.begin();
                            int j = 0;

                            if (polynom.bound >= 0) {
                                while (j < polynom.commit.unshifted.size()) {
                                    auto end_iter =
                                            (offset + params.g.size() > polynom.coeffs.end() ? polynom.coeffs.end() :
                                             offset + params.g.size());
                                    auto segment = std::vector<typename scalar_field_type::value_type>(offset,
                                                                                                       end_iter);
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
                                    auto segment = std::vector<typename scalar_field_type::value_type>(offset,
                                                                                                       end_iter);
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
                        a.resize(power_of_two, scalar_field_type::value_type::zero());

                        // computing b
                        std::vector<typename scalar_field_type::value_type> b(
                                power_of_two, scalar_field_type::value_type::zero());
                        scale = scalar_field_type::value_type::one();
                        for (auto e: elm) {
                            auto spare = scalar_field_type::value_type::one();
                            for (int i = 0; i < power_of_two; ++i) {
                                b[i] += scale * spare;
                                spare *= e;
                            }
                            scale *= evalscale;
                        }

                        typename scalar_field_type::value_type inner_product_in_vec = algebra::inner_product(a.begin(),
                                                                                                             a.end(),
                                                                                                             b.begin(),
                                                                                                             b.end());
                        sponge.absorb_fr(functions::shift_scalar(inner_product_in_vec));
                        typename group_type::value_type u = group_map.to_group(sponge.challenge_fq());

                        std::vector<typename scalar_field_type::value_type> chals;
                        std::vector<typename scalar_field_type::value_type> chal_invs;

                        std::vector<typename group_type::value_type> g_low, g_high;
                        std::vector<typename scalar_field_type::value_type> a_low, a_high, b_low, b_high;

                        while (power_of_two > 1) {
                            power_of_two >>= 1;
                            g_low.assign(g.begin(), g.begin() + power_of_two);
                            g_high.assign(g.begin() + power_of_two, g.end());
                            a_low.assign(a.begin(), a.begin() + power_of_two);
                            a_high.assign(a.begin() + power_of_two, a.end());
                            b_low.assign(b.begin(), b.begin() + power_of_two);
                            b_high.assign(b.begin() + power_of_two, b.end());

                            typename scalar_field_type::value_type rand_l = algebra::random_element<scalar_field_type>();
                            typename scalar_field_type::value_type rand_r = algebra::random_element<scalar_field_type>();

                            typename group_type::value_type l = algebra::multiexp_with_mixed_addition<multiexp_method>(
                                    g_low.begin(), g_low.end(), a_high.begin(), a_high.end(), 1) +
                                                                rand_l * params.h +
                                                                algebra::inner_product(a_high.begin(), a_high.end(),
                                                                                       b_low.begin(), b_low.end()) * u;
                            typename group_type::value_type r = algebra::multiexp_with_mixed_addition<multiexp_method>(
                                    g_high.begin(), g_high.end(), a_low.begin(), a_low.end(), 1) +
                                                                rand_r * params.h +
                                                                algebra::inner_product(a_low.begin(), a_low.end(),
                                                                                       b_high.begin(), b_high.end()) *
                                                                u;

                            res.lr.emplace_back(l, r);
                            blinders.emplace_back(rand_l, rand_r);

                            sponge.absorb_g(l);
                            sponge.absorb_g(r);
                            typename scalar_field_type::value_type u_scalar = sponge.squeeze_challenge(
                                    params.endo_r);    // u_pre to field using endo_r
                            typename scalar_field_type::value_type u_scalar_inv = u_scalar.inversed();
                            chals.push_back(u_scalar);
                            chal_invs.push_back(u_scalar_inv);

                            auto compress_function_u_inv = [&u_scalar_inv](auto &first, auto &second) {
                                return first * u_scalar_inv + second;
                            };

                            auto compress_function_u = [&u_scalar](auto &first, auto &second) {
                                return first * u_scalar + second;
                            };

                            a.resize(a_high.size());
                            std::transform(a_high.begin(), a_high.end(), a_low.begin(), a.begin(),
                                           compress_function_u_inv);
                            b.resize(b_high.size());
                            std::transform(b_high.begin(), b_high.end(), b_low.begin(), b.begin(), compress_function_u);
                            g.resize(g_high.size());
                            std::transform(g_high.begin(), g_high.end(), g_low.begin(), g.begin(), compress_function_u);
                        }
                        typename scalar_field_type::value_type a0 = a[0];
                        typename scalar_field_type::value_type b0 = b[0];
                        typename group_type::value_type g0 = g[0];

                        auto r_prime = blinding_factor;
                        for (int i = 0; i < blinders.size(); ++i) {
                            const auto &[l, r] = blinders[i];
                            r_prime += l * chal_invs[i] + r * chals[i];
                        }
                        typename scalar_field_type::value_type d = algebra::random_element<scalar_field_type>();
                        typename scalar_field_type::value_type r_delta = algebra::random_element<scalar_field_type>();

                        typename group_type::value_type delta = (g0 + u * b0) * d + params.h * r_delta;
                        sponge.absorb_g(delta);
                        typename scalar_field_type::value_type c = sponge.squeeze_challenge(
                                params.endo_r);    // to field using endo_r

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
                        typename scalar_field_type::value_type res = scalar_field_type::value_type::zero();
                        typename scalar_field_type::value_type xi_i = scalar_field_type::value_type::one();

                        for (const auto &[evals_tr, bound]: polys) {

                            std::vector<std::vector<typename scalar_field_type::value_type>> evals;
                            if (!evals_tr.evaluations.empty()) {
                                for (int i = 0; i < evals_tr.evaluations[0].size(); ++i) {
                                    std::vector<typename scalar_field_type::value_type> ev;
                                    for (int j = 0; j < evals_tr.evaluations.size(); ++j) {
                                        ev.push_back(evals_tr.evaluations[j][i]);
                                    }
                                    evals.push_back(ev);
                                }
                            }

                            for (auto &eval: evals) {
                                math::polynomial<typename scalar_field_type::value_type> polynom(eval);
                                typename scalar_field_type::value_type term = polynom.evaluate(r);
                                res += xi_i * term;
                                xi_i *= xi;
                            }
                            if (bound != -1) {
                                std::vector<typename scalar_field_type::value_type> last_evals(
                                        evaluation_points.size(), scalar_field_type::value_type::zero());
                                if (bound <= evals.size() * g_size) {
                                    last_evals = evals[evals.size() - 1];
                                }

                                std::vector<typename scalar_field_type::value_type> shifted_evals_vec;

                                for (int i = 0; i < last_evals.size(); ++i) {
                                    shifted_evals_vec.push_back(evaluation_points[i].pow(g_size - bound % g_size) *
                                                                last_evals[i]);
                                }

                                math::polynomial<typename scalar_field_type::value_type> shifted_evals(
                                        shifted_evals_vec);
                                res += xi_i * shifted_evals.evaluate(r);
                                xi_i *= xi;
                            }
                        }

                        return res;
                    }

                    static typename scalar_field_type::value_type
                    b_poly(const std::vector<typename scalar_field_type::value_type> &chals,
                           typename scalar_field_type::value_type x) {
                        auto k = chals.size();
                        std::vector<typename scalar_field_type::value_type> pow_twos = {x};

                        for (int i = 1; i < k; ++i) {
                            pow_twos.push_back(pow_twos.back().squared());
                        }

                        typename scalar_field_type::value_type res = scalar_field_type::value_type::one();
                        for (int i = 0; i < k; ++i) {
                            res *= scalar_field_type::value_type::one() + chals[i] * pow_twos[k - 1 - i];
                        }

                        return res;
                    }

                    static std::vector<typename scalar_field_type::value_type>
                    b_poly_coefficents(const std::vector<typename scalar_field_type::value_type> &chals) {
                        auto rounds = chals.size();
                        auto s_len = 1 << rounds;
                        std::vector<typename scalar_field_type::value_type> s(
                                s_len, scalar_field_type::value_type::one());
                        int k = 0;
                        int pow = 1;
                        for (int i = 1; i < s_len; ++i) {
                            (i == pow) ? (k += 1) : (k += 0);
                            (i == pow) ? (pow <<= 1) : (pow <<= 0);
                            s[i] = s[i - (pow >> 1)] * chals[rounds - 1 - (k - 1)];
                        }
                        return s;
                    }

                    static bool verify_eval(params_type &params, group_map_type &group_map,
                                            std::vector<batchproof_type> &batches) {

                        std::size_t power_of_two = 1;
                        for (; power_of_two < params.g.size(); power_of_two <<= 1);

                        std::vector<typename group_type::value_type> points = {params.h};
                        points.insert(points.end(), params.g.begin(), params.g.end());
                        points.resize(power_of_two + 1, group_type::value_type::zero());

                        std::vector<typename scalar_field_type::value_type> scalars(power_of_two + 1,
                                                                                    scalar_field_type::value_type::zero());

                        typename scalar_field_type::value_type rand_base = algebra::random_element<scalar_field_type>();
                        typename scalar_field_type::value_type sg_rand_base = algebra::random_element<scalar_field_type>();
                        typename scalar_field_type::value_type rand_base_i = scalar_field_type::value_type::one();
                        typename scalar_field_type::value_type sg_rand_base_i = scalar_field_type::value_type::one();

                        for (auto &batch: batches) {
                            std::vector<std::tuple<evaluation_type, int>> es;
                            for (auto eval: batch.evaluation) {
                                int bnd = -1;
                                if (!eval.commit.shifted.is_zero()) {
                                    bnd = eval.bound;
                                }
                                es.emplace_back(eval, bnd);
                            }

                            typename scalar_field_type::value_type combined_inner_product0 =
                                    combined_inner_product(batch.evaluation_points, batch.xi, batch.r, es,
                                                           params.g.size());

                            batch.sponge.absorb_fr(functions::shift_scalar(combined_inner_product0));
                            typename base_field_type::value_type t = batch.sponge.challenge_fq();
                            typename group_type::value_type u = group_map.to_group(t);
                            const auto &[chals, chal_invs] = batch.opening.challenges(params.endo_r, batch.sponge);
                            batch.sponge.absorb_g(batch.opening.delta);

                            typename scalar_field_type::value_type c = batch.sponge.squeeze_challenge(
                                    params.endo_r);    // to field using endo_r

                            typename scalar_field_type::value_type scale = scalar_field_type::value_type::one();
                            typename scalar_field_type::value_type b0 = scalar_field_type::value_type::zero();

                            for (auto e: batch.evaluation_points) {
                                typename scalar_field_type::value_type term = b_poly(chals, e);
                                b0 += scale * term;
                                scale *= batch.r;
                            }

                            std::vector<typename scalar_field_type::value_type> s = b_poly_coefficents(chals);

                            auto neg_rand_base_i = -rand_base_i;

                            points.push_back(batch.opening.sg);
                            scalars.push_back(neg_rand_base_i * batch.opening.z1 - sg_rand_base_i);

                            std::transform(s.begin(), s.end(), s.begin(), [&sg_rand_base_i](auto &iter_s) {
                                return iter_s * sg_rand_base_i;
                            });

                            for (int i = 0; i < s.size(); ++i) {
                                scalars[i + 1] += s[i];
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

                            auto xi_i = scalar_field_type::value_type::one();
                            for (auto eval: batch.evaluation) {
                                for (auto comm: eval.commit.unshifted) {
                                    scalars.push_back(rand_base_i_c_i * xi_i);
                                    points.push_back(comm);

                                    xi_i *= batch.xi;
                                }

                                if (eval.bound >= 0) {
                                    if (!eval.commit.shifted.is_zero()) {
                                        scalars.push_back(rand_base_i_c_i * xi_i);
                                        points.push_back(eval.commit.shifted);

                                        xi_i *= batch.xi;
                                    }
                                }
                            }

                            scalars.push_back(rand_base_i_c_i * combined_inner_product0);
                            points.push_back(u);
                            scalars.push_back(rand_base_i);
                            points.push_back(batch.opening.delta);

                            rand_base_i *= rand_base;
                            sg_rand_base_i *= sg_rand_base;
                        }

                        return (algebra::multiexp_with_mixed_addition<multiexp_method>(
                                points.begin(), points.end(), scalars.begin(), scalars.end(), 1) ==
                                group_type::value_type::zero());
                    }
                };
            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_KIMCHI_PEDERSEN_COMMITMENT_SCHEME_HPP
