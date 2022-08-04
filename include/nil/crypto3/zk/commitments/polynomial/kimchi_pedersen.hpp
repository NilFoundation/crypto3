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
#include <nil/crypto3/algebra/multiexp/inner_product.hpp>

#include <nil/crypto3/zk/transcript/kimchi_transcript.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail/mapping.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail/kimchi_functions.hpp>

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

                        params_type(std::vector<typename group_type::value_type> &g, typename group_type::value_type& h, 
                                    typename scalar_field_type::value_type &endo_r, typename base_field_type::value_type& endo_q) :
                                    g(g), h(h), endo_r(endo_r), endo_q(endo_q) {}
                    };

                    struct commitment_type {
                        std::vector<typename group_type::value_type> unshifted;
                        typename group_type::value_type shifted = group_type::value_type::zero();
                    };

                    struct blinding_type {
                        std::vector<typename scalar_field_type::value_type> unshifted;
                        typename scalar_field_type::value_type shifted = scalar_field_type::value_type::zero();
                    };
                    typedef std::tuple<commitment_type, blinding_type> blinded_commitment_type;

                    struct poly_type_single {
                        // polynomial itself
                        math::polynomial<typename scalar_field_type::value_type> coeffs;
                        // optional degree bound - poly degree must not exceed it
                        int bound = -1;
                        // chunked commitment
                        blinding_type commit;

                        poly_type_single(math::polynomial<typename scalar_field_type::value_type>& coeffs, int bound,
                                    blinding_type& commit) : coeffs(coeffs), bound(bound), commit(commit) {}
                    };

                    typedef std::vector<poly_type_single> poly_type;

                    struct proof_type {
                        std::vector<std::tuple<typename group_type::value_type, typename group_type::value_type>> lr;

                        typename group_type::value_type delta;

                        typename scalar_field_type::value_type z1;
                        typename scalar_field_type::value_type z2;

                        typename group_type::value_type sg;

                        std::tuple<std::vector<typename scalar_field_type::value_type>, std::vector<typename scalar_field_type::value_type> >
                        challenges(typename scalar_field_type::value_type& endo_r, sponge_type& sponge){
                            std::vector<typename scalar_field_type::value_type> chal, chal_invs;
                            for(auto &[l, r] : lr){
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

                        evaluation_type(commitment_type& commit, std::vector<std::vector<typename scalar_field_type::value_type>>& evaluations, unsigned int bound) : 
                                commit(commit), evaluations(evaluations), bound(bound) { }
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
                        typename base_field_type::value_type q = algebra::random_element<base_field_type>();
                        return params_type(g, h, r, q);
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
                                    params.g.end() - bound % g_len, params.g.end(), poly.begin() + start, poly.end(),
                                    1);
                            }
                        }

                        // masking part
                        typename scalar_field_type::value_type w = 0x36FB00AD544E073B92B4E700D9C49DE6FC93536CAE0C612C18FBE5F6D8E8EEF2_cppui256;
                        
                        for (auto &i : res.unshifted) {
                            // w = algebra::random_element<scalar_field_type>();
                            i = i + w * params.h;
                            blind_res.unshifted.push_back(w);
                        }
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
                        for(; power_of_two < params.g.size(); power_of_two <<= 1);
                        
                        g.resize(power_of_two, group_type::value_type::zero());

                        // computing a and blinding factor
                        std::vector<typename scalar_field_type::value_type> a(
                            params.g.size(), scalar_field_type::value_type::zero());
                        typename scalar_field_type::value_type blinding_factor = scalar_field_type::value_type::zero();
                        typename scalar_field_type::value_type scale = scalar_field_type::value_type::one();

                        for (auto &polynom : plms) {
                            auto offset = polynom.coeffs.begin();
                            int j = 0;

                            if (polynom.bound >= 0) {
                                while (j < polynom.commit.unshifted.size()) {
                                    auto end_iter =
                                        (offset + params.g.size() > polynom.coeffs.end() ? polynom.coeffs.end() :
                                                                                           offset + params.g.size());
                                    auto segment = std::vector<typename scalar_field_type::value_type>(offset, end_iter);
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
                                    auto segment = std::vector<typename scalar_field_type::value_type>(offset, end_iter);
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
                        for (auto e : elm) {
                            auto spare = scalar_field_type::value_type::one();
                            for (int i = 0; i < power_of_two; ++i) {
                                b[i] += scale * spare;
                                spare *= e;
                            }
                            scale *= evalscale;
                        }

                        typename scalar_field_type::value_type inner_product_in_vec = algebra::inner_product(a.begin(), a.end(), b.begin(), b.end());
                        sponge.absorb_fr(functions::shift_scalar(inner_product_in_vec));
                        typename group_type::value_type u = group_map.to_group(sponge.challenge_fq());

                        std::vector<typename scalar_field_type::value_type> chals;
                        std::vector<typename scalar_field_type::value_type> chal_invs;

                        std::vector<typename group_type::value_type> g_low, g_high;
                        std::vector<typename scalar_field_type::value_type> a_low, a_high, b_low, b_high;

                        std::vector<typename scalar_field_type::value_type> rand_vals = {
                                    typename scalar_field_type::value_type(0x1A842A688E600F012637FE181292F70C4347B5AE0D9EA9CE7CF18592C345CF73_cppui256),
                                    typename scalar_field_type::value_type(0x2059462D60621F70620EA697FA1382EC5553A3DADB3CF9072201E09871B8284C_cppui256),
                                    typename scalar_field_type::value_type(0x2747337D1C4F9894747074C771E8EC7F570640E5D0CAF30FDDC446C00FA48707_cppui256),
                                    typename scalar_field_type::value_type(0x2DD5047C3EEEF37930E8FA4AD9691B27CF86D3ED39D4DEC4FC6D4E8EE4FF0415_cppui256),
                                    typename scalar_field_type::value_type(0x12C387C69BDD436F65AB607A4ED7C62714872EDBF800518B58E76F5106650B29_cppui256),
                                    typename scalar_field_type::value_type(0x3CF70C3A89749A45DB5236B8DE167A37762526C45270138A9FCDF2352B1899DA_cppui256),
                                    typename scalar_field_type::value_type(0x1BDF55BC84C1A0E0F7F6834949FCF90279B9D21C17DBC9928202C49039570598_cppui256),
                                    typename scalar_field_type::value_type(0x09441E95A82199EFC390152C5039C0D0566A90B7F6D1AA5813B2DAB90110FF90_cppui256),
                                    };
                        int i = 0;
                        int rounds_num = 0;
                        while (power_of_two > 1) {
                            power_of_two >>= 1;
                            g_low.assign(g.begin(), g.begin() + power_of_two);
                            g_high.assign(g.begin() + power_of_two, g.end());
                            a_low.assign(a.begin(), a.begin() + power_of_two);
                            a_high.assign(a.begin() + power_of_two, a.end());
                            b_low.assign(b.begin(), b.begin() + power_of_two);
                            b_high.assign(b.begin() + power_of_two, b.end());

                            typename scalar_field_type::value_type rand_l = rand_vals[i++]; //algebra::random_element<scalar_field_type>();
                            typename scalar_field_type::value_type rand_r = rand_vals[i++]; //algebra::random_element<scalar_field_type>();

                            typename group_type::value_type l = algebra::multiexp_with_mixed_addition<multiexp_method>(
                                        g_low.begin(), g_low.end(), a_high.begin(), a_high.end(), 1) +
                                        rand_l * params.h +
                                        algebra::inner_product(a_high.begin(), a_high.end(), b_low.begin(), b_low.end()) * u;
                            typename group_type::value_type r = algebra::multiexp_with_mixed_addition<multiexp_method>(
                                        g_high.begin(), g_high.end(), a_low.begin(), a_low.end(), 1) +
                                        rand_r * params.h +
                                        algebra::inner_product(a_low.begin(), a_low.end(), b_high.begin(), b_high.end()) * u;

                            res.lr.emplace_back(l, r);
                            blinders.emplace_back(rand_l, rand_r);
                            
                            sponge.absorb_g(l);
                            sponge.absorb_g(r);
                            typename scalar_field_type::value_type u_scalar = sponge.squeeze_challenge(params.endo_r);    // u_pre to field using endo_r
                            typename scalar_field_type::value_type u_scalar_inv = u_scalar.inversed();
                            chals.push_back(u_scalar);
                            chal_invs.push_back(u_scalar_inv);

                            auto compress_function_u_inv = [&u_scalar_inv](auto& first, auto& second){ 
                                return first * u_scalar_inv + second; 
                            };

                            auto compress_function_u = [&u_scalar](auto& first, auto& second){ 
                                return first * u_scalar + second; 
                            };

                            a.resize(a_high.size());
                            std::transform(a_high.begin(), a_high.end(), a_low.begin(), a.begin(), compress_function_u_inv);
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
                        typename scalar_field_type::value_type d = typename scalar_field_type::value_type(0x375B4A9785503C24531723DB1F31B50B79C3D1EC9F95DB7645A3EDA03862B588_cppui256); // algebra::random_element<scalar_field_type>();
                        typename scalar_field_type::value_type r_delta = typename scalar_field_type::value_type(0x12688FE351ED01F3BB2EB6B0FA2A70FB232654F32B08990DC3A411E527776A89_cppui256); // algebra::random_element<scalar_field_type>();

                        typename group_type::value_type delta = (g0 + u * b0) * d + params.h * r_delta;
                        sponge.absorb_g(delta);
                        typename scalar_field_type::value_type c = sponge.squeeze_challenge(params.endo_r);    // to field using endo_r

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

                        for (const auto &[evals_tr, bound] : polys) {

                            std::vector<std::vector<typename scalar_field_type::value_type>> evals;
                            for (int i = 0; i < evals_tr.evaluations[0].size(); ++i) {
                                std::vector<typename scalar_field_type::value_type> ev;
                                for (int j = 0; j < evals_tr.evaluations.size(); ++j) {
                                    ev.push_back(evals_tr.evaluations[j][i]);
                                }
                                evals.push_back(ev);
                            }

                            for (auto &eval : evals) {
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

                                math::polynomial<typename scalar_field_type::value_type> shifted_evals;
                                for (int i = 0; i < last_evals.size(); ++i) {
                                    shifted_evals.push_back(evaluation_points[i].pow(g_size - bound % g_size) *
                                                            last_evals[i]);
                                }

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
                    b_poly_coefficients(const std::vector<typename scalar_field_type::value_type> &chals) {
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
                                            batchproof_type &batch) {

                        std::size_t power_of_two = 1;
                        for(; power_of_two < params.g.size(); power_of_two <<= 1);

                        std::vector<typename group_type::value_type> points = {params.h};
                        points.insert(points.end(), params.g.begin(), params.g.end());
                        points.resize(power_of_two + 1, group_type::value_type::zero());

                        std::vector<typename scalar_field_type::value_type> scalars(power_of_two + 1, scalar_field_type::value_type::zero());                        

                        typename scalar_field_type::value_type rand_base(0x277D4079C3A1EAE81D5D2925EBFB31E9A5EFBCE36DDD7C8667EA9547F1A6A95F_cppui256);// = algebra::random_element<scalar_field_type>();
                        typename scalar_field_type::value_type sg_rand_base(0x3714FD9D8360014DB1E1555D8AF20360E097DB966098650A54AC901EAEC808E2_cppui256);// = algebra::random_element<scalar_field_type>();
                        typename scalar_field_type::value_type rand_base_i = scalar_field_type::value_type::one();
                        typename scalar_field_type::value_type sg_rand_base_i = scalar_field_type::value_type::one();

                        std::vector<std::tuple<evaluation_type, int>> es;
                        for (auto eval : batch.evaluation) {
                            int bnd = -1;
                            if (!eval.commit.shifted.is_zero()) {
                                bnd = eval.bound;
                            }
                            es.emplace_back(eval, bnd);
                        }

                        typename scalar_field_type::value_type combined_inner_product0 =
                            combined_inner_product(batch.evaluation_points, batch.xi, batch.r, es, params.g.size());
                        batch.sponge.absorb_fr(functions::shift_scalar(combined_inner_product0));
                        typename base_field_type::value_type t = batch.sponge.challenge_fq();
                        typename group_type::value_type u = group_map.to_group(t);
                        const auto &[chals, chal_invs] = batch.opening.challenges(params.endo_r, batch.sponge);
                        batch.sponge.absorb_g(batch.opening.delta);

                        typename scalar_field_type::value_type c = batch.sponge.squeeze_challenge(params.endo_r);    // to field using endo_r

                        typename scalar_field_type::value_type scale = scalar_field_type::value_type::one();
                        typename scalar_field_type::value_type b0 = scalar_field_type::value_type::zero();

                        for (auto e : batch.evaluation_points) {
                            typename scalar_field_type::value_type term = b_poly(chals, e);
                            b0 += scale * term;
                            scale *= batch.r;
                        }

                        // typename scalar_field_type::value_type b0 = res;
                        
                        std::vector<typename scalar_field_type::value_type> s = b_poly_coefficients(chals);

                        auto neg_rand_base_i = -rand_base_i;

                        points.push_back(batch.opening.sg);
                        scalars.push_back(neg_rand_base_i * batch.opening.z1 - sg_rand_base_i);

                        // std::vector<typename scalar_field_type::value_type> terms(s.size());

                        std::transform(s.begin(), s.end(), s.begin(), [&sg_rand_base_i](auto &iter_s){
                            return iter_s * sg_rand_base_i;
                        });

                        for (int i = 0; i < s.size(); ++i) {
                            scalars[i + 1] += s[i];
                        }
                        
                        scalars[0] -= rand_base_i * batch.opening.z2;
                        scalars.push_back(neg_rand_base_i * batch.opening.z1 * b0);
                        points.push_back(u);

                        auto rand_base_i_c_i = c * rand_base_i;
                        // std::cout << "rand_base_i_c_i " << std::hex << rand_base_i_c_i.data << '\n';
                        for (int i = 0; i < batch.opening.lr.size(); ++i) {
                            const auto [l, r] = batch.opening.lr[i];
                            points.push_back(l);
                            scalars.push_back(rand_base_i_c_i * chal_invs[i]);

                            points.push_back(r);
                            scalars.push_back(rand_base_i_c_i * chals[i]);
                        }

                        auto xi_i = scalar_field_type::value_type::one();
                        for (auto eval : batch.evaluation) {
                            for (auto comm : eval.commit.unshifted) {
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
                        // std::cout << "xi " << std::hex << xi_i.data << '\n';
                        scalars.push_back(rand_base_i_c_i * combined_inner_product0);
                        points.push_back(u);
                        scalars.push_back(rand_base_i);
                        points.push_back(batch.opening.delta);

                        rand_base_i *= rand_base;
                        sg_rand_base_i *= sg_rand_base;

                        for(auto &a : points){
                            std::cout << "point " << std::hex << a.X.data << ' ' << std::hex << a.Y.data << '\n';
                        }
                        
                        for(auto &a : scalars){
                            std::cout << "scalar " << std::hex << a.data << '\n';
                        }
                        // std::cout << "size " << scalars.size() << '\n';


                        // std::vector<typename group_type::value_type> my_points = {
                        //     {0x092060386301c999aab4f263757836369ca27975e28bc7a8e5b2ce5b26262201_cppui256, 0x314fc4d83ae66a509f9d41be6165f2606a209a9b5805ee85ce20249c5ebcbe26_cppui256},
                        //     {0x121c4426885fd5a9701385aaf8d43e52e7660f1fc5afc5f6468cc55312fc60f8_cppui256, 0x21b439c01247ea3518c5ddeb324e4cb108af617780ddf766d96d3fd8ab028b70_cppui256},
                        //     {0x26c9349ff7fb4ab230a6f6aef045f451fbbe9b37c43c3274e2aa4b82d131fd26_cppui256, 0x1996274d67ec0464c51f79ccfa1f511c2aabb666abe67733ee8185b71b27a504_cppui256},
                        //     {0x26985f27306586711466c5b2c28754aa62fe33516d75cef1f7751f1a169713fd_cppui256, 0x2e8930092fe6a18b331ce0e6e27b413aa18e76394f18a2835da9fae10aa3229d_cppui256},
                        //     {0x014b2db7b753a74d454061fcb3ac537e1b4ba512f9ed258c996a59d9dacd13e5_cppui256, 0x06f392d371494fc39174c4b70c692b96f3b7c42da288f6b7aabf463334a952d0_cppui256},
                        //     {0x12ca0e2dbf286021cb76b7c12b6c9ad7fdf1d05f722f6ef14bd43e53e7b92120_cppui256, 0x216a80b79d3995d1f39ce19855c475052d1148acbdd379fe98961bfbd0a3e428_cppui256},
                        //     {0x1d257c1f4ec9872c9e06549bc910f7b7196f2e7cb120aec3fdceb049c7a0c9a5_cppui256, 0x191cbec20ed5ea342b6b395e92996215f7d93c675da56a13d548efb58524d336_cppui256},
                        //     {0x06236026ed7dc19c44540fbaf0c1c3498f82880a34422547fff519fff744bb48_cppui256, 0x3a02c5410dabde160bd09232a14f00b1ef6cd4d6285c90a8d41fa00bff922f0a_cppui256},
                        //     {0x079333fde60d3f670068b5a1d486eddd87ddf91d1e1fc000f387991b4ed848b4_cppui256, 0x3f7fc1a39fd74bdedc129195080d298cfc2c2cf714bad9f9334f0dafb035c200_cppui256},
                        //     {0x069b398c2968553b7987ff840cf0b71359d10f249f08c40898550a63f196d856_cppui256, 0x1b68bb879d6ec4efaa2207e212b59bad0d8e5e2493f99be3f2f24764046cd277_cppui256},
                        //     {0x2cbd65973ae0be0b9e652cec35efe509e1fa8dd8349dc1e644db494dc2b4fd75_cppui256, 0x1e27b8178e720407694f4ea1413b0cb87af4058cb308bbd68ff42d5078de243e_cppui256},
                        //     {0x0f29a22ef6949de85427f72ccd04e3f8f56837bb56da17d8fa5de9025e6b9ed5_cppui256, 0x26a2cd91bd2771e20decaacdc6ca96e7759668f3d0b7e8810866d27737627a59_cppui256},
                        //     typename group_type::value_type(),
                        //     typename group_type::value_type(),
                        //     typename group_type::value_type(),
                        //     typename group_type::value_type(),
                        //     typename group_type::value_type(),
                        //     {0x183e89a07fae7189d90bceced87af3a3666ed065d49910212098fa3e3e973d36_cppui256, 0x315eb7367d9d9e0e4e1077918da61500cd2ef0405d63b7a4e18d05ce95d0c95b_cppui256},
                        //     {0x1b6cac7f49cdf1e2ff16114d3b56746f400ea818a1a3b601b1bea800e4c143b9_cppui256, 0x098c419958c9f484574fde569455be6a1b2489bfcced4f19cdbdf1587286aac7_cppui256},
                        //     {0x2cbcf92e54f2ad975359f6390a562dd79c52847af729c16c4a1d55234be23f72_cppui256, 0x2b0fb10e330db2df2e65e899ad165b46ca9bd0f25bf86ed2145bab55524826de_cppui256},
                        //     {0x0de54af192b1e666bf432b369256f28fa7090d320c86e6804a434c07d19ace0f_cppui256, 0x016a01b519f302a1c44cd54372c73bc1d25bd90db7cda7e4e01aed13e7cf26f9_cppui256},
                        //     {0x0b884baaeaf73060519f5d8b8539a1567333f1df41da6ee06092487174bd9fcb_cppui256, 0x2bef27d89d61a901c97a85bf9dacfa1f5042b8a96fe1adca194a96ade865e745_cppui256},
                        //     {0x2277a0752d91a0d3917f74f00c0bb91ad4621353da74331a6103838cf386567c_cppui256, 0x2e88cca90ecf1dce78e089eab2c42398df49f61d6762c3edaa1e27861ace0bd8_cppui256},
                        //     {0x038afa6f58bd597a9b848d71239dfd5db8768302e5c8567e583af19e52821ad2_cppui256, 0x17b1ac3ec136fdf18fb47a079b32bb41935cd7e7327e40e849c754824d9d5ad6_cppui256},
                        //     {0x330b8e2245ddf677aa75bfe3eb513158ab9bcad4865992139942f41c99c78cf7_cppui256, 0x1d601026f5a2812cdd7e92b99fb5c9c5e4afb84e1b35dfb5695c11a61cc9d7a5_cppui256},
                        //     {0x0a33f7b5e3e0be1f2478c0829a533b698abfc03c7b1377bc4d5c95d7378aed17_cppui256, 0x38537bab228e76478e4357cccbcb1977b041d68a637b3b90e88c0d4bc987154d_cppui256},
                        //     {0x063120f148e4c430a4a7e950b02129ebbca7e2b1e4511598b9c705dff3af7893_cppui256, 0x175502fd4397a1a9a6c22384cb6a9ab73a51d82dfeaf82f97d6bf3b80337d84a_cppui256},
                        //     {0x3a445ac8ca34ae5c12e66c3e9d3cc5df572f109629e9eafb9e7de451302aceb2_cppui256, 0x0280e113c668a50ec5fbc7654a8417176f614cd6e1658edaa43034ada563c9d2_cppui256},
                        //     {0x1b6cac7f49cdf1e2ff16114d3b56746f400ea818a1a3b601b1bea800e4c143b9_cppui256, 0x098c419958c9f484574fde569455be6a1b2489bfcced4f19cdbdf1587286aac7_cppui256},
                        //     {0x14e1f73486f2f8deb46b82b291b0d986fa08ef24cb60925813610d996122aa01_cppui256, 0x12fe65849363bd69bf69236dce9d7227c91083bc7876876c26f89fdc889154a1_cppui256},
                        // };

                        // std::vector<typename scalar_field_type::value_type> my_scalars = {
                        //     0x0502C4136D13D43292AB621B900693AE14AFAC97E6D44589EB18921420D270DD_cppui256,
                        //     0x0000000000000000000000000000000000000000000000000000000000000001_cppui256,
                        //     0x3EF2CFF891B858662ED2F48B539F99450C83383A625A2E3B6AA92F93280E1F54_cppui256,
                        //     0x33E62A38C5E158DAAAD7F039CD637376FA9434AF4479C0364F5F2F58383C41BF_cppui256,
                        //     0x276E49C171A4DFEF98815D27CD4756F531E5F0BD16F256FBC8D9145BA68A3CA6_cppui256,
                        //     0x1E4CB212111CD12F848E6C9FF6450881EB57EB2E766250A56F502A907A7716D6_cppui256,
                        //     0x14C6956DE17DF51614271610A29E61F76D086680FCEBFF14CBCD6097AC4C568E_cppui256,
                        //     0x2DBF59B2EFE92056DBB18199DC694B323BD180EB3C89B1AAC6D19A64B1A561B1_cppui256,
                        //     0x2754558056A6B6C4AB113122DE3A79DA6AAAE253307927EB87AEBFA8DADEE5EE_cppui256,
                        //     0x1485FB3E58C620F64BC4EBA19AAF8FA75BD58E80747C2C76D32EE2EE00D939B7_cppui256,
                        //     0x24F71A5034441349590FD1C144D1E13267A350B77DE3E80B211E68E07EF3FFA0_cppui256,
                        //     0x0E840876CB441EED0E2A4AEC4D1BED1A5C803FAC4D328A04C7983186845FD399_cppui256,
                        //     0x1503716950CCEDDB07FF2B0C3E557425CA563F3634D14649B5F8521598B93C95_cppui256,
                        //     0x2E2B87F3DF83EE97D07BCCE513B0B725160C6DD9D25639D9D6FF0A6A80D79414_cppui256,
                        //     0x37CD916F0E2348C8020A05FCF624A51149A2C7CE18C3B7DF79F0605A94B300D0_cppui256,
                        //     0x3AB20B4B6A8F0242D0ED74C514A2F6E9A3F2C9F941EA1E8C980136326E347820_cppui256,
                        //     0x1BD5E1E34EA9D4BE74B413BF0E9C40C2F45588FCDE539DE9925644CFA64ABD20_cppui256,
                        //     0x39B4F24092436C22519D92277005A423539CCAF3B328915E8C4D2C44012DC28B_cppui256,
                        //     0x1560807DE44BA19A4C0B926EAD5C5E932D8012ABF94A79C38A134CDCFD3CEFA6_cppui256,
                        //     0x0FBE30CE70451C441F4BD047DE1530989CC1B219FC4CBEACD067E4674DF0AD58_cppui256,
                        //     0x17338D95FD83B16ED84F4530CF5C1ECBCB136F5F2CAF3C7E469E7E2EB6BCF4C2_cppui256,
                        //     0x31754C973F04AF9AF6964C90351DFFD830412CB68715BFBC62C6F5273B2BA814_cppui256,
                        //     0x3A7A1D96F55359E7D63699C689490352C7699C571542A05D45DCCA95C1FB54C6_cppui256,
                        //     0x367B5BA1C4DA2C737CAC0B098A5005BD2EEBA87340D6B4BCFA187D14D128D862_cppui256,
                        //     0x2165872693C67A330AA022DB8ADDCAFC8216AC0EEAC690F33457F2C0A97048D6_cppui256,
                        //     0x1DD69A916CA3B5A6EB83E9542FDFEE1E61C22C82333A61B7B0D3F730B92C3BF6_cppui256,
                        //     0x0ECE005AD0DF893B34FCCD582C20586A30C7D13C4351AF3AD05356FE721C9414_cppui256,
                        //     0x12906C0C1045D7DE2B3AE0532F18F1DD4398F95A569FA557690758D822B2DAF5_cppui256,
                        //     0x339E425C16C09EB979AF6CE9A515AE30F29E324754B1AC5194F7634814DAF207_cppui256,
                        //     0x0000000000000000000000000000000000000000000000000000000000000001_cppui256,
                        // };
                        auto res_point = algebra::multiexp_with_mixed_addition<multiexp_method>(
                                    my_points.begin(), my_points.end(), my_scalars.begin(), my_scalars.end(), 1);
                        
                        std::cout << "res_point " << std::hex << res_point.X.data << ' ' << std::hex << res_point.Y.data << '\n';
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
