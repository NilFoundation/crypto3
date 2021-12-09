//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_ELGAMAL_VERIFIABLE_HPP
#define CRYPTO3_PUBKEY_ELGAMAL_VERIFIABLE_HPP

#include <tuple>
#include <type_traits>
#include <iterator>
#include <vector>

#include <nil/crypto3/algebra/algorithms/pair.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/detail/basic_policy.hpp>

#include <nil/crypto3/pubkey/keys/private_key.hpp>
#include <nil/crypto3/pubkey/keys/verification_key.hpp>
#include <nil/crypto3/pubkey/operations/generate_keypair_op.hpp>
#include <nil/crypto3/pubkey/operations/encrypt_op.hpp>
#include <nil/crypto3/pubkey/operations/decrypt_op.hpp>
#include <nil/crypto3/pubkey/operations/verify_encryption_op.hpp>
#include <nil/crypto3/pubkey/operations/verify_decryption_op.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Curve, std::size_t BlockBits = 4>
            class elgamal_verifiable {
                typedef elgamal_verifiable<Curve, BlockBits> self_type;
                static_assert(BlockBits > 0);

            public:
                typedef Curve curve_type;
                static constexpr std::size_t block_bits = BlockBits;

                typedef public_key<self_type> public_key_type;
                typedef private_key<self_type> private_key_type;
                typedef verification_key<self_type> verification_key_type;
                typedef std::tuple<public_key_type, private_key_type, verification_key_type> keypair_type;

                typedef std::vector<typename Curve::template g1_type<>::value_type> cipher_type;
                typedef std::pair<std::vector<typename Curve::scalar_field_type::value_type>,
                                  typename Curve::template g1_type<>::value_type>
                    decipher_type;
            };

            template<typename Curve, std::size_t BlockBits>
            struct verification_key<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;
                typedef typename Curve::template g1_type<> g1_type;
                typedef typename Curve::template g2_type<> g2_type;

                // friend class

                verification_key() = default;
                verification_key(const typename g2_type::value_type &rho_g2,
                                 const std::vector<typename g2_type::value_type> &rho_sv_g2,
                                 const std::vector<typename g2_type::value_type> &rho_rhov_g2,
                                 const typename zk::snark::accumulation_vector<g1_type> &gamma_ABC_g1) :
                    rho_g2(rho_g2),
                    rho_sv_g2(rho_sv_g2), rho_rhov_g2(rho_rhov_g2), gamma_ABC_g1(gamma_ABC_g1) {
                }
                verification_key(typename g2_type::value_type &&rho_g2,
                                 std::vector<typename g2_type::value_type> &&rho_sv_g2,
                                 std::vector<typename g2_type::value_type> &&rho_rhov_g2,
                                 zk::snark::accumulation_vector<g1_type> &&gamma_ABC_g1) :
                    rho_g2(std::move(rho_g2)),
                    rho_sv_g2(std::move(rho_sv_g2)), rho_rhov_g2(std::move(rho_rhov_g2)),
                    gamma_ABC_g1(std::move(gamma_ABC_g1)) {
                }

            private:
                typename g2_type::value_type rho_g2;
                std::vector<typename g2_type::value_type> rho_sv_g2;
                std::vector<typename g2_type::value_type> rho_rhov_g2;
                // TODO: refactor
                zk::snark::accumulation_vector<g1_type> gamma_ABC_g1;
            };

            template<typename Curve, std::size_t BlockBits>
            struct public_key<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;

                typedef typename Curve::template g1_type<> g1_type;
                typedef typename Curve::template g2_type<> g2_type;

                friend class encrypt_op<scheme_type>;

                public_key() = default;
                public_key &operator=(const public_key &other) = default;
                public_key(const public_key &other) = default;
                public_key(public_key &&other) = default;
                public_key(const typename g1_type::value_type &delta_g1,
                           const std::vector<typename g1_type::value_type> &delta_s_g1,
                           const std::vector<typename g1_type::value_type> &t_g1,
                           const std::vector<typename g2_type::value_type> &t_g2,
                           const typename g1_type::value_type &delta_sum_s_g1,
                           const typename g1_type::value_type &gamma_inverse_sum_s_g1,
                           const typename zk::snark::accumulation_vector<g1_type> &gamma_ABC_g1) :
                    delta_g1(delta_g1),
                    delta_s_g1(delta_s_g1), t_g1(t_g1), t_g2(t_g2), delta_sum_s_g1(delta_sum_s_g1),
                    gamma_inverse_sum_s_g1(gamma_inverse_sum_s_g1), gamma_ABC_g1(gamma_ABC_g1) {
                }
                public_key(typename g1_type::value_type &&delta_g1,
                           std::vector<typename g1_type::value_type> &&delta_s_g1,
                           std::vector<typename g1_type::value_type> &&t_g1,
                           std::vector<typename g2_type::value_type> &&t_g2,
                           typename g1_type::value_type &&delta_sum_s_g1,
                           typename g1_type::value_type &&gamma_inverse_sum_s_g1,
                           zk::snark::accumulation_vector<g1_type> &&gamma_ABC_g1) :
                    delta_g1(std::move(delta_g1)),
                    delta_s_g1(std::move(delta_s_g1)), t_g1(std::move(t_g1)), t_g2(std::move(t_g2)),
                    delta_sum_s_g1(std::move(delta_sum_s_g1)),
                    gamma_inverse_sum_s_g1(std::move(gamma_inverse_sum_s_g1)), gamma_ABC_g1(std::move(gamma_ABC_g1)) {
                }

            private:
                typename g1_type::value_type delta_g1;
                std::vector<typename g1_type::value_type> delta_s_g1;
                std::vector<typename g1_type::value_type> t_g1;
                std::vector<typename g2_type::value_type> t_g2;
                typename g1_type::value_type delta_sum_s_g1;
                typename g1_type::value_type gamma_inverse_sum_s_g1;
                // TODO: refactor
                zk::snark::accumulation_vector<g1_type> gamma_ABC_g1;
            };

            template<typename Curve, std::size_t BlockBits>
            struct private_key<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;

                typedef typename Curve::scalar_field_type scalar_field_type;

                private_key() = default;
                private_key(const typename scalar_field_type::value_type &rho) : rho(rho) {
                }

            private:
                typename scalar_field_type::value_type rho;
            };

            template<typename Curve, std::size_t BlockBits>
            struct generate_keypair_op<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;
                typedef zk::snark::detail::r1cs_gg_ppzksnark_basic_policy<Curve, zk::snark::ProvingMode::EncryptedInput>
                    zksnark_policy_type;

                typedef typename scheme_type::public_key_type public_key_type;
                typedef typename scheme_type::private_key_type private_key_type;
                typedef typename scheme_type::verification_key_type verification_key_type;
                typedef typename scheme_type::keypair_type keypair_type;

                typedef typename Curve::scalar_field_type scalar_field_type;
                typedef typename Curve::template g1_type<> g1_type;
                typedef typename Curve::template g2_type<> g2_type;

                struct init_params_type {
                    const typename zksnark_policy_type::keypair &gg_keypair;
                    std::size_t msg_size;
                };
                struct internal_accumulator_type {
                    const typename zksnark_policy_type::keypair &gg_keypair;
                    std::size_t msg_size;
                    std::vector<typename scalar_field_type::value_type> rnd;
                };
                typedef keypair_type result_type;

                static inline internal_accumulator_type init_accumulator(const init_params_type &init_params) {
                    return {init_params.gg_keypair, init_params.msg_size,
                            std::vector<typename scalar_field_type::value_type> {}};
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    std::copy(first, last, std::back_inserter(acc.rnd));
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, InputRange range) {
                    update(acc, std::cbegin(range), std::cend(range));
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    auto rnd_iter = std::cbegin(acc.rnd);
                    const size_t input_size = acc.gg_keypair.second.gamma_ABC_g1.rest.values.size();

                    typename scalar_field_type::value_type s_sum = scalar_field_type::zero();

                    std::vector<typename g1_type::value_type> delta_s_g1;
                    typename g1_type::value_type delta_sum_s_g1;
                    typename g1_type::value_type gamma_inverse_sum_s_g1 = acc.gg_keypair.second.gamma_g1;

                    typename scalar_field_type::value_type rho = *rnd_iter++;
                    typename g2_type::value_type rho_g2 = rho * typename g2_type::value_type::one();
                    std::vector<typename g2_type::value_type> rho_sv_g2;
                    std::vector<typename g2_type::value_type> rho_rhov_g2;

                    std::vector<typename g1_type::value_type> t_g1;
                    std::vector<typename g2_type::value_type> t_g2;

                    delta_s_g1.reserve(input_size);
                    rho_sv_g2.reserve(input_size);
                    rho_rhov_g2.reserve(input_size);
                    t_g1.reserve(input_size);
                    t_g2.reserve(input_size + 1);

                    typename scalar_field_type::value_type t = *rnd_iter++;
                    t_g2.emplace_back(t * typename g2_type::value_type::one());
                    delta_sum_s_g1 = t * acc.gg_keypair.second.delta_g1;

                    for (size_t i = 1; i < acc.msg_size + 1; i++) {
                        typename scalar_field_type::value_type s = *rnd_iter++;
                        typename scalar_field_type::value_type v = *rnd_iter++;
                        typename scalar_field_type::value_type sv = s * v;
                        t = *rnd_iter++;

                        delta_s_g1.emplace_back(s * acc.gg_keypair.second.delta_g1);
                        t_g1.emplace_back(t * acc.gg_keypair.second.gamma_ABC_g1.rest.values[i]);
                        t_g2.emplace_back(t * typename g2_type::value_type::one());
                        delta_sum_s_g1 = delta_sum_s_g1 + (s * t) * acc.gg_keypair.second.delta_g1;
                        gamma_inverse_sum_s_g1 = gamma_inverse_sum_s_g1 + s * acc.gg_keypair.second.gamma_g1;

                        rho_sv_g2.emplace_back(sv * typename g2_type::value_type::one());
                        rho_rhov_g2.emplace_back(v * rho_g2);
                    }
                    gamma_inverse_sum_s_g1 = -gamma_inverse_sum_s_g1;

                    public_key_type pk(acc.gg_keypair.second.delta_g1, delta_s_g1, t_g1, t_g2, delta_sum_s_g1,
                                       gamma_inverse_sum_s_g1, acc.gg_keypair.second.gamma_ABC_g1);
                    private_key_type sk(rho);
                    verification_key_type vk(rho_g2, rho_sv_g2, rho_rhov_g2);

                    return {pk, sk, vk};
                }
            };

            template<typename Curve, std::size_t BlockBits>
            struct encrypt_op<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;
                typedef typename scheme_type::public_key_type public_key_type;

                typedef typename Curve::scalar_field_type scalar_field_type;
                typedef typename Curve::template g1_type<> g1_type;

                struct init_params_type {
                    const typename scalar_field_type::value_type &r;
                    const public_key_type &pubkey;
                };
                struct internal_accumulator_type {
                    std::vector<typename scalar_field_type::value_type> supplied_plain_text;
                    typename scalar_field_type::value_type r;
                    const public_key_type &pubkey;
                };
                typedef typename scheme_type::cipher_type result_type;

                static inline internal_accumulator_type init_accumulator(const init_params_type &init_params) {
                    return {std::vector<typename scalar_field_type::value_type> {}, init_params.r, init_params.pubkey};
                }

                // TODO: process input data in place
                // TODO: use marshaling module instead of custom marshaling to process input data
                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    std::copy(first, last, std::back_inserter(acc.supplied_plain_text));
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, InputRange range) {
                    update(acc, std::cbegin(range), std::cend(range));
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    const std::size_t input_size = acc.pubkey.gamma_ABC_g1.rest.values.size();
                    assert(input_size - 1 == acc.supplied_plain_text.size());

                    result_type ct_g1;
                    ct_g1.reserve(input_size + 2);
                    ct_g1.emplace_back(acc.r * acc.pubkey.delta_g1);

                    typename g1_type::value_type sum_tm_g1 = acc.r * acc.pubkey.delta_sum_s_g1;

                    for (std::size_t i = 0; i < input_size; ++i) {
                        ct_g1.emplace_back(acc.r * acc.pubkey.delta_s_g1[i] +
                                           acc.supplied_plain_text[i] * acc.pubkey.gamma_ABC_g1.rest.values[i + 1]);
                        sum_tm_g1 = sum_tm_g1 + acc.supplied_plain_text[i] * acc.pubkey.t_g1[i];
                    }
                    ct_g1.emplace_back(sum_tm_g1);

                    return ct_g1;
                }
            };

            template<typename Curve, std::size_t BlockBits>
            struct decrypt_op<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;
                typedef typename scheme_type::private_key_type private_key_type;
                typedef typename scheme_type::verification_key_type verification_key_type;

                typedef typename Curve::scalar_field_type scalar_field_type;
                typedef typename Curve::template g1_type<> g1_type;
                typedef typename Curve::gt_type gt_type;

                struct init_params_type {
                    const private_key_type &privkey;
                    const verification_key_type &vk;
                };
                struct internal_accumulator_type {
                    std::vector<typename g1_type::value_type> supplied_cipher_text;
                    const private_key_type &privkey;
                    const verification_key_type &vk;
                };
                typedef typename scheme_type::decipher_type result_type;

                static inline internal_accumulator_type init_accumulator(const init_params_type &init_params) {
                    return internal_accumulator_type {std::vector<typename scalar_field_type::value_type> {},
                                                      init_params.privkey, init_params.vk};
                }

                // TODO: process input data in place
                // TODO: use marshaling module instead of custom marshaling to process input data
                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    std::copy(first, last, std::back_inserter(acc.supplied_cipher_text));
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, InputRange range) {
                    update(acc, std::cbegin(range), std::cend(range));
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    assert(acc.supplied_cipher_text.size() - 2 == acc.vk.gamma_ABC_g1.size() - 1);
                    std::vector<typename scalar_field_type::value_type> m_new;
                    m_new.reserve(acc.supplied_cipher_text.size() - 2);

                    for (size_t j = 1; j < acc.supplied_cipher_text.size() - 1; ++j) {
                        typename gt_type::value_type ci_sk_i =
                            algebra::pair_reduced<Curve>(acc.supplied_cipher_text[j], acc.vk.rho_rhov_g2[j - 1]);
                        typename gt_type::value_type c0_sk_0 =
                            algebra::pair_reduced<Curve>(acc.supplied_cipher_text[0], acc.vk.rho_sv_g2[j - 1]) *
                            acc.privkey.rho;
                        typename gt_type::value_type dec_tmp = ci_sk_i * c0_sk_0.inversed();
                        auto discrete_log = gt_type::value_type::one();
                        typename gt_type::value_type bruteforce =
                            algebra::pair_reduced<Curve>(acc.vk.gamma_ABC_g1.rest.values[j], acc.vk.rho_rhov_g2[j - 1]);
                        std::size_t exp = 0;
                        bool deciphered = false;
                        do {
                            if (dec_tmp == discrete_log) {
                                m_new.template emplace_back(exp);
                                deciphered = true;
                                break;
                            }
                            discrete_log = discrete_log * bruteforce;
                        } while (exp++ < 1 << scheme_type::block_bits);
                        assert(deciphered);
                    }

                    typename g1_type::value_type verify_c0 = acc.privkey.rho * acc.supplied_cipher_text[0];

                    return {m_new, verify_c0};
                }
            };

            template<typename Curve, std::size_t BlockBits>
            struct verify_encryption_op<elgamal_verifiable<Curve, BlockBits>> { };

            template<typename Curve, std::size_t BlockBits>
            struct verify_decryption_op<elgamal_verifiable<Curve, BlockBits>> { };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
