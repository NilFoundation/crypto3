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

#include <boost/assert.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>

#include <nil/crypto3/zk/algorithms/prove.hpp>
#include <nil/crypto3/zk/algorithms/verify.hpp>

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <nil/crypto3/pubkey/keys/private_key.hpp>
#include <nil/crypto3/pubkey/keys/verification_key.hpp>
#include <nil/crypto3/pubkey/operations/generate_keypair_op.hpp>
#include <nil/crypto3/pubkey/operations/encrypt_op.hpp>
#include <nil/crypto3/pubkey/operations/decrypt_op.hpp>
#include <nil/crypto3/pubkey/operations/verify_encryption_op.hpp>
#include <nil/crypto3/pubkey/operations/verify_decryption_op.hpp>
#include <nil/crypto3/pubkey/operations/rerandomize_op.hpp>

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

                typedef zk::snark::r1cs_gg_ppzksnark<
                    Curve, zk::snark::r1cs_gg_ppzksnark_generator<Curve, zk::snark::proving_mode::encrypted_input>,
                    zk::snark::r1cs_gg_ppzksnark_prover<Curve, zk::snark::proving_mode::encrypted_input>,
                    zk::snark::r1cs_gg_ppzksnark_verifier_strong_input_consistency<
                        Curve, zk::snark::proving_mode::encrypted_input>,
                    zk::snark::proving_mode::encrypted_input>
                    proof_system_type;

                typedef std::pair<std::vector<typename Curve::template g1_type<>::value_type>,
                                  typename proof_system_type::proof_type>
                    cipher_type;
                typedef std::pair<std::vector<typename Curve::scalar_field_type::value_type>,
                                  typename Curve::template g1_type<>::value_type>
                    decipher_type;
            };

            template<typename Curve, std::size_t BlockBits>
            struct verification_key<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;
                typedef typename Curve::template g2_type<> g2_type;

                friend class decrypt_op<scheme_type>;
                friend class verify_decryption_op<scheme_type>;

                verification_key() = default;
                verification_key(const typename g2_type::value_type &rho_g2,
                                 const std::vector<typename g2_type::value_type> &rho_sv_g2,
                                 const std::vector<typename g2_type::value_type> &rho_rhov_g2) :
                    rho_g2(rho_g2),
                    rho_sv_g2(rho_sv_g2), rho_rhov_g2(rho_rhov_g2) {
                }
                verification_key(typename g2_type::value_type &&rho_g2,
                                 std::vector<typename g2_type::value_type> &&rho_sv_g2,
                                 std::vector<typename g2_type::value_type> &&rho_rhov_g2) :
                    rho_g2(std::move(rho_g2)),
                    rho_sv_g2(std::move(rho_sv_g2)), rho_rhov_g2(std::move(rho_rhov_g2)) {
                }

                // private:
                typename g2_type::value_type rho_g2;
                std::vector<typename g2_type::value_type> rho_sv_g2;
                std::vector<typename g2_type::value_type> rho_rhov_g2;
            };

            template<typename Curve, std::size_t BlockBits>
            struct public_key<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;

                typedef typename Curve::template g1_type<> g1_type;
                typedef typename Curve::template g2_type<> g2_type;

                public_key() = default;
                public_key &operator=(const public_key &other) = default;
                public_key(const public_key &other) = default;
                public_key(public_key &&other) = default;
                public_key(const typename g1_type::value_type &delta_g1,
                           const std::vector<typename g1_type::value_type> &delta_s_g1,
                           const std::vector<typename g1_type::value_type> &t_g1,
                           const std::vector<typename g2_type::value_type> &t_g2,
                           const typename g1_type::value_type &delta_sum_s_g1,
                           const typename g1_type::value_type &gamma_inverse_sum_s_g1) :
                    delta_g1(delta_g1),
                    delta_s_g1(delta_s_g1), t_g1(t_g1), t_g2(t_g2), delta_sum_s_g1(delta_sum_s_g1),
                    gamma_inverse_sum_s_g1(gamma_inverse_sum_s_g1) {
                }
                public_key(typename g1_type::value_type &&delta_g1,
                           std::vector<typename g1_type::value_type> &&delta_s_g1,
                           std::vector<typename g1_type::value_type> &&t_g1,
                           std::vector<typename g2_type::value_type> &&t_g2,
                           typename g1_type::value_type &&delta_sum_s_g1,
                           typename g1_type::value_type &&gamma_inverse_sum_s_g1) :
                    delta_g1(std::move(delta_g1)),
                    delta_s_g1(std::move(delta_s_g1)), t_g1(std::move(t_g1)), t_g2(std::move(t_g2)),
                    delta_sum_s_g1(std::move(delta_sum_s_g1)),
                    gamma_inverse_sum_s_g1(std::move(gamma_inverse_sum_s_g1)) {
                }

                bool operator==(const public_key &other) const {
                    return delta_g1 == other.delta_g1 && delta_s_g1 == other.delta_s_g1 && t_g1 == other.t_g1 &&
                           t_g2 == other.t_g2 && delta_sum_s_g1 == other.delta_sum_s_g1 &&
                           gamma_inverse_sum_s_g1 == other.gamma_inverse_sum_s_g1;
                }

                typename g1_type::value_type delta_g1;
                std::vector<typename g1_type::value_type> delta_s_g1;
                std::vector<typename g1_type::value_type> t_g1;
                std::vector<typename g2_type::value_type> t_g2;
                typename g1_type::value_type delta_sum_s_g1;
                typename g1_type::value_type gamma_inverse_sum_s_g1;
            };

            template<typename Curve, std::size_t BlockBits>
            struct private_key<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;
                typedef typename Curve::scalar_field_type scalar_field_type;

                friend class decrypt_op<scheme_type>;

                private_key() = default;
                private_key(const typename scalar_field_type::value_type &rho) : rho(rho) {
                }

                // private:
                typename scalar_field_type::value_type rho;
            };

            template<typename Curve, std::size_t BlockBits>
            struct generate_keypair_op<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;
                typedef typename scheme_type::proof_system_type proof_system_type;

                typedef typename scheme_type::public_key_type public_key_type;
                typedef typename scheme_type::private_key_type private_key_type;
                typedef typename scheme_type::verification_key_type verification_key_type;
                typedef typename scheme_type::keypair_type keypair_type;

                typedef typename Curve::scalar_field_type scalar_field_type;
                typedef typename Curve::template g1_type<> g1_type;
                typedef typename Curve::template g2_type<> g2_type;

                struct init_params_type {
                    const typename proof_system_type::keypair_type &gg_keypair;
                    std::size_t msg_size;
                };
                struct internal_accumulator_type {
                    const typename proof_system_type::keypair_type &gg_keypair;
                    std::size_t msg_size;
                    std::vector<typename scalar_field_type::value_type> rnd;
                };
                typedef keypair_type result_type;

                static inline internal_accumulator_type init_accumulator(const init_params_type &init_params) {
                    // TODO: check
                    BOOST_ASSERT_MSG(init_params.gg_keypair.second.gamma_ABC_g1.rest.size() > init_params.msg_size,
                                     "Array of gammas in vk should be longer than the message.");
                    return {init_params.gg_keypair, init_params.msg_size,
                            std::vector<typename scalar_field_type::value_type> {}};
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    std::move(first, last, std::back_inserter(acc.rnd));
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, InputRange range) {
                    update(acc, std::cbegin(range), std::cend(range));
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    // TODO: check
                    BOOST_ASSERT_MSG(acc.rnd.size() >= 3 * acc.msg_size + 2,
                                     "Too few numbers in the source of randomness.");
                    auto rnd_iter = std::cbegin(acc.rnd);

                    typename scalar_field_type::value_type s_sum = scalar_field_type::value_type::zero();

                    std::vector<typename g1_type::value_type> delta_s_g1;
                    typename g1_type::value_type delta_sum_s_g1;
                    typename g1_type::value_type gamma_inverse_sum_s_g1 = acc.gg_keypair.second.gamma_g1;

                    typename scalar_field_type::value_type rho = *rnd_iter++;
                    typename g2_type::value_type rho_g2 = rho * g2_type::value_type::one();
                    std::vector<typename g2_type::value_type> rho_sv_g2;
                    std::vector<typename g2_type::value_type> rho_rhov_g2;

                    std::vector<typename g1_type::value_type> t_g1;
                    std::vector<typename g2_type::value_type> t_g2;

                    delta_s_g1.reserve(acc.msg_size);
                    rho_sv_g2.reserve(acc.msg_size);
                    rho_rhov_g2.reserve(acc.msg_size);
                    t_g1.reserve(acc.msg_size);
                    t_g2.reserve(acc.msg_size + 1);

                    typename scalar_field_type::value_type t = *rnd_iter++;
                    t_g2.emplace_back(t * g2_type::value_type::one());
                    delta_sum_s_g1 = t * acc.gg_keypair.second.delta_g1;

                    for (std::size_t i = 0; i < acc.msg_size; ++i) {
                        typename scalar_field_type::value_type s = *rnd_iter++;
                        typename scalar_field_type::value_type v = *rnd_iter++;
                        typename scalar_field_type::value_type sv = s * v;
                        t = *rnd_iter++;

                        delta_s_g1.emplace_back(s * acc.gg_keypair.second.delta_g1);
                        t_g1.emplace_back(t * acc.gg_keypair.second.gamma_ABC_g1.rest[i]);
                        t_g2.emplace_back(t * g2_type::value_type::one());
                        delta_sum_s_g1 = delta_sum_s_g1 + (s * t) * acc.gg_keypair.second.delta_g1;
                        gamma_inverse_sum_s_g1 = gamma_inverse_sum_s_g1 + s * acc.gg_keypair.second.gamma_g1;

                        rho_sv_g2.emplace_back(sv * g2_type::value_type::one());
                        rho_rhov_g2.emplace_back(v * rho_g2);
                    }
                    gamma_inverse_sum_s_g1 = -gamma_inverse_sum_s_g1;

                    public_key_type pk(acc.gg_keypair.second.delta_g1, delta_s_g1, t_g1, t_g2, delta_sum_s_g1,
                                       gamma_inverse_sum_s_g1);
                    private_key_type sk(rho);
                    verification_key_type vk(rho_g2, rho_sv_g2, rho_rhov_g2);

                    return {pk, sk, vk};
                }
            };

            template<typename Curve, std::size_t BlockBits>
            struct encrypt_op<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;
                typedef typename scheme_type::proof_system_type proof_system_type;
                typedef typename scheme_type::public_key_type public_key_type;

                typedef typename Curve::scalar_field_type scalar_field_type;
                typedef typename Curve::template g1_type<> g1_type;

                struct init_params_type {
                    typename scalar_field_type::value_type r;
                    const public_key_type &pubkey;
                    const typename proof_system_type::keypair_type &gg_keypair;
                    // TODO: accumulate primary_input and auxiliary_input
                    const typename proof_system_type::primary_input_type &primary_input;
                    const typename proof_system_type::auxiliary_input_type &auxiliary_input;
                };
                struct internal_accumulator_type {
                    std::vector<typename scalar_field_type::value_type> plain_text;
                    typename scalar_field_type::value_type r;
                    const public_key_type &pubkey;
                    const typename proof_system_type::keypair_type &gg_keypair;
                    const typename proof_system_type::primary_input_type &primary_input;
                    const typename proof_system_type::auxiliary_input_type &auxiliary_input;
                };
                typedef typename scheme_type::cipher_type result_type;

                static inline internal_accumulator_type init_accumulator(const init_params_type &init_params) {
                    return {std::vector<typename scalar_field_type::value_type> {},
                            std::move(init_params.r),
                            init_params.pubkey,
                            init_params.gg_keypair,
                            init_params.primary_input,
                            init_params.auxiliary_input};
                }

                // TODO: process input data in place
                // TODO: use marshalling module instead of custom marshalling to process input data
                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    std::copy(first, last, std::back_inserter(acc.plain_text));
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, InputRange range) {
                    update(acc, std::cbegin(range), std::cend(range));
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    // TODO: check
                    BOOST_ASSERT_MSG(acc.gg_keypair.second.gamma_ABC_g1.rest.size() > acc.plain_text.size(),
                                     "Array of gammas in vk should be longer than the plain text.");
                    BOOST_ASSERT_MSG(acc.primary_input.size() > acc.plain_text.size(),
                                     "Primary input should be longer than plain text.");
                    BOOST_ASSERT_MSG(acc.gg_keypair.second.gamma_ABC_g1.rest.size() == acc.primary_input.size(),
                                     "Number of gammas should be equal to the primary input size.");
                    BOOST_ASSERT_MSG(acc.plain_text.size() == acc.pubkey.delta_s_g1.size(),
                                     "Plain text size should be equal to the delta_s array size from pk.");
                    BOOST_ASSERT_MSG(acc.plain_text.size() == acc.pubkey.t_g1.size(),
                                     "Plain text size should be equal to the t_g1 array size from pk.");
                    BOOST_ASSERT_MSG(acc.plain_text.size() == acc.pubkey.t_g2.size() - 1,
                                     "Plain text size should be equal to the t_g2 array size from pk.");
                    for (std::size_t i = 0; i < acc.plain_text.size(); ++i) {
                        BOOST_ASSERT_MSG(acc.primary_input[i] == acc.plain_text[i],
                                         "Plain text should be a prefix of primary input.");
                    }

                    typename result_type::first_type ct_g1;
                    ct_g1.reserve(acc.plain_text.size() + 2);
                    ct_g1.emplace_back(acc.r * acc.pubkey.delta_g1);

                    typename g1_type::value_type sum_tm_g1 = acc.r * acc.pubkey.delta_sum_s_g1;

                    for (std::size_t i = 0; i < acc.plain_text.size(); ++i) {
                        ct_g1.emplace_back(acc.r * acc.pubkey.delta_s_g1[i] +
                                           acc.plain_text[i] * acc.gg_keypair.second.gamma_ABC_g1.rest[i]);
                        sum_tm_g1 = sum_tm_g1 + acc.plain_text[i] * acc.pubkey.t_g1[i];
                    }
                    ct_g1.emplace_back(sum_tm_g1);
                    auto proof = zk::prove<proof_system_type>(acc.gg_keypair.first, acc.pubkey, acc.primary_input,
                                                              acc.auxiliary_input, acc.r);

                    return {ct_g1, proof};
                }
            };

            template<typename Curve, std::size_t BlockBits>
            struct decrypt_op<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;
                typedef typename scheme_type::proof_system_type proof_system_type;
                typedef typename scheme_type::private_key_type private_key_type;
                typedef typename scheme_type::verification_key_type verification_key_type;

                typedef typename Curve::scalar_field_type scalar_field_type;
                typedef typename Curve::template g1_type<> g1_type;
                typedef typename Curve::gt_type gt_type;

                struct init_params_type {
                    const private_key_type &privkey;
                    const verification_key_type &vk;
                    const typename proof_system_type::keypair_type &gg_keypair;
                };
                struct internal_accumulator_type {
                    std::vector<typename g1_type::value_type> cipher_text;
                    const private_key_type &privkey;
                    const verification_key_type &vk;
                    const typename proof_system_type::keypair_type &gg_keypair;
                };
                typedef typename scheme_type::decipher_type result_type;

                static inline internal_accumulator_type init_accumulator(const init_params_type &init_params) {
                    return internal_accumulator_type {std::vector<typename g1_type::value_type> {}, init_params.privkey,
                                                      init_params.vk, init_params.gg_keypair};
                }

                // TODO: process input data in place
                // TODO: use marshalling module instead of custom marshalling to process input data
                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    std::copy(first, last, std::back_inserter(acc.cipher_text));
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, InputRange range) {
                    update(acc, std::cbegin(range), std::cend(range));
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    // TODO: check
                    BOOST_ASSERT_MSG(
                        acc.gg_keypair.second.gamma_ABC_g1.rest.size() > acc.cipher_text.size() - 2,
                        "Array of gammas in vk should be longer than the cipher text (exclusive of 2 element in CT).");
                    BOOST_ASSERT_MSG(acc.cipher_text.size() - 2 == acc.vk.rho_sv_g2.size(),
                                     "Cipher text size should be equal to the rho_sv_g2 array size from vk (exclusive "
                                     "of 2 element in CT).");
                    BOOST_ASSERT_MSG(acc.cipher_text.size() - 2 == acc.vk.rho_rhov_g2.size(),
                                     "Cipher text size should be equal to the rho_rhov_g2 array size from vk "
                                     "(exclusive of 2 element in CT).");
                    std::vector<typename scalar_field_type::value_type> m_new;
                    m_new.reserve(acc.cipher_text.size() - 2);

                    for (size_t j = 1; j < acc.cipher_text.size() - 1; ++j) {
                        typename gt_type::value_type ci_sk_i =
                            algebra::pair_reduced<Curve>(acc.cipher_text[j], acc.vk.rho_rhov_g2[j - 1]);
                        typename gt_type::value_type c0_sk_0 =
                            algebra::pair_reduced<Curve>(acc.cipher_text[0], acc.vk.rho_sv_g2[j - 1])
                                .pow(acc.privkey.rho.data);
                        typename gt_type::value_type dec_tmp = ci_sk_i * c0_sk_0.inversed();
                        auto discrete_log = gt_type::value_type::one();
                        typename gt_type::value_type bruteforce = algebra::pair_reduced<Curve>(
                            acc.gg_keypair.second.gamma_ABC_g1.rest[j - 1], acc.vk.rho_rhov_g2[j - 1]);
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
                        BOOST_ASSERT_MSG(deciphered, "Decryption failed.");
                    }

                    typename g1_type::value_type verify_c0 = acc.privkey.rho * acc.cipher_text[0];

                    return {m_new, verify_c0};
                }
            };

            template<typename Curve, std::size_t BlockBits>
            struct verify_encryption_op<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;
                typedef typename scheme_type::proof_system_type proof_system_type;
                typedef typename scheme_type::public_key_type public_key_type;

                typedef typename Curve::scalar_field_type scalar_field_type;
                typedef typename Curve::template g1_type<> g1_type;

                struct init_params_type {
                    const public_key_type &pubkey;
                    const typename proof_system_type::verification_key_type &gg_vk;
                    const typename proof_system_type::proof_type &proof;
                    const typename proof_system_type::primary_input_type &unencrypted_primary_input;
                };
                struct internal_accumulator_type {
                    const public_key_type &pubkey;
                    const typename proof_system_type::verification_key_type &gg_vk;
                    const typename proof_system_type::proof_type &proof;
                    const typename proof_system_type::primary_input_type &unencrypted_primary_input;
                    std::vector<typename g1_type::value_type> cipher_text;
                };
                typedef bool result_type;

                static inline internal_accumulator_type init_accumulator(const init_params_type &init_params) {
                    return internal_accumulator_type {init_params.pubkey, init_params.gg_vk, init_params.proof,
                                                      init_params.unencrypted_primary_input,
                                                      std::vector<typename g1_type::value_type> {}};
                }

                // TODO: process input data in place
                // TODO: use marshalling module instead of custom marshalling to process input data
                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    std::copy(first, last, std::back_inserter(acc.cipher_text));
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, InputRange range) {
                    update(acc, std::cbegin(range), std::cend(range));
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    return zk::verify<proof_system_type>(std::cbegin(acc.cipher_text), std::cend(acc.cipher_text),
                                                         acc.gg_vk, acc.pubkey, acc.unencrypted_primary_input,
                                                         acc.proof);
                }
            };

            template<typename Curve, std::size_t BlockBits>
            struct verify_decryption_op<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;
                typedef typename scheme_type::proof_system_type proof_system_type;
                typedef typename scheme_type::public_key_type public_key_type;
                typedef typename scheme_type::verification_key_type verification_key_type;

                typedef typename Curve::scalar_field_type scalar_field_type;
                typedef typename Curve::template g1_type<> g1_type;
                typedef typename Curve::template g2_type<> g2_type;
                typedef typename Curve::gt_type gt_type;

                struct init_params_type {
                    const verification_key_type &vk;
                    const typename proof_system_type::keypair_type &gg_keypair;
                    const typename g1_type::value_type &proof;
                };
                struct internal_accumulator_type {
                    const verification_key_type &vk;
                    const typename proof_system_type::keypair_type &gg_keypair;
                    const typename g1_type::value_type &proof;
                    std::vector<typename scalar_field_type::value_type> plain_text;
                    std::vector<typename g1_type::value_type> cipher_text;
                };
                typedef bool result_type;

                static inline internal_accumulator_type init_accumulator(const init_params_type &init_params) {
                    return internal_accumulator_type {init_params.vk, init_params.gg_keypair, init_params.proof,
                                                      std::vector<typename scalar_field_type::value_type> {},
                                                      std::vector<typename g1_type::value_type> {}};
                }

                // TODO: process input data in place
                // TODO: use marshalling module instead of custom marshalling to process input data
                template<typename InputIterator>
                static inline typename std::enable_if<
                    std::is_same<typename scalar_field_type::value_type,
                                 typename std::iterator_traits<InputIterator>::value_type>::value>::type
                    update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    std::copy(first, last, std::back_inserter(acc.plain_text));
                }

                template<typename InputIterator>
                static inline typename std::enable_if<
                    std::is_same<typename g1_type::value_type,
                                 typename std::iterator_traits<InputIterator>::value_type>::value>::type
                    update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    std::copy(first, last, std::back_inserter(acc.cipher_text));
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, InputRange range) {
                    update(acc, std::cbegin(range), std::cend(range));
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    BOOST_ASSERT_MSG(
                        acc.plain_text.size() + 2 == acc.cipher_text.size(),
                        "Cipher text size should be equal to the plain text size (exclusive of 2 element in CT).");
                    BOOST_ASSERT_MSG(acc.gg_keypair.second.gamma_ABC_g1.rest.size() > acc.plain_text.size(),
                                     "Array of gammas in vk should be longer than the plain text.");
                    typename gt_type::value_type vm_gt =
                        algebra::pair_reduced<Curve>(acc.proof, g2_type::value_type::one());
                    typename gt_type::value_type new_c0_v0_gt =
                        algebra::pair_reduced<Curve>(acc.cipher_text[0], acc.vk.rho_g2);
                    bool ans = (vm_gt == new_c0_v0_gt);

                    for (size_t i = 1; i < acc.cipher_text.size() - 1; ++i) {
                        typename gt_type::value_type ci_v_nj_gt =
                            algebra::pair_reduced<Curve>(acc.cipher_text[i], acc.vk.rho_rhov_g2[i - 1]);
                        typename gt_type::value_type v_vj_gt =
                            algebra::pair_reduced<Curve>(acc.proof, acc.vk.rho_sv_g2[i - 1]);
                        typename gt_type::value_type verify_tmp = ci_v_nj_gt * v_vj_gt.inversed();
                        typename gt_type::value_type verify_msg =
                            algebra::pair_reduced<Curve>(acc.gg_keypair.second.gamma_ABC_g1.rest[i - 1],
                                                         acc.vk.rho_rhov_g2[i - 1])
                                .pow(acc.plain_text[i - 1].data);
                        bool ans_m = (verify_tmp == verify_msg);
                        ans &= ans_m;
                    }

                    return ans;
                }
            };

            template<typename Curve, std::size_t BlockBits>
            struct rerandomize_op<elgamal_verifiable<Curve, BlockBits>> {
                typedef elgamal_verifiable<Curve, BlockBits> scheme_type;
                typedef typename scheme_type::proof_system_type proof_system_type;
                typedef typename scheme_type::public_key_type public_key_type;

                typedef typename Curve::scalar_field_type scalar_field_type;
                typedef typename Curve::template g1_type<> g1_type;
                typedef typename Curve::template g2_type<> g2_type;
                typedef typename Curve::gt_type gt_type;

                struct init_params_type {
                    const public_key_type &pubkey;
                    const typename proof_system_type::keypair_type &gg_keypair;
                    const typename proof_system_type::proof_type &proof;
                };
                struct internal_accumulator_type {
                    const public_key_type &pubkey;
                    const typename proof_system_type::keypair_type &gg_keypair;
                    const typename proof_system_type::proof_type &proof;
                    std::vector<typename scalar_field_type::value_type> rnd;
                    std::vector<typename g1_type::value_type> cipher_text;
                };
                typedef typename scheme_type::cipher_type result_type;

                static inline internal_accumulator_type init_accumulator(const init_params_type &init_params) {
                    return internal_accumulator_type {init_params.pubkey, init_params.gg_keypair, init_params.proof,
                                                      std::vector<typename scalar_field_type::value_type> {},
                                                      std::vector<typename g1_type::value_type> {}};
                }

                // TODO: process input data in place
                // TODO: use marshalling module instead of custom marshalling to process input data
                template<typename InputIterator>
                static inline typename std::enable_if<
                    std::is_same<typename scalar_field_type::value_type,
                                 typename std::iterator_traits<InputIterator>::value_type>::value>::type
                    update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    std::copy(first, last, std::back_inserter(acc.rnd));
                }

                template<typename InputIterator>
                static inline typename std::enable_if<
                    std::is_same<typename g1_type::value_type,
                                 typename std::iterator_traits<InputIterator>::value_type>::value>::type
                    update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    std::copy(first, last, std::back_inserter(acc.cipher_text));
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, InputRange range) {
                    update(acc, std::cbegin(range), std::cend(range));
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    BOOST_ASSERT_MSG(acc.rnd.size() >= 3, "Too few numbers in the source of randomness (at least 3).");
                    BOOST_ASSERT_MSG(acc.pubkey.delta_s_g1.size() == acc.cipher_text.size() - 2,
                                     "Cipher text size should be equal to the delta_s_g1 array size from pk (exclusive "
                                     "of 2 element in CT).");
                    BOOST_ASSERT_MSG(acc.pubkey.t_g1.size() == acc.cipher_text.size() - 2,
                                     "Cipher text size should be equal to the t_g1 array size from pk (exclusive of 2 "
                                     "element in CT).");
                    BOOST_ASSERT_MSG(acc.pubkey.t_g2.size() - 1 == acc.cipher_text.size() - 2,
                                     "Cipher text size should be equal to the t_g2 array size from pk (exclusive of 2 "
                                     "element in CT).");
                    std::vector<typename g1_type::value_type> ct_g1;
                    ct_g1.reserve(acc.cipher_text.size());

                    auto rnd_it = std::cbegin(acc.rnd);
                    typename scalar_field_type::value_type r = *rnd_it++;
                    typename scalar_field_type::value_type z1 = *rnd_it++;
                    typename scalar_field_type::value_type z2 = *rnd_it++;

                    typename scalar_field_type::value_type z1_inverse = z1.inversed();

                    ct_g1.emplace_back(acc.cipher_text.front() + r * acc.pubkey.delta_g1);
                    for (size_t i = 1; i < acc.cipher_text.size() - 1; ++i) {
                        ct_g1.emplace_back(acc.cipher_text[i] + r * acc.pubkey.delta_s_g1[i - 1]);
                    }
                    ct_g1.emplace_back(acc.cipher_text.back() + r * acc.pubkey.delta_sum_s_g1);

                    typename g1_type::value_type g1_A = z1 * acc.proof.g_A;
                    typename g2_type::value_type g2_B =
                        z1_inverse * acc.proof.g_B + z2 * acc.gg_keypair.second.delta_g2;
                    typename g1_type::value_type g1_C =
                        acc.proof.g_C + z2 * g1_A + r * acc.pubkey.gamma_inverse_sum_s_g1;

                    return std::make_pair(ct_g1, typename proof_system_type::proof_type {
                                                     std::move(g1_A), std::move(g2_B), std::move(g1_C)});
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
