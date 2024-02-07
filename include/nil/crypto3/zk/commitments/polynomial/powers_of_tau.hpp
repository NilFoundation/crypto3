#ifndef CRYPTO3_ZK_POWERS_OF_TAU_HPP
#define CRYPTO3_ZK_POWERS_OF_TAU_HPP

#include <nil/crypto3/zk/commitments/detail/polynomial/powers_of_tau/private_key.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/powers_of_tau/public_key.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/powers_of_tau/accumulator.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/powers_of_tau/result.hpp>
#include <nil/crypto3/zk/commitments/polynomial/proof_of_knowledge.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/vector_pairs.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/hash/blake2b.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/powers_of_tau/accumulator.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                template<typename CurveType, unsigned TauPowersLength>
                class powers_of_tau {
                    typedef CurveType curve_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename scalar_field_type::value_type scalar_field_value_type;
                    typedef typename CurveType::template g1_type<> g1_type;
                    typedef typename g1_type::value_type g1_value_type;
                    typedef typename CurveType::template g2_type<> g2_type;
                    typedef typename g2_type::value_type g2_value_type;

                public:
                    typedef detail::powers_of_tau_private_key<curve_type> private_key_type;
                    typedef detail::powers_of_tau_public_key<curve_type> public_key_type;
                    typedef detail::powers_of_tau_accumulator<curve_type, TauPowersLength> accumulator_type;
                    typedef detail::powers_of_tau_result<curve_type> result_type;
                    typedef proof_of_knowledge<curve_type> proof_of_knowledge_scheme_type;

                    enum parameter_personalization {
                        tau_personalization, alpha_personalization, beta_personalization
                    };

                    // The result of this function is considered toxic wast
                    // and should thus be destroyed
                    template<typename RNG = boost::random_device>
                    static private_key_type generate_private_key(RNG &&rng = boost::random_device()) {
                        typename scalar_field_type::value_type tau = algebra::random_element<scalar_field_type>(rng);
                        typename scalar_field_type::value_type alpha = algebra::random_element<scalar_field_type>(rng);
                        typename scalar_field_type::value_type beta = algebra::random_element<scalar_field_type>(rng);

                        return private_key_type{std::move(tau), std::move(alpha), std::move(beta)};
                    }

                    static auto rng_from_beacon(const std::vector<std::uint8_t> &beacon) {
                        std::size_t n = 42;
                        std::vector<std::uint8_t> cur_hash = beacon;
                        for (std::size_t i = 0; i < std::size_t(1 << n); ++i) {
                            std::vector<std::uint8_t> hash = nil::crypto3::hash<hashes::sha2<256>>(cur_hash);
                            cur_hash = hash;
                        }
                        // random::chacha gen;
                        boost::random::mt19937 gen;
                        // gen.seed(cur_hash);
                        gen.seed(cur_hash[0]);

                        return gen;
                    }

                    template<typename RNG = boost::random_device>
                    static public_key_type proof_eval(const private_key_type &private_key,
                                                      const accumulator_type &before,
                                                      RNG &&rng = boost::random_device()) {
                        std::vector<std::uint8_t> transcript = compute_transcript(before);
                        auto tau_pok = proof_of_knowledge_scheme_type::proof_eval(
                                private_key.tau, transcript, tau_personalization, rng);
                        auto alpha_pok = proof_of_knowledge_scheme_type::proof_eval(
                                private_key.alpha, transcript, alpha_personalization, rng);
                        auto beta_pok = proof_of_knowledge_scheme_type::proof_eval(
                                private_key.beta, transcript, beta_personalization, rng);

                        return public_key_type{std::move(tau_pok), std::move(alpha_pok), std::move(beta_pok)};
                    }

                    static bool verify_eval(const public_key_type &public_key,
                                            const accumulator_type &before,
                                            const accumulator_type &after) {
                        std::vector<std::uint8_t> transcript = compute_transcript(before);

                        auto tau_g2_s = proof_of_knowledge_scheme_type::compute_g2_s(
                                public_key.tau_pok.g1_s, public_key.tau_pok.g1_s_x, transcript, tau_personalization);
                        auto alpha_g2_s = proof_of_knowledge_scheme_type::compute_g2_s(
                                public_key.alpha_pok.g1_s, public_key.alpha_pok.g1_s_x, transcript,
                                alpha_personalization);
                        auto beta_g2_s = proof_of_knowledge_scheme_type::compute_g2_s(
                                public_key.beta_pok.g1_s, public_key.beta_pok.g1_s_x, transcript, beta_personalization);

                        // Verify the proofs of knowledge of tau, alpha and beta
                        if (!proof_of_knowledge_scheme_type::verify_eval(public_key.tau_pok, tau_g2_s)) {
                            return false;
                        }
                        if (!proof_of_knowledge_scheme_type::verify_eval(public_key.alpha_pok, alpha_g2_s)) {
                            return false;
                        }
                        if (!proof_of_knowledge_scheme_type::verify_eval(public_key.beta_pok, beta_g2_s)) {
                            return false;
                        }

                        // Check the correctness of the generators fot tau powers
                        if (after.tau_powers_g1[0] != g1_value_type::one()) {
                            return false;
                        }
                        if (after.tau_powers_g2[0] != g2_value_type::one()) {
                            return false;
                        }

                        // Did the participant multiply the previous tau by the new one?
                        if (!is_same_ratio(std::make_pair(before.tau_powers_g1[1], after.tau_powers_g1[1]),
                                           std::make_pair(tau_g2_s, public_key.tau_pok.g2_s_x))) {
                            return false;
                        }

                        // Did the participant multiply the previous alpha by the new one?
                        if (!is_same_ratio(std::make_pair(before.alpha_tau_powers_g1[0], after.alpha_tau_powers_g1[0]),
                                           std::make_pair(alpha_g2_s, public_key.alpha_pok.g2_s_x))) {
                            return false;
                        }

                        // Did the participant multiply the previous beta by the new one?
                        if (!is_same_ratio(std::make_pair(before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]),
                                           std::make_pair(beta_g2_s, public_key.beta_pok.g2_s_x))) {
                            return false;
                        }

                        if (!is_same_ratio(std::make_pair(before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]),
                                           std::make_pair(before.beta_g2, after.beta_g2))) {
                            return false;
                        }

                        // Are the powers of tau correct?
                        if (!is_same_ratio(detail::power_pairs<scalar_field_type>(after.tau_powers_g1),
                                           std::make_pair(after.tau_powers_g2[0], after.tau_powers_g2[1]))) {
                            return false;
                        }
                        if (!is_same_ratio(std::make_pair(after.tau_powers_g1[0], after.tau_powers_g1[1]),
                                           commitments::detail::power_pairs<scalar_field_type>(after.tau_powers_g2))) {
                            return false;
                        }
                        if (!is_same_ratio(detail::power_pairs<scalar_field_type>(after.alpha_tau_powers_g1),
                                           std::make_pair(after.tau_powers_g2[0], after.tau_powers_g2[1]))) {
                            return false;
                        }
                        if (!is_same_ratio(detail::power_pairs<scalar_field_type>(after.beta_tau_powers_g1),
                                           std::make_pair(after.tau_powers_g2[0], after.tau_powers_g2[1]))) {
                            return false;
                        }

                        return true;
                    }

                    static bool is_same_ratio(const std::pair<g1_value_type, g1_value_type> &g1_pair,
                                              const std::pair<g2_value_type, g2_value_type> &g2_pair) {

                        return algebra::pair_reduced<CurveType>(g1_pair.first, g2_pair.second) ==
                               algebra::pair_reduced<CurveType>(g1_pair.second, g2_pair.first);
                    }

                    static std::vector<std::uint8_t> compute_transcript(const accumulator_type &acc) {
                        auto acc_blob = serialize_accumulator(acc);
                        return nil::crypto3::hash<hashes::blake2b<512>>(acc_blob);
                    }

                    static std::vector<std::uint8_t> serialize_accumulator(const accumulator_type &acc) {
                        using endianness = nil::marshalling::option::little_endian;
                        auto filled_val =
                                nil::crypto3::marshalling::types::fill_powers_of_tau_accumulator<accumulator_type,
                                        endianness>(acc);
                        std::vector<std::uint8_t> blob(filled_val.length());
                        auto it = std::begin(blob);
                        nil::marshalling::status_type status = filled_val.write(it, blob.size());
                        if (status != nil::marshalling::status_type::success) {
                            return {};
                        } else {
                            return blob;
                        }
                    }
                };
            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_POWERS_OF_TAU_HPP
