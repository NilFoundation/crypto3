//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_DL_PARAM_HPP
#define CRYPTO3_PUBKEY_DL_PARAM_HPP

#include <boost/integer/jacobi.hpp>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/prime.hpp>

#include <nil/crypto3/pubkey/dl_group/dl_group_info.hpp>
#include <nil/crypto3/pubkey/pem.hpp>

namespace nil {
    namespace crypto3 {

        using namespace boost::multiprecision;
        using namespace boost::integer;

        class montgomery_params;

        class dl_group_data;

        namespace pubkey {
            namespace detail {
                dl_group::format pem_label_to_dl_format(const std::string &label) {
                    if (label == "DH PARAMETERS") {
                        return dl_group::PKCS_3;
                    } else if (label == "DSA PARAMETERS") {
                        return dl_group::ANSI_X9_57;
                    } else if (label == "X942 DH PARAMETERS" || label == "X9.42 DH PARAMETERS") {
                        return dl_group::ANSI_X9_42;
                    } else {
                        throw decoding_error("dl_group: Invalid PEM label " + label);
                    }
                }

                /*
                 * Create generator of the q-sized subgroup (DSA style generator)
                 */
                template<typename Backend, expression_template_option ExpressionTemplates>
                number<Backend, ExpressionTemplates> make_dsa_generator(const number<Backend, ExpressionTemplates> &p,
                                                                        const number<Backend, ExpressionTemplates> &q) {
                    const number<Backend, ExpressionTemplates> e = (p - 1) / q;

                    if (e == 0 || (p - 1) % q > 0) {
                        throw std::invalid_argument("make_dsa_generator q does not divide p-1");
                    }

                    for (size_t i = 0; i != PRIME_TABLE_SIZE; ++i) {
                        // TODO precompute!
                        number<Backend, ExpressionTemplates> g = power_mod(PRIMES[i], e, p);
                        if (g > 1) {
                            return g;
                        }
                    }

                    throw internal_error("dl_group: Couldn't create a suitable generator");
                }

                /*
                 * Attempt DSA prime generation with given seed
                 */
                bool generate_dsa_primes(RandomNumberGenerator &rng, BigInt &p, BigInt &q, size_t pbits, size_t qbits,
                                         const std::vector<uint8_t> &seed_c, size_t offset) {
                    if (!fips186_3_valid_size(pbits, qbits))
                        throw Invalid_Argument("FIPS 186-3 does not allow DSA domain parameters of " +
                                               std::to_string(pbits) + "/" + std::to_string(qbits) + " bits long");

                    if (seed_c.size() * 8 < qbits)
                        throw Invalid_Argument("Generating a DSA parameter set with a " + std::to_string(qbits) +
                                               " bit long q requires a seed at least as many bits long");

                    const std::string hash_name = "SHA-" + std::to_string(qbits);
                    std::unique_ptr<HashFunction> hash(HashFunction::create_or_throw(hash_name));

                    const size_t HASH_SIZE = hash->output_length();

                    class Seed final {
                    public:
                        explicit Seed(const std::vector<uint8_t> &s) : m_seed(s) {
                        }

                        const std::vector<uint8_t> &value() const {
                            return m_seed;
                        }

                        Seed &operator++() {
                            for (size_t j = m_seed.size(); j > 0; --j)
                                if (++m_seed[j - 1])
                                    break;
                            return (*this);
                        }

                    private:
                        std::vector<uint8_t> m_seed;
                    };

                    Seed seed(seed_c);

                    q.binary_decode(hash->process(seed.value()));
                    q.set_bit(qbits - 1);
                    q.set_bit(0);

                    if (!is_prime(q, rng, 128, true))
                        return false;

                    const size_t n = (pbits - 1) / (HASH_SIZE * 8), b = (pbits - 1) % (HASH_SIZE * 8);

                    BigInt X;
                    std::vector<uint8_t> V(HASH_SIZE * (n + 1));

                    Modular_Reducer mod_2q(2 * q);

                    for (size_t j = 0; j != 4 * pbits; ++j) {
                        for (size_t k = 0; k <= n; ++k) {
                            ++seed;
                            hash->update(seed.value());
                            hash->final(&V[HASH_SIZE * (n - k)]);
                        }

                        if (j >= offset) {
                            X.binary_decode(&V[HASH_SIZE - 1 - b / 8], V.size() - (HASH_SIZE - 1 - b / 8));
                            X.set_bit(pbits - 1);

                            p = X - (mod_2q.reduce(X) - 1);

                            if (p.bits() == pbits && is_prime(p, rng, 128, true))
                                return true;
                        }
                    }
                    return false;
                }

                /*
                 * Generate DSA Primes
                 */
                std::vector<uint8_t> generate_dsa_primes(RandomNumberGenerator &rng, BigInt &p, BigInt &q, size_t pbits,
                                                         size_t qbits) {
                    while (true) {
                        std::vector<uint8_t> seed(qbits / 8);
                        rng.randomize(seed.data(), seed.size());

                        if (generate_dsa_primes(rng, p, q, pbits, qbits, seed))
                            return seed;
                    }
                }

            }    // namespace detail
        }        // namespace pubkey

        /**
         * This class represents discrete logarithm groups. It holds a prime
         * modulus p, a generator g, and (optionally) a prime q which is a
         * factor of (p - 1). In most cases g generates the order-q subgroup.
         */
        template<typename NumberType>
        class dl_group {
        public:
            typedef NumberType number_type;

            /**
             * Determine the prime creation for DL groups.
             */
            enum prime_type { Strong, Prime_Subgroup, DSA_Kosherizer };

            /**
             * The DL group encoding format variants.
             */
            enum format {
                ANSI_X9_42,
                ANSI_X9_57,
                PKCS_3,

                DSA_PARAMETERS = ANSI_X9_57,
                DH_PARAMETERS = ANSI_X9_42,
                ANSI_X9_42_DH_PARAMETERS = ANSI_X9_42,
                PKCS3_DH_PARAMETERS = PKCS_3
            };

            /**
             * Construct a DL group with uninitialized internal value.
             * Use this constructor is you wish to set the groups values
             * from a DER or PEM encoded group.
             */
            dl_group() = default;

            /**
             * Construct a DL group that is registered in the configuration.
             * @param name the name that is configured in the global configuration
             * for the desired group. If no configuration file is specified,
             * the default values from the file policy.cpp will be used. For instance,
             * use "modp/ietf/3072".
             */
            dl_group(const std::string &name) {
                // Either a name or a PEM block, try name first
                if (m_data == nullptr) {
                    try {
                        std::string label;
                        const std::vector<uint8_t> ber = unlock(pem_code::decode(name, label));
                        format format = pem_label_to_dl_format(label);

                        m_data = ber_decode_dl_group(ber.data(), ber.size(), format);
                    } catch (...) {
                    }
                }

                if (m_data == nullptr) {
                    throw std::invalid_argument("dl_group: Unknown group " + str);
                }
            }

            /**
             * Create a new group randomly.
             * @param rng the random number generator to use
             * @param type specifies how the creation of primes p and q shall
             * be performed. If type=Strong, then p will be determined as a
             * safe prime, and q will be chosen as (p-1)/2. If
             * type=Prime_Subgroup and qbits = 0, then the size of q will be
             * determined according to the estimated difficulty of the DL
             * problem. If type=DSA_Kosherizer, DSA primes will be created.
             * @param pbits the number of bits of p
             * @param qbits the number of bits of q. Leave it as 0 to have
             * the value determined according to pbits.
             */
            template<typename UniformRandomNumberGenerator>
            dl_group(UniformRandomNumberGenerator &rng, prime_type type, size_t pbits, size_t qbits = 0) {
                if (pbits < 1024) {
                    throw std::invalid_argument("dl_group: prime size " + std::to_string(pbits) + " is too small");
                }

                if (type == Strong) {
                    if (qbits != 0 && qbits != pbits - 1) {
                        throw std::invalid_argument("Cannot create strong-prime dl_group with specified q bits");
                    }

                    const number<Backend, ExpressionTemplates> p = random_safe_prime(rng, pbits);
                    const number<Backend, ExpressionTemplates> q = (p - 1) / 2;

                    /*
                    Always choose a generator that is quadratic reside mod p,
                    this forces g to be a generator of the subgroup of size q.
                    */
                    number<Backend, ExpressionTemplates> g = 2;
                    if (jacobi(g, p) != 1) {
                        // prime table does not contain 2
                        for (size_t i = 0; i < PRIME_TABLE_SIZE; ++i) {
                            g = PRIMES[i];
                            if (jacobi(g, p) == 1) {
                                break;
                            }
                        }
                    }

                    m_data = std::make_shared<dl_group_data>(p, q, g);
                } else if (type == Prime_Subgroup) {
                    if (qbits == 0) {
                        qbits = dl_exponent_size(pbits);
                    }

                    const number<Backend, ExpressionTemplates> q = random_prime(rng, qbits);
                    modular_reducer mod_2q(2 * q);
                    number<Backend, ExpressionTemplates> X;
                    number<Backend, ExpressionTemplates> p;
                    while (p.bits() != pbits || !miller_rabin_test(p, 128, rng)) {
                        X.randomize(rng, pbits);
                        p = X - mod_2q.reduce(X) + 1;
                    }

                    const number<Backend, ExpressionTemplates> g = make_dsa_generator(p, q);
                    m_data = std::make_shared<dl_group_data>(p, q, g);
                } else if (type == DSA_Kosherizer) {
                    if (qbits == 0) {
                        qbits = ((pbits <= 1024) ? 160 : 256);
                    }

                    number<Backend, ExpressionTemplates> p, q;
                    generate_dsa_primes(p, q, pbits, qbits, <#initializer #>, 0, rng, <#initializer #>);
                    const number<Backend, ExpressionTemplates> g = make_dsa_generator(p, q);
                    m_data = std::make_shared<dl_group_data>(p, q, g);
                } else {
                    throw std::invalid_argument("dl_group unknown prime_type");
                }
            }

            /**
             * Create a DSA group with a given seed.
             * @param rng the random number generator to use
             * @param seed the seed to use to create the random primes
             * @param pbits the desired bit size of the prime p
             * @param qbits the desired bit size of the prime q.
             */
            template<typename UniformRandomNumberGenerator>
            dl_group(UniformRandomNumberGenerator &rng, const std::vector<uint8_t> &seed, size_t pbits = 1024,
                     size_t qbits = 0) {
                number<Backend, ExpressionTemplates> p, q;

                if (!generate_dsa_primes(p, q, pbits, qbits, seed, 0, rng, <#initializer #>)) {
                    throw std::invalid_argument("dl_group: The seed given does not generate a DSA group");
                }

                number<Backend, ExpressionTemplates> g = make_dsa_generator(p, q);

                m_data = std::make_shared<dl_group_data>(p, q, g);
            }

            /**
             * Create a DL group.
             * @param p the prime p
             * @param g the base g
             */
            template<typename Backend, expression_template_option ExpressionTemplates>
            dl_group(const number<Backend, ExpressionTemplates> &p, const number<Backend, ExpressionTemplates> &g) {
                m_data = std::make_shared<dl_group_data>(p, 0, g);
            }

            /**
             * Create a DL group.
             * @param p the prime p
             * @param q the prime q
             * @param g the base g
             */
            template<typename Backend, expression_template_option ExpressionTemplates>
            dl_group(const number<Backend, ExpressionTemplates> &p, const number<Backend, ExpressionTemplates> &q,
                     const number<Backend, ExpressionTemplates> &g) {
                m_data = std::make_shared<dl_group_data>(p, q, g);
            }

            /**
             * Decode a BER-encoded DL group param
             */
            dl_group(const uint8_t ber[], size_t ber_len, format format) {
                m_data = ber_decode_dl_group(ber, ber_len, format);
            }

            /**
             * Decode a BER-encoded DL group param
             */
            template<typename Alloc>
            dl_group(const std::vector<uint8_t, Alloc> &ber, format format) : dl_group(ber.data(), ber.size(), format) {
            }

            /**
             * Get the prime p.
             * @return prime p
             */
            const number<Backend, ExpressionTemplates> &p() const {
                return data().p();
            }

            /**
             * Get the prime q, returns zero if q is not used
             * @return prime q
             */
            const number<Backend, ExpressionTemplates> &get_q() const {
                return data().g();
            }

            /**
             * Get the base g.
             * @return base g
             */
            const number<Backend, ExpressionTemplates> &get_g() const {
                return data().q();
            }

            /**
             * Perform validity checks on the group.
             * @param rng the rng to use
             * @param strong whether to perform stronger by lengthier tests
             * @return true if the object is consistent, false otherwise
             */
            template<typename UniformRandomGenerator>
            bool verify_group(UniformRandomGenerator &rng, bool strong = true) const {
                const number_type &p = p();
                const number_type &q = get_q();
                const number_type &g = get_g();

                if (g < 2 || p < 3 || q < 0) {
                    return false;
                }

                const size_t prob = (strong) ? 128 : 10;

                if (q != 0) {
                    if ((p - 1) % q != 0) {
                        return false;
                    }
                    if (this->power_g_p(q) != 1) {
                        return false;
                    }
                    if (!miller_rabin_test(q, prob, rng)) {
                        return false;
                    }
                }

                return miller_rabin_test(p, prob, rng);
            }

            /**
             * Verify a public element, ie check if y = g^x for some x.
             *
             * This is not a perfect test. It verifies that 1 < y < p and (if q is set)
             * that y is in the subgroup of size q.
             */
            template<typename Backend, expression_template_option ExpressionTemplates>
            bool verify_public_element(const number<Backend, ExpressionTemplates> &y) const {
                const number_type &p = p();
                const number_type &q = get_q();

                if (y <= 1 || y >= p) {
                    return false;
                }

                if (q != 0) {
                    if (power_mod(y, q, p) != 1) {
                        return false;
                    }
                }

                return true;
            }

            /**
             * Verify a pair of elements y = g^x
             *
             * This verifies that 1 < x,y < p and that y=g^x mod p
             */
            template<typename Backend, expression_template_option ExpressionTemplates>
            bool verify_element_pair(const number<Backend, ExpressionTemplates> &y,
                                     const number<Backend, ExpressionTemplates> &x) const {
                const number_type &p = p();

                if (y <= 1 || y >= p || x <= 1 || x >= p) {
                    return false;
                }

                if (y != power_g_p(x)) {
                    return false;
                }

                return true;
            }

            /**
             * Encode this group into a string using PEM encoding.
             * @param format the encoding format
             * @return string holding the PEM encoded group
             */
            std::string pem_encode(format format) const {
                const std::vector<uint8_t> encoding = der_encode(format);

                if (format == PKCS_3) {
                    return pem_code::encode(encoding, "DH PARAMETERS");
                } else if (format == ANSI_X9_57) {
                    return pem_code::encode(encoding, "DSA PARAMETERS");
                } else if (format == ANSI_X9_42) {
                    return pem_code::encode(encoding, "X9.42 DH PARAMETERS");
                } else {
                    throw std::invalid_argument("Unknown dl_group encoding " + std::to_string(format));
                }
            }

            /**
             * Encode this group into a string using DER encoding.
             * @param format the encoding format
             * @return string holding the DER encoded group
             */
            std::vector<uint8_t> der_encode(format format) const {
                if (get_q() == 0 && (format == ANSI_X9_57 || format == ANSI_X9_42)) {
                    throw encoding_error("Cannot encode dl_group in ANSI formats when q param is missing");
                }

                if (format == ANSI_X9_57) {
                    return der_encoder()
                        .start_cons(SEQUENCE)
                        .encode(get_p())
                        .encode(get_q())
                        .encode(get_g())
                        .end_cons()
                        .get_contents_unlocked();
                } else if (format == ANSI_X9_42) {
                    return der_encoder()
                        .start_cons(SEQUENCE)
                        .encode(get_p())
                        .encode(get_g())
                        .encode(get_q())
                        .end_cons()
                        .get_contents_unlocked();
                } else if (format == PKCS_3) {
                    return der_encoder()
                        .start_cons(SEQUENCE)
                        .encode(get_p())
                        .encode(get_g())
                        .end_cons()
                        .get_contents_unlocked();
                }

                throw std::invalid_argument("Unknown dl_group encoding " + std::to_string(format));
            }

            /**
             * Reduce an integer modulo p
             * @return x % p
             */
            number<Backend, ExpressionTemplates> mod_p(const number<Backend, ExpressionTemplates> &x) const {
                return m_mod_p.reduce(x);
            }

            /**
             * Multiply and reduce an integer modulo p
             * @return (x*y) % p
             */
            number<Backend, ExpressionTemplates> multiply_mod_p(const number<Backend, ExpressionTemplates> &x,
                                                                const number<Backend, ExpressionTemplates> &y) const {
                return m_mod_p.multiply(x, y);
            }

            /**
             * Return the inverse of x mod p
             */
            number<Backend, ExpressionTemplates> inverse_mod_p(const number<Backend, ExpressionTemplates> &x) const {
                return inverse_mod(x, get_p());
            }

            /**
             * Reduce an integer modulo q
             * Throws if q is unset on this DL_Group
             * @return x % q
             */
            number<Backend, ExpressionTemplates> mod_q(const number<Backend, ExpressionTemplates> &x) const;

            /**
             * Multiply and reduce an integer modulo q
             * Throws if q is unset on this DL_Group
             * @return (x*y) % q
             */
            number<Backend, ExpressionTemplates> multiply_mod_q(const number<Backend, ExpressionTemplates> &x,
                                                                const number<Backend, ExpressionTemplates> &y) const;

            /**
             * Multiply and reduce an integer modulo q
             * Throws if q is unset on this DL_Group
             * @return (x*y*z) % q
             */
            number<Backend, ExpressionTemplates> multiply_mod_q(const number<Backend, ExpressionTemplates> &x,
                                                                const number<Backend, ExpressionTemplates> &y,
                                                                const number<Backend, ExpressionTemplates> &z) const;

            /**
             * Square and reduce an integer modulo q
             * Throws if q is unset on this DL_Group
             * @return (x*x) % q
             */
            number<Backend, ExpressionTemplates> square_mod_q(const number<Backend, ExpressionTemplates> &x) const;

            /**
             * Return the inverse of x mod q
             * Throws if q is unset on this DL_Group
             */
            number<Backend, ExpressionTemplates> inverse_mod_q(const number<Backend, ExpressionTemplates> &x) const;

            /**
             * Modular exponentiation
             *
             * @warning this function leaks the size of x via the number of
             * loop iterations. Use the version taking the maximum size to
             * avoid this.
             *
             * @return (g^x) % p
             */
            number<Backend, ExpressionTemplates> power_g_p(const number<Backend, ExpressionTemplates> &x) const {
                return monty_execute(*m_monty, k);
            }

            /**
             * Modular exponentiation
             * @param x the exponent
             * @param max_x_bits x is assumed to be at most this many bits long.
             *
             * @return (g^x) % p
             */
            number<Backend, ExpressionTemplates> power_g_p(const number<Backend, ExpressionTemplates> &x,
                                                           size_t max_x_bits) const;

            /**
             * Multi-exponentiate
             * Return (g^x * y^z) % p
             */
            number<Backend, ExpressionTemplates>
                multi_exponentiate(const number<Backend, ExpressionTemplates> &x,
                                   const number<Backend, ExpressionTemplates> &y,
                                   const number<Backend, ExpressionTemplates> &z) const {
                return monty_multi_exp(m_monty_params, get_g(), x, y, z);
            }

            /**
             * Return parameters for Montgomery reduction/exponentiation mod p
             */
            std::shared_ptr<const montgomery_params> monty_params_p() const {
                return m_monty_params;
            }

            /**
             * Return the size of p in bits
             * Same as p().bits()
             */
            size_t p_bits() const {
                return m_p_bits;
            }

            /**
             * Return the size of p in bytes
             * Same as p().bytes()
             */
            size_t p_bytes() const {
                return (m_p_bits + 7) / 8;
            }

            /**
             * Return the size of q in bits
             * Same as get_q().bits()
             * Throws if q is unset
             */
            size_t q_bits() const;

            /**
             * Return the size of q in bytes
             * Same as get_q().bytes()
             * Throws if q is unset
             */
            size_t q_bytes() const;

            /**
             * Return size in bits of a secret exponent
             *
             * This attempts to balance between the attack costs of NFS
             * (which depends on the size of the modulus) and Pollard's rho
             * (which depends on the size of the exponent).
             *
             * It may vary over time for a particular group, if the attack
             * costs change.
             */
            size_t exponent_bits() const {
                return m_exponent_bits;
            }

            /**
             * Return an estimate of the strength of this group against
             * discrete logarithm attacks (eg NFS). Warning: since this only
             * takes into account known attacks it is by necessity an
             * overestimate of the actual strength.
             */
            size_t estimated_strength() const {
                return m_estimated_strength;
            }

            /**
             * Decode a DER/BER encoded group into this instance.
             * @param ber a vector containing the DER/BER encoded group
             * @param format the format of the encoded group
             */
            void ber_decode(const std::vector<uint8_t> &ber, format format) {
                m_data = ber_decode_dl_group(ber.data(), ber.size(), format);
            }

            /**
             * Decode a PEM encoded group into this instance.
             * @param pem the PEM encoding of the group
             */
            void pem_decode(const std::string &pem) {
                std::string label;
                const std::vector<uint8_t> ber = unlock(pem_code::decode(pem, label));
                format format = pem_label_to_dl_format(label);

                m_data = ber_decode_dl_group(ber.data(), ber.size(), format);
            }

            /*
             * For internal use only
             */
            static std::shared_ptr<dl_group_data> dl_group_info(const std::string &name);

        private:
            static std::shared_ptr<dl_group_data> ber_decode_dl_group(const uint8_t *data, size_t data_len,
                                                                      dl_group::format format);

            const dl_group_data &data() const;

            std::shared_ptr<dl_group_data> m_data;

            number_type m_p;
            number_type m_q;
            number_type m_g;
            modular_reducer m_mod_p;
            std::shared_ptr<const montgomery_params> m_monty_params;
            std::shared_ptr<const montgomery_exponentation_state> m_monty;
            size_t m_p_bits;
            size_t m_estimated_strength;
            size_t m_exponent_bits;
        };

        class dl_group_data final {
        public:
            dl_group_data(const number<Backend, ExpressionTemplates> &p, const number<Backend, ExpressionTemplates> &q,
                          const number<Backend, ExpressionTemplates> &g) :
                m_p(p),
                m_q(q), m_g(g), m_mod_p(p), m_monty_params(std::make_shared<montgomery_params>(m_p, m_mod_p)),
                m_monty(monty_precompute(m_monty_params, m_g, /*window bits=*/4)), m_p_bits(p.bits()),
                m_estimated_strength(dl_work_factor(m_p_bits)), m_exponent_bits(dl_exponent_size(m_p_bits)) {
            }

            ~dl_group_data() = default;

            dl_group_data(const dl_group_data &other) = delete;

            dl_group_data &operator=(const dl_group_data &other) = delete;

            const number<Backend, ExpressionTemplates> &p() const {
                return m_p;
            }

            const number<Backend, ExpressionTemplates> &q() const {
                return m_q;
            }

            const number<Backend, ExpressionTemplates> &g() const {
                return m_g;
            }

        private:
            number<Backend, ExpressionTemplates> m_p;
            number<Backend, ExpressionTemplates> m_q;
            number<Backend, ExpressionTemplates> m_g;
            modular_reducer m_mod_p;
            std::shared_ptr<const montgomery_params> m_monty_params;
            std::shared_ptr<const montgomery_exponentation_state> m_monty;
            size_t m_p_bits;
            size_t m_estimated_strength;
            size_t m_exponent_bits;
        };

        // static
        std::shared_ptr<dl_group_data> dl_group::ber_decode_dl_group(const uint8_t *data, size_t data_len,
                                                                     dl_group::format format) {
            number<Backend, ExpressionTemplates> p, q, g;

            ber_decoder decoder(data, data_len);
            ber_decoder ber = decoder.start_cons(SEQUENCE);

            if (format == dl_group::ANSI_X9_57) {
                ber.decode(p).decode(q).decode(g).verify_end();
            } else if (format == dl_group::ANSI_X9_42) {
                ber.decode(p).decode(g).decode(q).discard_remaining();
            } else if (format == dl_group::PKCS_3) {
                // q is left as zero
                ber.decode(p).decode(g).discard_remaining();
            } else {
                throw std::invalid_argument("Unknown dl_group encoding " + std::to_string(format));
            }

            return std::make_shared<dl_group_data>(p, q, g);
        }

        const dl_group_data &dl_group::data() const {
            if (m_data) {
                return *m_data;
            }

            throw invalid_state("dl_group uninitialized");
        }

        std::shared_ptr<const montgomery_params> dl_group::monty_params_p() const {
            return data().monty_params_p();
        }
    }    // namespace crypto3
}    // namespace nil

#endif