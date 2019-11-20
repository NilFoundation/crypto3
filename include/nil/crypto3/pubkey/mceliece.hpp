#ifndef CRYPTO3_PUBKEY_MCELIECE_KEY_HPP
#define CRYPTO3_PUBKEY_MCELIECE_KEY_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/pubkey/polyn_gf2m.hpp>

#include <nil/crypto3/utilities/exceptions.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                secure_vector<uint8_t> concat_vectors(const secure_vector<uint8_t> &a, const secure_vector<uint8_t> &b,
                                                      uint32_t dimension, uint32_t codimension) {
                    secure_vector<uint8_t> x(bit_size_to_byte_size(dimension) + bit_size_to_byte_size(codimension));

                    const size_t final_bits = dimension % 8;

                    if (final_bits == 0) {
                        const size_t dim_bytes = bit_size_to_byte_size(dimension);
                        copy_mem(&x[0], a.data(), dim_bytes);
                        copy_mem(&x[dim_bytes], b.data(), bit_size_to_byte_size(codimension));
                    } else {
                        copy_mem(&x[0], a.data(), (dimension / 8));
                        uint32_t l = dimension / 8;
                        x[l] = static_cast<uint8_t>(a[l] & ((1 << final_bits) - 1));

                        for (uint32_t k = 0; k < codimension / 8; ++k) {
                            x[l] ^= static_cast<uint8_t>(b[k] << final_bits);
                            ++l;
                            x[l] = static_cast<uint8_t>(b[k] >> (8 - final_bits));
                        }
                        x[l] ^= static_cast<uint8_t>(b[codimension / 8] << final_bits);
                    }

                    return x;
                }

                secure_vector<uint8_t> mult_by_pubkey(const secure_vector<uint8_t> &cleartext,
                                                      std::vector<uint8_t> const &public_matrix, uint32_t code_length,
                                                      uint32_t t) {
                    const uint32_t ext_deg = ceil_log2(code_length);
                    const uint32_t codimension = ext_deg * t;
                    const uint32_t dimension = code_length - codimension;
                    secure_vector<uint8_t> cR(bit_size_to_32bit_size(codimension) * sizeof(uint32_t));

                    const uint8_t *pt = public_matrix.data();

                    for (size_t i = 0; i < dimension / 8; ++i) {
                        for (size_t j = 0; j < 8; ++j) {
                            if (cleartext[i] & (1 << j)) {
                                xor_buf(cR.data(), pt, cR.size());
                            }
                            pt += cR.size();
                        }
                    }

                    for (size_t i = 0; i < dimension % 8; ++i) {
                        if (cleartext[dimension / 8] & (1 << i)) {
                            xor_buf(cR.data(), pt, cR.size());
                        }
                        pt += cR.size();
                    }

                    secure_vector<uint8_t> ciphertext = concat_vectors(cleartext, cR, dimension, codimension);
                    ciphertext.resize((code_length + 7) / 8);
                    return ciphertext;
                }

                secure_vector<uint8_t> create_random_error_vector(unsigned code_length, unsigned error_weight,
                                                                  random_number_generator &rng) {
                    secure_vector<uint8_t> result((code_length + 7) / 8);

                    size_t bits_set = 0;

                    while (bits_set < error_weight) {
                        gf2m x = random_code_element(code_length, rng);

                        const size_t byte_pos = x / 8, bit_pos = x % 8;

                        const uint8_t mask = (1 << bit_pos);

                        if (result[byte_pos] & mask) {
                            continue;
                        }    // already set this bit

                        result[byte_pos] |= mask;
                        bits_set++;
                    }

                    return result;
                }
            }    // namespace detail

            class mc_eliece_public_key : public virtual public_key_policy {
            public:
                explicit mc_eliece_public_key(const std::vector<uint8_t> &key_bits);

                mc_eliece_public_key(const std::vector<uint8_t> &pub_matrix, uint32_t the_t, uint32_t the_code_length) :
                    m_public_matrix(pub_matrix), m_t(the_t), m_code_length(the_code_length) {
                }

                mc_eliece_public_key(const mc_eliece_public_key &other) = default;

                mc_eliece_public_key &operator=(const mc_eliece_public_key &other) = default;

                virtual ~mc_eliece_public_key() = default;

                secure_vector<uint8_t> random_plaintext_element(random_number_generator &rng) const;

                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 3, 6, 1, 4, 1, 25258, 1, 3});
                }

                std::string algo_name() const override {
                    return "McEliece";
                }

                algorithm_identifier get_algorithm_identifier() const override;

                size_t key_length() const override;

                size_t estimated_strength() const override;

                std::vector<uint8_t> public_key_bits() const override;

                bool check_key(random_number_generator &, bool) const override {
                    return true;
                }

                uint32_t get_t() const {
                    return m_t;
                }

                uint32_t get_code_length() const {
                    return m_code_length;
                }

                uint32_t get_message_word_bit_length() const;

                const std::vector<uint8_t> &get_public_matrix() const {
                    return m_public_matrix;
                }

                bool operator==(const mc_eliece_public_key &other) const;

                bool operator!=(const mc_eliece_public_key &other) const {
                    return !(*this == other);
                }

                std::unique_ptr<pk_operations::kem_encryption>
                    create_kem_encryption_op(random_number_generator &rng,
                                             const std::string &params,
                                             const std::string &provider) const

                    override;

            protected:
                mc_eliece_public_key() : m_t(0), m_code_length(0) {
                }

                std::vector<uint8_t> m_public_matrix;
                uint32_t m_t;
                uint32_t m_code_length;
            };

            class mc_eliece_private_key final : public virtual mc_eliece_public_key, public virtual private_key_policy {
            public:
                /**
                 * @brief Generate a McEliece key pair
                 *
                 * Suggested parameters for a given security level (SL)
                 *
                 * SL=80 n=1632 t=33 - 59 KB pubkey 140 KB privkey
                 * SL=107 n=2480 t=45 - 128 KB pubkey 300 KB privkey
                 * SL=128 n=2960 t=57 - 195 KB pubkey 459 KB privkey
                 * SL=147 n=3408 t=67 - 265 KB pubkey 622 KB privkey
                 * SL=191 n=4624 t=95 - 516 KB pubkey 1234 KB privkey
                 * SL=256 n=6624 t=115 - 942 KB pubkey 2184 KB privkey
                 */
                mc_eliece_private_key(random_number_generator &rng, size_t code_length, size_t t);

                explicit mc_eliece_private_key(const secure_vector<uint8_t> &key_bits);

                mc_eliece_private_key(polyn_gf2m const &goppa_polyn,
                                      std::vector<uint32_t> const &parity_check_matrix_coeffs,
                                      std::vector<polyn_gf2m> const &square_root_matrix,
                                      std::vector<gf2m> const &inverse_support,
                                      std::vector<uint8_t> const &public_matrix);

                bool check_key(random_number_generator &rng, bool strong) const override;

                polyn_gf2m const &get_goppa_polyn() const {
                    return m_g;
                }

                std::vector<uint32_t> const &get_HPPcoeffs() const {
                    return m_coeffs;
                }

                std::vector<gf2m> const &get_Linv() const {
                    return m_Linv;
                }

                std::vector<polyn_gf2m> const &get_sqrtmod() const {
                    return m_sqrtmod;
                }

                inline uint32_t get_dimension() const {
                    return m_dimension;
                }

                inline uint32_t get_codimension() const {
                    return m_codimension;
                }

                secure_vector<uint8_t> private_key_bits() const override;

                bool operator==(const mc_eliece_private_key &other) const;

                bool operator!=(const mc_eliece_private_key &other) const {
                    return !(*this == other);
                }

                std::unique_ptr<pk_operations::kem_decryption>
                    create_kem_decryption_op(random_number_generator &rng,
                                             const std::string &params,
                                             const std::string &provider) const override;

            private:
                polyn_gf2m m_g;
                std::vector<polyn_gf2m> m_sqrtmod;
                std::vector<gf2m> m_Linv;
                std::vector<uint32_t> m_coeffs;

                uint32_t m_codimension;
                uint32_t m_dimension;
            };

            /**
             * Estimate work factor for McEliece
             * @return estimated security level for these key parameters
             */

            size_t mceliece_work_factor(size_t code_size, size_t t);

            void mceliece_encrypt(secure_vector<uint8_t> &ciphertext_out, secure_vector<uint8_t> &error_mask_out,
                                  const secure_vector<uint8_t> &plaintext, const mceliece_public_key &key,
                                  random_number_generator &rng) {
                secure_vector<uint8_t> error_mask =
                    detail::create_random_error_vector(key.get_code_length(), key.get_t(), rng);

                secure_vector<uint8_t> ciphertext =
                    detail::mult_by_pubkey(plaintext, key.get_public_matrix(), key.get_code_length(), key.get_t());

                ciphertext ^= error_mask;

                ciphertext_out.swap(ciphertext);
                error_mask_out.swap(error_mask);
            }

            class mceliece {
            public:
                typedef mceliece_public_key public_key_policy;
                typedef mceliece_private_key private_key_policy;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
