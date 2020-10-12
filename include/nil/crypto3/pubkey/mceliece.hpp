//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_MCELIECE_KEY_HPP
#define CRYPTO3_PUBKEY_MCELIECE_KEY_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/pubkey/detail/mceliece/polyn_gf2m.hpp>

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

            struct mc_eliece_public_key { };

            struct mc_eliece_private_key { };

            struct mc_eliece {
                typedef mc_eliece_public_key public_key_type;
                typedef mc_eliece_private_key private_key_type;
            };

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

            mceliece_private_key::mceliece_private_key(polyn_gf2m const &goppa_polyn,
                                                       std::vector<uint32_t> const &parity_check_matrix_coeffs,
                                                       std::vector<polyn_gf2m> const &square_root_matrix,
                                                       std::vector<gf2m> const &inverse_support,
                                                       std::vector<uint8_t> const &public_matrix) :
                McEliece_PublicKey(public_matrix, goppa_polyn.get_degree(), inverse_support.size()),
                m_g(goppa_polyn), m_sqrtmod(square_root_matrix), m_Linv(inverse_support),
                m_coeffs(parity_check_matrix_coeffs),
                m_codimension(ceil_log2(inverse_support.size()) * goppa_polyn.get_degree()),
                m_dimension(inverse_support.size() - m_codimension) {
            }

            mceliece_private_key::mceliece_private_key(RandomNumberGenerator &rng, size_t code_length, size_t t) {
                uint32_t ext_deg = ceil_log2(code_length);
                *this = generate_mceliece_key(rng, ext_deg, code_length, t);
            }

            uint32_t McEliece_PublicKey::get_message_word_bit_length() const {
                uint32_t codimension = ceil_log2(m_code_length) * m_t;
                return m_code_length - codimension;
            }

            secure_vector<uint8_t> McEliece_PublicKey::random_plaintext_element(RandomNumberGenerator &rng) const {
                const size_t bits = get_message_word_bit_length();

                secure_vector<uint8_t> plaintext((bits + 7) / 8);
                rng.randomize(plaintext.data(), plaintext.size());

                // unset unused bits in the last plaintext byte
                if (uint32_t used = bits % 8) {
                    const uint8_t mask = (1 << used) - 1;
                    plaintext[plaintext.size() - 1] &= mask;
                }

                return plaintext;
            }

            algorithm_identifier McEliece_PublicKey::algorithm_identifier() const {
                return algorithm_identifier(get_oid(), std::vector<uint8_t>());
            }

            std::vector<uint8_t> McEliece_PublicKey::public_key_bits() const {
                return der_encoder()
                    .start_cons(SEQUENCE)
                    .start_cons(SEQUENCE)
                    .encode(static_cast<size_t>(get_code_length()))
                    .encode(static_cast<size_t>(get_t()))
                    .end_cons()
                    .encode(m_public_matrix, OCTET_STRING)
                    .end_cons()
                    .get_contents_unlocked();
            }

            size_t McEliece_PublicKey::key_length() const {
                return m_code_length;
            }

            size_t McEliece_PublicKey::estimated_strength() const {
                return mceliece_work_factor(m_code_length, m_t);
            }

            McEliece_PublicKey::McEliece_PublicKey(const std::vector<uint8_t> &key_bits) {
                ber_decoder dec(key_bits);
                size_t n;
                size_t t;
                dec.start_cons(SEQUENCE)
                    .start_cons(SEQUENCE)
                    .decode(n)
                    .decode(t)
                    .end_cons()
                    .decode(m_public_matrix, OCTET_STRING)
                    .end_cons();
                m_t = t;
                m_code_length = n;
            }

            secure_vector<uint8_t> mceliece_private_key::private_key_bits() const {
                der_encoder enc;
                enc.start_cons(SEQUENCE)
                    .start_cons(SEQUENCE)
                    .encode(static_cast<size_t>(get_code_length()))
                    .encode(static_cast<size_t>(get_t()))
                    .end_cons()
                    .encode(m_public_matrix, OCTET_STRING)
                    .encode(m_g.encode(),
                            OCTET_STRING);    // g as octet string
                enc.start_cons(SEQUENCE);
                for (uint32_t i = 0; i < m_sqrtmod.size(); i++) {
                    enc.encode(m_sqrtmod[i].encode(), OCTET_STRING);
                }
                enc.end_cons();
                secure_vector<uint8_t> enc_support;
                for (uint32_t i = 0; i < m_Linv.size(); i++) {
                    enc_support.push_back(m_Linv[i] >> 8);
                    enc_support.push_back(m_Linv[i]);
                }
                enc.encode(enc_support, OCTET_STRING);
                secure_vector<uint8_t> enc_H;
                for (uint32_t i = 0; i < m_coeffs.size(); i++) {
                    enc_H.push_back(m_coeffs[i] >> 24);
                    enc_H.push_back(m_coeffs[i] >> 16);
                    enc_H.push_back(m_coeffs[i] >> 8);
                    enc_H.push_back(m_coeffs[i]);
                }
                enc.encode(enc_H, OCTET_STRING);
                enc.end_cons();
                return enc.get_contents();
            }

            bool mceliece_private_key::check_key(RandomNumberGenerator &rng, bool) const {
                const secure_vector<uint8_t> plaintext = this->random_plaintext_element(rng);

                secure_vector<uint8_t> ciphertext;
                secure_vector<uint8_t> errors;
                mceliece_encrypt(ciphertext, errors, plaintext, *this, rng);

                secure_vector<uint8_t> plaintext_out;
                secure_vector<uint8_t> errors_out;
                mceliece_decrypt(plaintext_out, errors_out, ciphertext, *this);

                if (errors != errors_out || plaintext != plaintext_out) {
                    return false;
                }

                return true;
            }

            mceliece_private_key::mceliece_private_key(const secure_vector<uint8_t> &key_bits) {
                size_t n, t;
                secure_vector<uint8_t> enc_g;
                ber_decoder dec_base(key_bits);
                ber_decoder dec = dec_base.start_cons(SEQUENCE)
                                      .start_cons(SEQUENCE)
                                      .decode(n)
                                      .decode(t)
                                      .end_cons()
                                      .decode(m_public_matrix, OCTET_STRING)
                                      .decode(enc_g, OCTET_STRING);

                if (t == 0 || n == 0) {
                    throw decoding_error("invalid McEliece parameters");
                }

                uint32_t ext_deg = ceil_log2(n);
                m_code_length = n;
                m_t = t;
                m_codimension = (ext_deg * t);
                m_dimension = (n - m_codimension);

                std::shared_ptr<gf2m_field> sp_field(new gf2m_field(ext_deg));
                m_g = polyn_gf2m(enc_g, sp_field);
                if (m_g.get_degree() != static_cast<int>(t)) {
                    throw decoding_error("degree of decoded Goppa polynomial is incorrect");
                }
                ber_decoder dec2 = dec.start_cons(SEQUENCE);
                for (uint32_t i = 0; i < t / 2; i++) {
                    secure_vector<uint8_t> sqrt_enc;
                    dec2.decode(sqrt_enc, OCTET_STRING);
                    while (sqrt_enc.size() < (t * 2)) {
                        // ensure that the length is always t
                        sqrt_enc.push_back(0);
                        sqrt_enc.push_back(0);
                    }
                    if (sqrt_enc.size() != t * 2) {
                        throw decoding_error("length of square root polynomial entry is too large");
                    }
                    m_sqrtmod.push_back(polyn_gf2m(sqrt_enc, sp_field));
                }
                secure_vector<uint8_t> enc_support;
                ber_decoder dec3 = dec2.end_cons().decode(enc_support, OCTET_STRING);
                if (enc_support.size() % 2) {
                    throw decoding_error("encoded support has odd length");
                }
                if (enc_support.size() / 2 != n) {
                    throw decoding_error("encoded support has length different from code length");
                }
                for (uint32_t i = 0; i < n * 2; i += 2) {
                    gf2m el = (enc_support[i] << 8) | enc_support[i + 1];
                    m_Linv.push_back(el);
                }
                secure_vector<uint8_t> enc_H;
                dec3.decode(enc_H, OCTET_STRING).end_cons();
                if (enc_H.size() % 4) {
                    throw decoding_error("encoded parity check matrix has length which is not a multiple of four");
                }
                if (enc_H.size() / 4 != bit_size_to_32bit_size(m_codimension) * m_code_length) {
                    throw decoding_error("encoded parity check matrix has wrong length");
                }

                for (uint32_t i = 0; i < enc_H.size(); i += 4) {
                    uint32_t coeff = (enc_H[i] << 24) | (enc_H[i + 1] << 16) | (enc_H[i + 2] << 8) | enc_H[i + 3];
                    m_coeffs.push_back(coeff);
                }
            }

            bool mceliece_private_key::operator==(const mceliece_private_key &other) const {
                if (*static_cast<const McEliece_PublicKey *>(this) !=
                    *static_cast<const McEliece_PublicKey *>(&other)) {
                    return false;
                }
                if (m_g != other.m_g) {
                    return false;
                }

                if (m_sqrtmod != other.m_sqrtmod) {
                    return false;
                }
                if (m_Linv != other.m_Linv) {
                    return false;
                }
                if (m_coeffs != other.m_coeffs) {
                    return false;
                }

                if (m_codimension != other.m_codimension || m_dimension != other.m_dimension) {
                    return false;
                }

                return true;
            }

            bool McEliece_PublicKey::operator==(const McEliece_PublicKey &other) const {
                if (m_public_matrix != other.m_public_matrix) {
                    return false;
                }
                if (m_t != other.m_t) {
                    return false;
                }
                if (m_code_length != other.m_code_length) {
                    return false;
                }
                return true;
            }

            namespace {

                class MCE_KEM_Encryptor final : public pk_operations::kem_encryption_with_kdf {
                public:
                    MCE_KEM_Encryptor(const McEliece_PublicKey &key, const std::string &kdf) :
                        kem_encryption_with_kdf(kdf), m_key(key) {
                    }

                private:
                    void raw_kem_encrypt(secure_vector<uint8_t> &out_encapsulated_key,
                                         secure_vector<uint8_t> &raw_shared_key,
                                         nil::crypto3::random_number_generator &rng) override {
                        secure_vector<uint8_t> plaintext = m_key.random_plaintext_element(rng);

                        secure_vector<uint8_t> ciphertext, error_mask;
                        mceliece_encrypt(ciphertext, error_mask, plaintext, m_key, rng);

                        raw_shared_key.clear();
                        raw_shared_key += plaintext;
                        raw_shared_key += error_mask;

                        out_encapsulated_key.swap(ciphertext);
                    }

                    const McEliece_PublicKey &m_key;
                };

                class MCE_KEM_Decryptor final : public pk_operations::kem_decryption_with_kdf {
                public:
                    MCE_KEM_Decryptor(const mceliece_private_key &key, const std::string &kdf) :
                        kem_decryption_with_kdf(kdf), m_key(key) {
                    }

                private:
                    secure_vector<uint8_t> raw_kem_decrypt(const uint8_t encap_key[], size_t len) override {
                        secure_vector<uint8_t> plaintext, error_mask;
                        mceliece_decrypt(plaintext, error_mask, encap_key, len, m_key);

                        secure_vector<uint8_t> output;
                        output.reserve(plaintext.size() + error_mask.size());
                        output.insert(output.end(), plaintext.begin(), plaintext.end());
                        output.insert(output.end(), error_mask.begin(), error_mask.end());
                        return output;
                    }

                    const mceliece_private_key &m_key;
                };

            }    // namespace

            std::unique_ptr<pk_operations::kem_encryption> McEliece_PublicKey::create_kem_encryption_op(
                RandomNumberGenerator & /*random*/, const std::string &params, const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::kem_encryption>(new MCE_KEM_Encryptor(*this, params));
                }
                throw Provider_Not_Found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::kem_decryption> mceliece_private_key::create_kem_decryption_op(
                RandomNumberGenerator & /*random*/, const std::string &params, const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::kem_decryption>(new MCE_KEM_Decryptor(*this, params));
                }
                throw Provider_Not_Found(algo_name(), provider);
            }

            namespace {

                double binomial(size_t n, size_t k) {
                    double x = 1;

                    for (size_t i = 0; i != k; ++i) {
                        x *= n - i;
                        x /= k - i;
                    }

                    return x;
                }

                double log_binomial(size_t n, size_t k) {
                    double x = 0;

                    for (size_t i = 0; i != k; ++i) {
                        x += std::log(n - i);
                        x -= std::log(k - i);
                    }

                    return x / std::log(2);
                }

                double nb_iter(size_t n, size_t k, size_t w, size_t p, size_t l) {
                    double x = 2 * log_binomial(k / 2, p);
                    x += log_binomial(n - k - l, w - 2 * p);
                    x = log_binomial(n, w) - x;
                    return x;
                }

                double cout_iter(size_t n, size_t k, size_t p, size_t l) {
                    double x = binomial(k / 2, p);
                    const size_t i = static_cast<size_t>(std::log(x) / std::log(2));
                    double res = 2 * p * (n - k - l) * std::ldexp(x * x, -static_cast<int>(l));

                    // x <- binomial(k/2,p)*2*(2*l+log[2](binomial(k/2,p)))
                    x *= 2 * (2 * l + i);

                    // res <- k*(n-k)/2 +
                    // binomial(k/2,p)*2*(2*l+log[2](binomial(k/2,p))) +
                    // 2*p*(n-k-l)*binomial(k/2,p)^2/2^l
                    res += x + k * ((n - k) / 2.0);

                    return std::log(res) / std::log(2);    // convert to bits
                }

                double cout_total(size_t n, size_t k, size_t w, size_t p, size_t l) {
                    return nb_iter(n, k, w, p, l) + cout_iter(n, k, p, l);
                }

                double best_wf(size_t n, size_t k, size_t w, size_t p) {
                    if (p >= k / 2) {
                        return -1;
                    }

                    double min = cout_total(n, k, w, p, 0);

                    for (size_t l = 1; l < n - k; ++l) {
                        const double lwf = cout_total(n, k, w, p, l);
                        if (lwf < min) {
                            min = lwf;
                        } else {
                            break;
                        }
                    }

                    return min;
                }

            }    // namespace

            size_t mceliece_work_factor(size_t n, size_t t) {
                const size_t k = n - ceil_log2(n) * t;

                double min = cout_total(n, k, t, 0, 0);    // correspond a p=1
                for (size_t p = 0; p != t / 2; ++p) {
                    double lwf = best_wf(n, k + 1, t, p);
                    if (lwf < 0) {
                        break;
                    }

                    min = std::min(min, lwf);
                }

                return static_cast<size_t>(min);
            }

            namespace detail {
                secure_vector<uint8_t> aead_key(const secure_vector<uint8_t> &mk, const aead_mode &aead) {
                    // Fold the key as required for the AEAD mode in use
                    if (aead.valid_keylength(mk.size())) {
                        return mk;
                    }

                    secure_vector<uint8_t> r(aead.key_spec().maximum_keylength());
                    for (size_t i = 0; i != mk.size(); ++i) {
                        r[i % r.size()] ^= mk[i];
                    }
                    return r;
                }
            }    // namespace detail

            /**
             * McEliece Integrated Encryption System
             * Derive a shared key using MCE KEM and encrypt/authenticate the
             * plaintext and AD using AES-256 in OCB mode.
             */
            template<typename UniformRandomGenerator>
            secure_vector<uint8_t> mceies_encrypt(const mc_eliece_public_key &pubkey, const uint8_t pt[], size_t pt_len,
                                                  const uint8_t ad[], size_t ad_len, UniformRandomGenerator &rng,
                                                  const std::string &aead = "AES-256/OCB") {
                pk_kem_encryptor kem_op(pubkey, rng, "KDF1(SHA-512)");

                secure_vector<uint8_t> mce_ciphertext, mce_key;
                kem_op.encrypt(mce_ciphertext, mce_key, 64, rng);

                const size_t mce_code_bytes = (pubkey.get_code_length() + 7) / 8;

                BOOST_ASSERT_MSG(mce_ciphertext.size() == mce_code_bytes, "Unexpected size");

                std::unique_ptr<aead_mode> aead = aead_mode::create_or_throw(algo, ENCRYPTION);

                const size_t nonce_len = aead->default_nonce_length();

                aead->set_key(aead_key(mce_key, *aead));
                aead->set_associated_data(ad, ad_len);

                const secure_vector<uint8_t> nonce = rng.random_vec(nonce_len);

                secure_vector<uint8_t> msg(mce_ciphertext.size() + nonce.size() + pt_len);
                copy_mem(msg.data(), mce_ciphertext.data(), mce_ciphertext.size());
                copy_mem(msg.data() + mce_ciphertext.size(), nonce.data(), nonce.size());
                copy_mem(msg.data() + mce_ciphertext.size() + nonce.size(), pt, pt_len);

                aead->start(nonce);
                aead->finish(msg, mce_ciphertext.size() + nonce.size());
                return msg;
            }

            /**
             * McEliece Integrated Encryption System
             * Derive a shared key using MCE KEM and decrypt/authenticate the
             * ciphertext and AD using AES-256 in OCB mode.
             */
            secure_vector<uint8_t> mceies_decrypt(const mc_eliece_private_key &privkey, const uint8_t ct[],
                                                  size_t ct_len, const uint8_t ad[], size_t ad_len,
                                                  const std::string &aead = "AES-256/OCB") {
                try {
                    Null_RNG null_rng;
                    pk_kem_decryptor kem_op(privkey, null_rng, "KDF1(SHA-512)");

                    const size_t mce_code_bytes = (privkey.get_code_length() + 7) / 8;

                    std::unique_ptr<aead_mode> aead = aead_mode::create_or_throw(algo, DECRYPTION);

                    const size_t nonce_len = aead->default_nonce_length();

                    if (ct_len < mce_code_bytes + nonce_len + aead->tag_size()) {
                        throw Exception("Input message too small to be valid");
                    }

                    const secure_vector<uint8_t> mce_key = kem_op.decrypt(ct, mce_code_bytes, 64);

                    aead->set_key(aead_key(mce_key, *aead));
                    aead->set_associated_data(ad, ad_len);

                    secure_vector<uint8_t> pt(ct + mce_code_bytes + nonce_len, ct + ct_len);

                    aead->start(&ct[mce_code_bytes], nonce_len);
                    aead->finish(pt, 0);
                    return pt;
                } catch (Integrity_Failure &) {
                    throw;
                } catch (std::exception &e) {
                    throw Exception("mce_decrypt failed: " + std::string(e.what()));
                }
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
