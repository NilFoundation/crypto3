#ifndef CRYPTO3_MCELIECE_KEY_HPP
#define CRYPTO3_MCELIECE_KEY_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/pubkey/mce/polyn_gf2m.hpp>
#include <nil/crypto3/utilities/exceptions.hpp>

namespace nil {
    namespace crypto3 {

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

            std::unique_ptr<pk_operations::kem_encryption> create_kem_encryption_op(random_number_generator &rng,
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
                                  std::vector<gf2m> const &inverse_support, std::vector<uint8_t> const &public_matrix);

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

        class mceliece {
        public:
            typedef mceliece_public_key public_key_policy;
            typedef mceliece_private_key private_key_policy;
        };
    }    // namespace crypto3
}    // namespace nil

#endif
