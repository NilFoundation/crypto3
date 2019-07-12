#ifndef CRYPTO3_ECC_DOMAIN_PARAMETERS_HPP_
#define CRYPTO3_ECC_DOMAIN_PARAMETERS_HPP_

#include <nil/crypto3/pubkey/ec_group/point_gfp.hpp>

#include <nil/crypto3/asn1/asn1_oid.hpp>

#include <memory>
#include <set>

namespace nil {
    namespace crypto3 {

/**
* This class represents elliptic curve domain parameters
*/
        enum ec_group_encoding {
            EC_DOMPAR_ENC_EXPLICIT = 0, EC_DOMPAR_ENC_IMPLICITCA = 1, EC_DOMPAR_ENC_oid_t = 2
        };

        class curve_gfp;

        class ec_group_data;

        class ec_group_data_map;

        /**
         * @brief Class representing an elliptic curve
         */
        class ec_group final {
        public:
            /**
            * Construct Domain parameters from specified parameters
            * @param p the elliptic curve p
            * @param a the elliptic curve a param
            * @param b the elliptic curve b param
            * @param base_x the x coordinate of the base point
            * @param base_y the y coordinate of the base point
            * @param order the order of the base point
            * @param cofactor the cofactor
            * @param oid an optional oid_t used to identify this curve
            */
            ec_group(const cpp_int &p, const cpp_int &a, const cpp_int &b, const cpp_int &base_x, const cpp_int &base_y,
                     const cpp_int &order, const cpp_int &cofactor, const oid_t &oid = oid_t()) {
                m_data = ec_group_data().lookup_or_create(p, a, b, base_x, base_y, order, cofactor, oid);
            }

            /**
            * Decode a BER encoded ECC domain parameter set
            * @param ber_encoding the bytes of the BER encoding
            */
            explicit ec_group(const std::vector<uint8_t> &ber_encoding);

            /**
            * Create an EC domain by oid_t (or throw if unknown)
            * @param oid the oid_t of the EC domain to create
            */
            explicit ec_group(const oid_t &oid);

            /**
            * Create an EC domain from PEM encoding (as from pem_encode), or
            * from an oid_t name (eg "secp256r1", or "1.2.840.10045.3.1.7")
            * @param pem_or_oid PEM-encoded data, or an oid_t
            */
            explicit ec_group(const std::string &pem_or_oid);

            /**
            * Create an uninitialized ec_group
            */
            ec_group();

            ~ec_group();

            /**
            * Create the DER encoding of this domain
            * @param form of encoding to use
            * @returns bytes encododed as DER
            */
            std::vector<uint8_t> der_encode(ec_group_encoding form) const;

            /**
            * Return the PEM encoding (always in explicit form)
            * @return string containing PEM data
            */
            std::string pem_encode() const;

            /**
            * Return if a == -3 mod p
            */
            bool a_is_minus_3() const;

            /**
            * Return if a == 0 mod p
            */
            bool a_is_zero() const;

            /**
            * Return the size of p in bits (same as get_p().bits())
            */
            size_t get_p_bits() const;

            /**
            * Return the size of p in bits (same as get_p().bytes())
            */
            size_t get_p_bytes() const;

            /**
            * Return the size of group order in bits (same as get_order().bits())
            */
            size_t get_order_bits() const;

            /**
            * Return the size of p in bytes (same as get_order().bytes())
            */
            size_t get_order_bytes() const;

            /**
            * Return the prime modulus of the field
            */
            const cpp_int &get_p() const;

            /**
            * Return the a parameter of the elliptic curve equation
            */
            const cpp_int &get_a() const;

            /**
            * Return the b parameter of the elliptic curve equation
            */
            const cpp_int &get_b() const;

            /**
            * Return group base point
            * @result base point
            */
            const point_gfp &get_base_point() const;

            /**
            * Return the x coordinate of the base point
            */
            const cpp_int &get_g_x() const;

            /**
            * Return the y coordinate of the base point
            */
            const cpp_int &get_g_y() const;

            /**
            * Return the order of the base point
            * @result order of the base point
            */
            const cpp_int &get_order() const;

            /*
            * Reduce x modulo the order
            */
            cpp_int mod_order(const cpp_int &x) const;

            /*
            * Return inverse of x modulo the order
            */
            cpp_int inverse_mod_order(const cpp_int &x) const;

            /*
            * Reduce (x*x) modulo the order
            */
            cpp_int square_mod_order(const cpp_int &x) const;

            /*
            * Reduce (x*y) modulo the order
            */
            cpp_int multiply_mod_order(const cpp_int &x, const cpp_int &y) const;

            /*
            * Reduce (x*y*z) modulo the order
            */
            cpp_int multiply_mod_order(const cpp_int &x, const cpp_int &y, const cpp_int &z) const;

            /**
            * Return the cofactor
            * @result the cofactor
            */
            const cpp_int &get_cofactor() const;

            /**
            * Check if y is a plausible point on the curve
            *
            * In particular, checks that it is a point on the curve, not infinity,
            * and that it has order matching the group.
            */
            bool verify_public_element(const point_gfp &y) const;

            /**
            * Return the oid_t of these domain parameters
            * @result the oid_t as a string
            */
            std::string CRYPTO3_DEPRECATED("Use get_curve_oid") get_oid() const {
                return get_curve_oid().as_string();
            }

            /**
            * Return the oid_t of these domain parameters
            * @result the oid_t
            */
            const oid_t &get_curve_oid() const;

            /**
            * Return a point on this curve with the affine values x, y
            */
            point_gfp point(const cpp_int &x, const cpp_int &y) const;

            /**
            * Multi exponentiate. Not constant time.
            * @return base_point*x + pt*y
            */
            point_gfp point_multiply(const cpp_int &x, const point_gfp &pt, const cpp_int &y) const;

            /**
            * Blinded point multiplication, attempts resistance to side channels
            * @param k the scalar
            * @param rng a random number generator
            * @param ws a temp workspace
            * @return base_point*k
            */
            point_gfp blinded_base_point_multiply(const cpp_int &k, random_number_generator &rng,
                                                  std::vector<cpp_int> &ws) const;

            /**
            * Blinded point multiplication, attempts resistance to side channels
            * Returns just the x coordinate of the point
            *
            * @param k the scalar
            * @param rng a random number generator
            * @param ws a temp workspace
            * @return x coordinate of base_point*k
            */
            cpp_int blinded_base_point_multiply_x(const cpp_int &k, random_number_generator &rng,
                                                  std::vector<cpp_int> &ws) const;

            /**
            * Blinded point multiplication, attempts resistance to side channels
            * @param point input point
            * @param k the scalar
            * @param rng a random number generator
            * @param ws a temp workspace
            * @return point*k
            */
            point_gfp blinded_var_point_multiply(const point_gfp &point, const cpp_int &k, random_number_generator &rng,
                                                 std::vector<cpp_int> &ws) const;

            /**
            * Return a random scalar ie an integer in [1,order)
            */
            cpp_int random_scalar(random_number_generator &rng) const;

            /**
            * Return the zero (or infinite) point on this curve
            */
            point_gfp zero_point() const;

            size_t point_size(point_gfp::compression_type format) const;

            point_gfp os2ecp(const uint8_t bits[], size_t len) const;

            template<typename Alloc>
            point_gfp os2ecp(const std::vector<uint8_t, Alloc> &vec) const {
                return this->os2ecp(vec.data(), vec.size());
            }

            bool initialized() const {
                return (m_data != nullptr);
            }

            /**
             * Verify ec_group domain
             * @returns true if group is valid. false otherwise
             */
            bool verify_group(random_number_generator &rng, bool strong = false) const;

            bool operator==(const ec_group &other) const;

            /**
            * Return a set of known named EC groups
            */
            static const std::set<std::string> &known_named_groups();

            /*
            * For internal use only
            */
            static std::shared_ptr<ec_group_data> ec_group_info(const oid_t &oid);

            static size_t clear_registered_curve_data();

        private:
            static ec_group_data_map &ec_group_data();

            static std::shared_ptr<ec_group_data> ber_decode_ec_group(const uint8_t bits[], size_t len);

            static std::shared_ptr<ec_group_data> load_ec_group_info(const char *p, const char *a, const char *b,
                                                                     const char *g_x, const char *g_y,
                                                                     const char *order, const oid_t &oid);

            // Member data
            const ec_group_data &data() const;

            std::shared_ptr<ec_group_data> m_data;
        };

        inline bool operator!=(const ec_group &lhs, const ec_group &rhs) {
            return !(lhs == rhs);
        }
    }
}

#endif
