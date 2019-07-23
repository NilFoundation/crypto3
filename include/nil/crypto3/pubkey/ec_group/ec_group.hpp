#ifndef CRYPTO3_ECC_DOMAIN_PARAMETERS_HPP
#define CRYPTO3_ECC_DOMAIN_PARAMETERS_HPP

#include <nil/crypto3/pubkey/ec_group/point_gfp.hpp>
#include <nil/crypto3/pubkey/ec_group/point_mul.hpp>

#include <nil/crypto3/asn1/asn1_oid.hpp>

#include <memory>
#include <set>

namespace nil {
    namespace crypto3 {

        /**
         * This class represents elliptic curve domain parameters
         */
        enum ec_group_encoding { EC_DOMPAR_ENC_EXPLICIT = 0, EC_DOMPAR_ENC_IMPLICITCA = 1, EC_DOMPAR_ENC_oid_t = 2 };

        class ec_group_data;

        class ec_group_data_map;

        /**
         * @brief Class representing an elliptic curve
         */
        template<typename CurveType, typename NumberType = typename CurveType::number_type>
        class ec_group {
        public:
            typedef NumberType number_type;
            typedef CurveType curve_type;

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
            template<typename Backend, expression_template_option ExpressionTemplates>
            ec_group(const number<Backend, ExpressionTemplates> &p, const number<Backend, ExpressionTemplates> &a,
                     const number<Backend, ExpressionTemplates> &b, const number<Backend, ExpressionTemplates> &base_x,
                     const number<Backend, ExpressionTemplates> &base_y,
                     const number<Backend, ExpressionTemplates> &order,
                     const number<Backend, ExpressionTemplates> &cofactor, const oid_t &oid = oid_t()) :
                m_curve(p, a, b),
                m_base_point(m_curve, base_x, base_y), m_g_x(base_x), m_g_y(base_y), m_order(order),
                m_cofactor(cofactor), m_mod_order(order), m_base_mult(m_base_point, m_mod_order), m_oid(oid),
                m_p_bits(msb(p)), m_order_bits(msb(order)), m_a_is_minus_3(a == p - 3), m_a_is_zero(a == 0) {
            }

            /**
             * Decode a BER encoded ECC domain parameter set
             * @param ber_encoding the bytes of the BER encoding
             */
            explicit ec_group(const std::vector<uint8_t> &ber_encoding) {
                m_data = ber_decode_ec_group(ber.data(), ber.size());
            }

            /**
             * Create an EC domain by oid_t (or throw if unknown)
             * @param oid the oid_t of the EC domain to create
             */
            explicit ec_group(const oid_t &oid) {
                this->m_data = ec_group_data().lookup(oid);
                if (!this->m_data) {
                    throw std::invalid_argument("Unknown ec_group " + oid.as_string());
                }
            }

            /**
             * Create an EC domain from PEM encoding (as from pem_encode), or
             * from an oid_t name (eg "secp256r1", or "1.2.840.10045.3.1.7")
             * @param str PEM-encoded data, or an oid_t
             */
            explicit ec_group(const std::string &str) {
                if (str.empty()) {
                    return;
                }    // no initialization / uninitialized

                try {
                    oid_t oid = oid_tS::lookup(str);
                    if (!oid.empty()) {
                        m_data = ec_group_data().lookup(oid);
                    }
                } catch (Invalid_oid_t &) {
                }

                if (m_data == nullptr) {
                    if (str.size() > 30 && str.substr(0, 29) == "-----BEGIN EC PARAMETERS-----") {
                        // OK try it as PEM ...
                        secure_vector<uint8_t> ber = pem_code::decode_check_label(str, "EC PARAMETERS");
                        this->m_data = ber_decode_ec_group(ber.data(), ber.size());
                    }
                }

                if (m_data == nullptr) {
                    throw std::invalid_argument("Unknown ECC group '" + str + "'");
                }
            }

            /**
             * Create an uninitialized ec_group
             */
            ec_group() = default;

            ~ec_group() = default;

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
            bool a_is_minus_3() const {
                return m_a_is_minus_3;
            }

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
            const number_type &get_p() const;

            /**
             * Return the a parameter of the elliptic curve equation
             */
            const number_type &get_a() const;

            /**
             * Return the b parameter of the elliptic curve equation
             */
            const number_type &get_b() const;

            /**
             * Return group base point
             * @result base point
             */
            const point_gfp<curve_type> &get_base_point() const;

            /**
             * Return the x coordinate of the base point
             */
            const number_type &get_g_x() const;

            /**
             * Return the y coordinate of the base point
             */
            const number_type &get_g_y() const;

            /**
             * Return the order of the base point
             * @result order of the base point
             */
            const number_type &get_order() const;

            /*
             * Reduce x modulo the order
             */
            number_type mod_order(const number_type &x) const;

            /*
             * Return inverse of x modulo the order
             */
            number_type inverse_mod_order(const number_type &x) const;

            /*
             * Reduce (x*x) modulo the order
             */
            number_type square_mod_order(const number_type &x) const;

            /*
             * Reduce (x*y) modulo the order
             */
            number_type multiply_mod_order(const number_type &x, const number_type &y) const;

            /*
             * Reduce (x*y*z) modulo the order
             */
            number_type multiply_mod_order(const number_type &x, const number_type &y, const number_type &z) const;

            /**
             * Return the cofactor
             * @result the cofactor
             */
            const number_type &get_cofactor() const;

            /**
             * Check if y is a plausible point on the curve
             *
             * In particular, checks that it is a point on the curve, not infinity,
             * and that it has order matching the group.
             */
            bool verify_public_element(const point_gfp<curve_type> &y) const;

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
            point_gfp<curve_type> point(const number_type &x, const number_type &y) const;

            /**
             * Multi exponentiate. Not constant time.
             * @return base_point*x + pt*y
             */
            point_gfp<curve_type> point_multiply(const number_type &x, const point_gfp &pt, const number_type &y) const;

            /**
             * Blinded point multiplication, attempts resistance to side channels
             * @param k the scalar
             * @param rng a random number generator
             * @param ws a temp workspace
             * @return base_point*k
             */
            template<typename UniformRandomGenerator>
            point_gfp<curve_type> blinded_base_point_multiply(const number_type &k, UniformRandomGenerator &rng,
                                                              std::vector<number_type> &ws) const;

            /**
             * Blinded point multiplication, attempts resistance to side channels
             * Returns just the x coordinate of the point
             *
             * @param k the scalar
             * @param rng a random number generator
             * @param ws a temp workspace
             * @return x coordinate of base_point*k
             */
            template<typename UniformRandomGenerator>
            number_type blinded_base_point_multiply_x(const number_type &k, UniformRandomGenerator &rng,
                                                      std::vector<number_type> &ws) const;

            /**
             * Blinded point multiplication, attempts resistance to side channels
             * @param point input point
             * @param k the scalar
             * @param rng a random number generator
             * @param ws a temp workspace
             * @return point*k
             */
            template<typename UniformRandomGenerator>
            point_gfp<curve_type> blinded_var_point_multiply(const point_gfp<curve_type> &point, const number_type &k,
                                                             UniformRandomGenerator &rng,
                                                             std::vector<number_type> &ws) const;

            /**
             * Return a random scalar ie an integer in [1,order)
             */
            template<typename UniformRandomGenerator>
            number_type random_scalar(UniformRandomGenerator &rng) const;

            /**
             * Return the zero (or infinite) point on this curve
             */
            point_gfp<curve_type> zero_point() const;

            size_t point_size(typename point_gfp<curve_type>::compression_type format) const;

            point_gfp<curve_type> os2ecp(const uint8_t bits[], size_t len) const;

            template<typename Alloc>
            point_gfp<curve_type> os2ecp(const std::vector<uint8_t, Alloc> &vec) const {
                return this->os2ecp(vec.data(), vec.size());
            }

            bool initialized() const {
                return (m_data != nullptr);
            }

            /**
             * Verify ec_group domain
             * @returns true if group is valid. false otherwise
             */
            template<typename UniformRandomGenerator>
            bool verify_group(UniformRandomGenerator &rng, bool strong = false) const;

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
            curve_gfp<NumberType> m_curve;
            point_gfp<CurveType> m_base_point;

            NumberType m_g_x;
            NumberType m_g_y;
            NumberType m_order;
            NumberType m_cofactor;
            modular_reducer m_mod_order;
            point_gfp_base_point_precompute m_base_mult;
            oid_t m_oid;
            size_t m_p_bits;
            size_t m_order_bits;
            bool m_a_is_minus_3;
            bool m_a_is_zero;

            static ec_group_data_map &ec_group_data();

            static std::shared_ptr<ec_group_data> ber_decode_ec_group(const uint8_t bits[], size_t len);

            static std::shared_ptr<ec_group_data> load_ec_group_info(const char *p, const char *a, const char *b,
                                                                     const char *g_x, const char *g_y,
                                                                     const char *order, const oid_t &oid);

            // Member data
            const ec_group_data &data() const;

            std::shared_ptr<ec_group_data> m_data;
        };

        template<typename CurveType, typename NumberType = typename CurveType::number_type>
        inline bool operator!=(const ec_group<CurveType, NumberType> &lhs, const ec_group<CurveType, NumberType> &rhs) {
            return !(lhs == rhs);
        }
    }    // namespace crypto3
}    // namespace nil

#endif
