//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ECC_DOMAIN_PARAMETERS_HPP
#define CRYPTO3_PUBKEY_ECC_DOMAIN_PARAMETERS_HPP

#include <nil/crypto3/pubkey/pem.hpp>

#include <nil/crypto3/pubkey/ec_group/ec_group_info.hpp>
#include <nil/crypto3/pubkey/ec_group/point_gfp.hpp>
#include <nil/crypto3/pubkey/ec_group/point_mul.hpp>

#include <memory>
#include <set>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            /**
             * This class represents elliptic curve domain parameters
             */
            enum ec_group_encoding {
                EC_DOMPAR_ENC_EXPLICIT = 0,
                EC_DOMPAR_ENC_IMPLICITCA = 1,
                EC_DOMPAR_ENC_oid_t = 2
            };

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
                         const number<Backend, ExpressionTemplates> &b,
                         const number<Backend, ExpressionTemplates> &base_x,
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
                std::vector<uint8_t> der_encode(ec_group_encoding form) const {
                    std::vector<uint8_t> output;

                    der_encoder der(output);

                    if (form == EC_DOMPAR_ENC_EXPLICIT) {
                        const size_t ecpVers1 = 1;
                        const oid_t curve_type("1.2.840.10045.1.1");    // prime field

                        const size_t p_bytes = get_p_bytes();

                        der.start_cons(SEQUENCE)
                            .encode(ecpVers1)
                            .start_cons(SEQUENCE)
                            .encode(curve_type)
                            .encode(get_p())
                            .end_cons()
                            .start_cons(SEQUENCE)
                            .encode(number_type::encode_1363(a(), p_bytes), OCTET_STRING)
                            .encode(number_type::encode_1363(b(), p_bytes), OCTET_STRING)
                            .end_cons()
                            .encode(get_base_point().encode(point_gfp<CurveType>::UNCOMPRESSED), OCTET_STRING)
                            .encode(get_order())
                            .encode(get_cofactor())
                            .end_cons();
                    } else if (form == EC_DOMPAR_ENC_oid_t) {
                        const oid_t oid = get_curve_oid();
                        if (oid.empty()) {
                            throw encoding_error("Cannot encode ec_group as oid_t because oid_t not set");
                        }
                        der.encode(oid);
                    } else if (form == EC_DOMPAR_ENC_IMPLICITCA) {
                        der.encode_null();
                    } else {
                        throw internal_error("ec_group::der_encode: Unknown encoding");
                    }

                    return output;
                }

                /**
                 * Return the PEM encoding (always in explicit form)
                 * @return string containing PEM data
                 */
                std::string pem_encode() const {
                    const std::vector<uint8_t> der = der_encode(EC_DOMPAR_ENC_EXPLICIT);
                    return pem_code::encode(der, "EC PARAMETERS");
                }

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
                 * Return the size of p in bits (same as p().bits())
                 */
                size_t get_p_bits() const;

                /**
                 * Return the size of p in bits (same as p().bytes())
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
                const number_type &p() const;

                /**
                 * Return the a parameter of the elliptic curve equation
                 */
                const number_type &a() const;

                /**
                 * Return the b parameter of the elliptic curve equation
                 */
                const number_type &b() const;

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
                bool verify_public_element(const point_gfp<curve_type> &y) const {
                    // check that public point is not at infinity
                    if (y == 0) {
                        return false;
                    }

                    // check that public point is on the curve
                    if (!y.on_the_curve()) {
                        return false;
                    }

                    // check that public point has order q
                    if (!(y * get_order()) == 0) {
                        return false;
                    }

                    if (get_cofactor() > 1) {
                        if ((y * get_cofactor()) == 0) {
                            return false;
                        }
                    }

                    return true;
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
                point_gfp<curve_type> point_multiply(const number_type &x, const point_gfp<curve_type> &pt,
                                                     const number_type &y) const {
                    point_gfp_multi_point_precompute<curve_type, number_type> xy_mul(get_base_point(), pt);
                    return xy_mul.multi_exp(x, y);
                }

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
                point_gfp<curve_type> blinded_var_point_multiply(const point_gfp<curve_type> &point,
                                                                 const number_type &k, UniformRandomGenerator &rng,
                                                                 std::vector<number_type> &ws) const {
                    point_gfp_var_point_precompute mul(point, rng, ws);
                    return mul.mul(k, rng, get_order(), ws);
                }

                /**
                 * Return a random scalar ie an integer in [1,order)
                 */
                template<typename UniformRandomGenerator>
                number_type random_scalar(UniformRandomGenerator &rng) const {
                    return number_type::random_integer(rng, 1, get_order());
                }

                /**
                 * Return the zero (or infinite) point on this curve
                 */
                point_gfp<curve_type> zero_point() const {
                    return point_gfp<curve_type>(m_curve);
                }

                size_t point_size(typename point_gfp<curve_type>::compression_type format) const {
                    // Hybrid and standard format are (x,y), compressed is y, +1 format byte
                    if (format == point_gfp<curve_type>::COMPRESSED) {
                        return (1 + get_p_bytes());
                    } else {
                        return (1 + 2 * get_p_bytes());
                    }
                }

                point_gfp<curve_type> os2ecp(const uint8_t bits[], size_t len) const {
                    return nil::crypto3::os2ecp(bits, len, data().curve());
                }

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
                bool verify_group(UniformRandomGenerator &rng, bool strong = false) const {
                    const number_type &p = p();
                    const number_type &a = a();
                    const number_type &b = b();
                    const number_type &order = get_order();
                    const point_gfp<CurveType> &base_point = get_base_point();

                    if (a < 0 || a >= p) {
                        return false;
                    }
                    if (b <= 0 || b >= p) {
                        return false;
                    }
                    if (order <= 0) {
                        return false;
                    }

                    // check if field modulus is prime
                    if (!miller_rabin_test(p, 128, rng)) {
                        return false;
                    }

                    // check if order is prime
                    if (!miller_rabin_test(order, 128, rng)) {
                        return false;
                    }

                    // compute the discriminant: 4*a^3 + 27*b^2 which must be nonzero
                    const modular_reducer mod_p(p);

                    const number_type discriminant =
                        mod_p.reduce(mod_p.multiply(4, mod_p.cube(a)) + mod_p.multiply(27, mod_p.square(b)));

                    if (discriminant == 0) {
                        return false;
                    }

                    // check for valid cofactor
                    if (get_cofactor() < 1) {
                        return false;
                    }

                    // check if the base point is on the curve
                    if (!base_point.on_the_curve()) {
                        return false;
                    }
                    if ((base_point * get_cofactor()) == 0) {
                        return false;
                    }
                    // check if order of the base point is correct
                    return (base_point * order) == 0;
                }

                bool operator==(const ec_group &other) const {
                    if (m_data == other.m_data) {
                        return true;
                    }    // same shared rep

                    /*
                     * No point comparing order/cofactor as they are uniquely determined
                     * by the curve equation (p,a,b) and the base point.
                     */
                    return (p() == other.p() && a() == other.a() && b() == other.b() && get_g_x() == other.get_g_x() &&
                            get_g_y() == other.get_g_y());
                }

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
                modular_reducer m_mod_order {};
                point_gfp_base_point_precompute m_base_mult {};
                oid_t m_oid;
                size_t m_p_bits {};
                size_t m_order_bits {};
                bool m_a_is_minus_3 {};
                bool m_a_is_zero {};

                static ec_group_data_map &ec_group_data();

                static std::shared_ptr<ec_group_data> ber_decode_ec_group(const uint8_t bits[], size_t len);

                static std::shared_ptr<ec_group_data> load_ec_group_info(const char *p, const char *a, const char *b,
                                                                         const char *g_x, const char *g_y,
                                                                         const char *order, const oid_t &oid);

                // Member data
                const ec_group_data &data() const;

                std::shared_ptr<ec_group_data> m_data {};
            };

            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            inline bool operator!=(const ec_group<CurveType, NumberType> &lhs,
                                   const ec_group<CurveType, NumberType> &rhs) {
                return !(lhs == rhs);
            }

            class ec_group_data final {
            public:
                ec_group_data(const number_type &p, const number_type &a, const number_type &b, const number_type &g_x,
                              const number_type &g_y, const number_type &order, const number_type &cofactor,
                              const oid_t &oid) :
                    m_curve(p, a, b),
                    m_base_point(m_curve, g_x, g_y), m_g_x(g_x), m_g_y(g_y), m_order(order), m_cofactor(cofactor),
                    m_mod_order(order), m_base_mult(m_base_point, m_mod_order), m_oid(oid), m_p_bits(msb(p)),
                    m_order_bits(msb(order)), m_a_is_minus_3(a == p - 3), m_a_is_zero(a == 0) {
                }

                bool match(const number_type &p, const number_type &a, const number_type &b, const number_type &g_x,
                           const number_type &g_y, const number_type &order, const number_type &cofactor) const {
                    return (this->p() == p && this->a() == a && this->b() == b && this->order() == order &&
                            this->cofactor() == cofactor && this->g_x() == g_x && this->g_y() == g_y);
                }

                const oid_t &oid() const {
                    return m_oid;
                }

                const number_type &p() const {
                    return m_curve.p();
                }

                const number_type &a() const {
                    return m_curve.a();
                }

                const number_type &b() const {
                    return m_curve.b();
                }

                const number_type &order() const {
                    return m_order;
                }

                const number_type &cofactor() const {
                    return m_cofactor;
                }

                const number_type &g_x() const {
                    return m_g_x;
                }

                const number_type &g_y() const {
                    return m_g_y;
                }

                size_t p_bits() const {
                    return m_p_bits;
                }

                size_t p_bytes() const {
                    return (m_p_bits + 7) / 8;
                }

                size_t order_bits() const {
                    return m_order_bits;
                }

                size_t order_bytes() const {
                    return (m_order_bits + 7) / 8;
                }

                const curve_gfp &curve() const {
                    return m_curve;
                }

                const point_gfp &base_point() const {
                    return m_base_point;
                }

                bool a_is_minus_3() const {
                    return m_a_is_minus_3;
                }

                bool a_is_zero() const {
                    return m_a_is_zero;
                }

                number_type mod_order(const number_type &x) const {
                    return m_mod_order.reduce(x);
                }

                number_type square_mod_order(const number_type &x) const {
                    return m_mod_order.square(x);
                }

                number_type multiply_mod_order(const number_type &x, const number_type &y) const {
                    return m_mod_order.multiply(x, y);
                }

                number_type multiply_mod_order(const number_type &x, const number_type &y, const number_type &z) const {
                    return m_mod_order.multiply(m_mod_order.multiply(x, y), z);
                }

                number_type inverse_mod_order(const number_type &x) const {
                    return inverse_mod(x, m_order);
                }

                point_gfp blinded_base_point_multiply(const number_type &k, random_number_generator &rng,
                                                      std::vector<number_type> &ws) const {
                    return m_base_mult.mul(k, rng, m_order, ws);
                }

            private:
                curve_gfp m_curve;
                point_gfp m_base_point;

                number_type m_g_x;
                number_type m_g_y;
                number_type m_order;
                number_type m_cofactor;
                modular_reducer m_mod_order;
                point_gfp_base_point_precompute m_base_mult;
                oid_t m_oid;
                size_t m_p_bits;
                size_t m_order_bits;
                bool m_a_is_minus_3;
                bool m_a_is_zero;
            };

            class ec_group_data_map final {
            public:
                ec_group_data_map() {
                }

                size_t clear() {
                    lock_guard_type<mutex_type> lock(m_mutex);
                    size_t count = m_registered_curves.size();
                    m_registered_curves.clear();
                    return count;
                }

                std::shared_ptr<ec_group_data> lookup(const oid_t &oid) {
                    lock_guard_type<mutex_type> lock(m_mutex);

                    for (auto i : m_registered_curves) {
                        if (i->oid() == oid) {
                            return i;
                        }
                    }

                    // Not found, check hardcoded data
                    std::shared_ptr<ec_group_data> data = ec_group::ec_group_info(oid);

                    if (data) {
                        m_registered_curves.push_back(data);
                        return data;
                    }

                    // Nope, unknown curve
                    return std::shared_ptr<ec_group_data>();
                }

                std::shared_ptr<ec_group_data> lookup_or_create(const number_type &p,
                                                                const number_type &a,
                                                                const number_type &b,
                                                                const number_type &g_x,
                                                                const number_type &g_y,
                                                                const number_type &order,
                                                                const number_type &cofactor,
                                                                const oid_t &oid) {
                    lock_guard_type<mutex_type> lock(m_mutex);

                    for (auto i : m_registered_curves) {
                        if (oid.has_value()) {
                            if (i->oid() == oid) {
                                return i;
                            } else if (i->oid().has_value()) {
                                continue;
                            }
                        }

                        if (i->match(p, a, b, g_x, g_y, order, cofactor)) {
                            return i;
                        }
                    }

                    // Not found - if oid_t is set try looking up that way

                    if (oid.has_value()) {
                        // Not located in existing store - try hardcoded data set
                        std::shared_ptr<ec_group_data> data = ec_group::ec_group_info(oid);

                        if (data) {
                            m_registered_curves.push_back(data);
                            return data;
                        }
                    }

                    // Not found or no oid_t, add data and return
                    return add_curve(p, a, b, g_x, g_y, order, cofactor, oid);
                }

            private:
                std::shared_ptr<ec_group_data> add_curve(const number_type &p, const number_type &a,
                                                         const number_type &b, const number_type &g_x,
                                                         const number_type &g_y, const number_type &order,
                                                         const number_type &cofactor, const oid_t &oid) {
                    std::shared_ptr<ec_group_data> d =
                        std::make_shared<ec_group_data>(p, a, b, g_x, g_y, order, cofactor, oid);

                    // This function is always called with the lock held
                    m_registered_curves.push_back(d);
                    return d;
                }

                mutex_type m_mutex;
                std::vector<std::shared_ptr<ec_group_data>> m_registered_curves;
            };

            // static
            ec_group_data_map &ec_group::ec_group_data() {
                /*
                 * This exists purely to ensure the allocator is constructed before g_ec_data,
                 * which ensures that its destructor runs after ~g_ec_data is complete.
                 */

                static allocator_initializer g_init_allocator;
                static ec_group_data_map g_ec_data;
                return g_ec_data;
            }

            // static
            size_t ec_group::clear_registered_curve_data() {
                return ec_group_data().clear();
            }

            // static
            std::shared_ptr<ec_group_data> ec_group::load_ec_group_info(const char *p_str, const char *a_str,
                                                                        const char *b_str, const char *g_x_str,
                                                                        const char *g_y_str, const char *order_str,
                                                                        const oid_t &oid) {
                const number_type p(p_str);
                const number_type a(a_str);
                const number_type b(b_str);
                const number_type g_x(g_x_str);
                const number_type g_y(g_y_str);
                const number_type order(order_str);
                const number_type cofactor(1);    // implicit

                return std::make_shared<ec_group_data>(p, a, b, g_x, g_y, order, cofactor, oid);
            }

            // static
            std::shared_ptr<ec_group_data> ec_group::ber_decode_ec_group(const uint8_t bits[], size_t len) {
                ber_decoder ber(bits, len);
                ber_object obj = ber.get_next_object();

                if (obj.type() == NULL_TAG) {
                    throw decoding_error("Cannot handle ImplicitCA ECC parameters");
                } else if (obj.type() == OBJECT_ID) {
                    oid_t dom_par_oid;
                    ber_decoder(bits, len).decode(dom_par_oid);
                    return ec_group_data().lookup(dom_par_oid);
                } else if (obj.type() == SEQUENCE) {
                    number_type p, a, b, order, cofactor;
                    std::vector<uint8_t> base_pt;
                    std::vector<uint8_t> seed;

                    ber_decoder(bits, len)
                        .start_cons(SEQUENCE)
                        .decode_and_check<size_t>(1,
                                                  "Unknown ECC param version "
                                                  "code")
                        .start_cons(SEQUENCE)
                        .decode_and_check(oid_t("1.2.840.10045.1.1"), "Only prime ECC fields supported")
                        .decode(p)
                        .end_cons()
                        .start_cons(SEQUENCE)
                        .decode_octet_string_bigint(a)
                        .decode_octet_string_bigint(b)
                        .decode_optional_string(seed, BIT_STRING, BIT_STRING)
                        .end_cons()
                        .decode(base_pt, OCTET_STRING)
                        .decode(order)
                        .decode(cofactor)
                        .end_cons()
                        .verify_end();

                    if (p.bits() < 64 || p < 0 || !is_bailie_psw_probable_prime(p)) {
                        throw decoding_error("Invalid ECC p parameter");
                    }

                    if (a < 0 || a >= p) {
                        throw decoding_error("Invalid ECC a parameter");
                    }

                    if (b <= 0 || b >= p) {
                        throw decoding_error("Invalid ECC b parameter");
                    }

                    if (order <= 0 || !is_bailie_psw_probable_prime(order)) {
                        throw decoding_error("Invalid ECC order parameter");
                    }

                    if (cofactor <= 0 || cofactor >= 16) {
                        throw decoding_error("Invalid ECC cofactor parameter");
                    }

                    std::pair<number_type, number_type> base_xy =
                        nil::crypto3::os2ecp(base_pt.data(), base_pt.size(), p, a, b);

                    return ec_group_data().lookup_or_create(p, a, b, base_xy.first, base_xy.second, order, cofactor,
                                                            oid_t());
                } else {
                    throw decoding_error("Unexpected tag while decoding ECC domain params");
                }
            }

            const ec_group_data &ec_group::data() const {
                if (m_data == nullptr) {
                    throw invalid_state("ec_group uninitialized");
                }
                return *m_data;
            }

            bool ec_group::a_is_minus_3() const {
                return data().a_is_minus_3();
            }

            bool ec_group::a_is_zero() const {
                return data().a_is_zero();
            }

            size_t ec_group::get_p_bits() const {
                return data().p_bits();
            }

            size_t ec_group::get_p_bytes() const {
                return (m_p_bits + 7) / 8;
            }

            size_t ec_group::get_order_bits() const {
                return data().order_bits();
            }

            size_t ec_group::get_order_bytes() const {
                return data().order_bytes();
            }

            const number_type &ec_group::p() const {
                return m_curve.p();
            }

            const number_type &ec_group::a() const {
                return m_curve.a();
            }

            const number_type &ec_group::b() const {
                return m_curve.b();
            }

            const point_gfp &ec_group::get_base_point() const {
                return m_base_point;
            }

            const number_type &ec_group::get_order() const {
                return m_order;
            }

            const number_type &ec_group::get_g_x() const {
                return data().g_x();
            }

            const number_type &ec_group::get_g_y() const {
                return data().g_y();
            }

            const number_type &ec_group::get_cofactor() const {
                return data().cofactor();
            }

            number_type ec_group::mod_order(const number_type &k) const {
                return data().mod_order(k);
            }

            number_type ec_group::square_mod_order(const number_type &x) const {
                return data().square_mod_order(x);
            }

            number_type ec_group::multiply_mod_order(const number_type &x, const number_type &y) const {
                return data().multiply_mod_order(x, y);
            }

            number_type ec_group::multiply_mod_order(const number_type &x, const number_type &y,
                                                     const number_type &z) const {
                return data().multiply_mod_order(x, y, z);
            }

            number_type ec_group::inverse_mod_order(const number_type &x) const {
                return data().inverse_mod_order(x);
            }

            const oid_t &ec_group::get_curve_oid() const {
                return data().oid();
            }

            point_gfp ec_group::point(const number_type &x, const number_type &y) const {
                // TODO: randomize the representation?
                return point_gfp(data().curve(), x, y);
            }

            point_gfp ec_group::blinded_base_point_multiply(const number_type &k,
                                                            random_number_generator &rng,
                                                            std::vector<number_type> &ws) const {
                return data().blinded_base_point_multiply(k, rng, ws);
            }

            number_type ec_group::blinded_base_point_multiply_x(const number_type &k,
                                                                random_number_generator &rng,
                                                                std::vector<number_type> &ws) const {
                const point_gfp pt = data().blinded_base_point_multiply(k, rng, ws);

                if (pt == 0) {
                    return 0;
                }
                return pt.get_affine_x();
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
