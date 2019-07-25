#include <nil/crypto3/pubkey/ec_group/ec_group.hpp>
#include <nil/crypto3/pubkey/ec_group/point_mul.hpp>

#include <nil/crypto3/multiprecision/prime.hpp>
#include <nil/crypto3/multiprecision/modular_reduce.hpp>

#include <nil/crypto3/asn1/ber_dec.hpp>
#include <nil/crypto3/asn1/der_enc.hpp>
#include <nil/crypto3/asn1/oids.hpp>

#include <nil/crypto3/pubkey/pem.hpp>

#include <nil/crypto3/random/random.hpp>

#include <vector>
#include <nil/crypto3/multiprecision/modular_inverse.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

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
                    return (this->p() == p && this->a() == a && this->b() == b && this->order() == order
                            && this->cofactor() == cofactor && this->g_x() == g_x && this->g_y() == g_y);
                }

                const oid_t &oid() const {
                    return m_oid;
                }

                const number_type &p() const {
                    return m_curve.get_p();
                }

                const number_type &a() const {
                    return m_curve.get_a();
                }

                const number_type &b() const {
                    return m_curve.get_b();
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
                    std::shared_ptr<ec_group_data> d
                        = std::make_shared<ec_group_data>(p, a, b, g_x, g_y, order, cofactor, oid);

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

                    std::pair<number_type, number_type> base_xy
                        = nil::crypto3::os2ecp(base_pt.data(), base_pt.size(), p, a, b);

                    return ec_group_data().lookup_or_create(p, a, b, base_xy.first, base_xy.second, order, cofactor,
                                                            oid_t());
                } else {
                    throw decoding_error("Unexpected tag while decoding ECC domain params");
                }
            }

            const ec_group_data &ec_group::data() const {
                if (m_data == nullptr) {
                    throw Invalid_State("ec_group uninitialized");
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

            const number_type &ec_group::get_p() const {
                return m_curve.get_p();
            }

            const number_type &ec_group::get_a() const {
                return m_curve.get_a();
            }

            const number_type &ec_group::get_b() const {
                return m_curve.get_b();
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

            point_gfp ec_group::zero_point() const {
                return point_gfp(data().curve());
            }
        }    // namespace pubkey
    }        // namespace crypto3
}