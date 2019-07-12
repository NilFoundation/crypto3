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

        class ec_group_data final {
        public:

            ec_group_data(const cpp_int &p, const cpp_int &a,
                          const cpp_int &b, const cpp_int &g_x,
                          const cpp_int &g_y, const cpp_int &order,
                          const cpp_int &cofactor, const oid_t &oid) : m_curve(p, a, b),
                    m_base_point(m_curve, g_x, g_y), m_g_x(g_x), m_g_y(g_y), m_order(order), m_cofactor(cofactor),
                    m_mod_order(order), m_base_mult(m_base_point, m_mod_order), m_oid(oid),
                    m_p_bits(msb(p)), m_order_bits(msb(order)),
                    m_a_is_minus_3(a == p - 3), m_a_is_zero(a == 0) {
            }

            bool match(const cpp_int &p, const cpp_int &a,
                       const cpp_int &b, const cpp_int &g_x,
                       const cpp_int &g_y, const cpp_int &order,
                       const cpp_int &cofactor) const {
                return (this->p() == p && this->a() == a && this->b() == b && this->order() == order &&
                        this->cofactor() == cofactor && this->g_x() == g_x && this->g_y() == g_y);
            }

            const oid_t &oid() const {
                return m_oid;
            }

            const cpp_int &p() const {
                return m_curve.get_p();
            }

            const cpp_int &a() const {
                return m_curve.get_a();
            }

            const cpp_int &b() const {
                return m_curve.get_b();
            }

            const cpp_int &order() const {
                return m_order;
            }

            const cpp_int &cofactor() const {
                return m_cofactor;
            }

            const cpp_int &g_x() const {
                return m_g_x;
            }

            const cpp_int &g_y() const {
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

            cpp_int mod_order(const cpp_int &x) const {
                return m_mod_order.reduce(x);
            }

            cpp_int square_mod_order(const cpp_int &x) const {
                return m_mod_order.square(x);
            }

            cpp_int multiply_mod_order(const cpp_int &x,
                                                              const cpp_int &y) const {
                return m_mod_order.multiply(x, y);
            }

            cpp_int multiply_mod_order(const cpp_int &x,
                                                              const cpp_int &y,
                                                              const cpp_int &z) const {
                return m_mod_order.multiply(m_mod_order.multiply(x, y), z);
            }

            cpp_int inverse_mod_order(const cpp_int &x) const {
                return inverse_mod(x, m_order);
            }

            point_gfp blinded_base_point_multiply(const cpp_int &k, random_number_generator &rng,
                                                  std::vector<cpp_int> &ws) const {
                return m_base_mult.mul(k, rng, m_order, ws);
            }

        private:
            curve_gfp m_curve;
            point_gfp m_base_point;

            cpp_int m_g_x;
            cpp_int m_g_y;
            cpp_int m_order;
            cpp_int m_cofactor;
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

            std::shared_ptr<ec_group_data> lookup_or_create(const cpp_int &p,
                                                            const cpp_int &a,
                                                            const cpp_int &b,
                                                            const cpp_int &g_x,
                                                            const cpp_int &g_y,
                                                            const cpp_int &order,
                                                            const cpp_int &cofactor,
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

            std::shared_ptr<ec_group_data> add_curve(const cpp_int &p,
                                                     const cpp_int &a,
                                                     const cpp_int &b,
                                                     const cpp_int &g_x,
                                                     const cpp_int &g_y,
                                                     const cpp_int &order,
                                                     const cpp_int &cofactor, const oid_t &oid) {
                std::shared_ptr<ec_group_data> d = std::make_shared<ec_group_data>(p, a, b, g_x, g_y, order, cofactor,
                                                                                   oid);

                // This function is always called with the lock held
                m_registered_curves.push_back(d);
                return d;
            }

            mutex_type m_mutex;
            std::vector<std::shared_ptr<ec_group_data>> m_registered_curves;
        };

//static
        ec_group_data_map &ec_group::ec_group_data() {
            /*
            * This exists purely to ensure the allocator is constructed before g_ec_data,
            * which ensures that its destructor runs after ~g_ec_data is complete.
            */

            static allocator_initializer g_init_allocator;
            static ec_group_data_map g_ec_data;
            return g_ec_data;
        }

//static
        size_t ec_group::clear_registered_curve_data() {
            return ec_group_data().clear();
        }

//static
        std::shared_ptr<ec_group_data> ec_group::load_ec_group_info(const char *p_str, const char *a_str,
                                                                    const char *b_str, const char *g_x_str,
                                                                    const char *g_y_str, const char *order_str,
                                                                    const oid_t &oid) {
            const cpp_int p(p_str);
            const cpp_int a(a_str);
            const cpp_int b(b_str);
            const cpp_int g_x(g_x_str);
            const cpp_int g_y(g_y_str);
            const cpp_int order(order_str);
            const cpp_int cofactor(1); // implicit

            return std::make_shared<ec_group_data>(p, a, b, g_x, g_y, order, cofactor, oid);
        }

//static
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
                cpp_int p, a, b, order, cofactor;
                std::vector<uint8_t> base_pt;
                std::vector<uint8_t> seed;

                ber_decoder(bits, len).start_cons(SEQUENCE).decode_and_check<size_t>(1, "Unknown ECC param version "
                                                                                        "code").start_cons(
                        SEQUENCE).decode_and_check(oid_t("1.2.840.10045.1.1"),
                                                   "Only prime ECC fields supported").decode(p).end_cons().start_cons(
                        SEQUENCE).decode_octet_string_bigint(a).decode_octet_string_bigint(b).decode_optional_string(
                        seed, BIT_STRING, BIT_STRING).end_cons().decode(base_pt, OCTET_STRING).decode(order).decode(
                        cofactor).end_cons().verify_end();

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

                std::pair<cpp_int,
                        cpp_int> base_xy = nil::crypto3::os2ecp(base_pt.data(), base_pt.size(),
                                                                                       p, a, b);

                return ec_group_data().lookup_or_create(p, a, b, base_xy.first, base_xy.second, order, cofactor,
                                                        oid_t());
            } else {
                throw decoding_error("Unexpected tag while decoding ECC domain params");
            }
        }

        ec_group::ec_group() {
        }

        ec_group::~ec_group() {
            // shared_ptr possibly freed here
        }

        ec_group::ec_group(const oid_t &domain_oid) {
            this->m_data = ec_group_data().lookup(domain_oid);
            if (!this->m_data) {
                throw std::invalid_argument("Unknown ec_group " + domain_oid.as_string());
            }
        }

        ec_group::ec_group(const std::string &str) {
            if (str.empty()) {
                return;
            } // no initialization / uninitialized

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

        ec_group::ec_group(const std::vector<uint8_t> &ber) {
            m_data = ber_decode_ec_group(ber.data(), ber.size());
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
            return data().p_bytes();
        }

        size_t ec_group::get_order_bits() const {
            return data().order_bits();
        }

        size_t ec_group::get_order_bytes() const {
            return data().order_bytes();
        }

        const cpp_int &ec_group::get_p() const {
            return data().p();
        }

        const cpp_int &ec_group::get_a() const {
            return data().a();
        }

        const cpp_int &ec_group::get_b() const {
            return data().b();
        }

        const point_gfp &ec_group::get_base_point() const {
            return data().base_point();
        }

        const cpp_int &ec_group::get_order() const {
            return data().order();
        }

        const cpp_int &ec_group::get_g_x() const {
            return data().g_x();
        }

        const cpp_int &ec_group::get_g_y() const {
            return data().g_y();
        }

        const cpp_int &ec_group::get_cofactor() const {
            return data().cofactor();
        }

        cpp_int ec_group::mod_order(const cpp_int &k) const {
            return data().mod_order(k);
        }

        cpp_int ec_group::square_mod_order(const cpp_int &x) const {
            return data().square_mod_order(x);
        }

        cpp_int ec_group::multiply_mod_order(const cpp_int &x,
                                                                    const cpp_int &y) const {
            return data().multiply_mod_order(x, y);
        }

        cpp_int ec_group::multiply_mod_order(const cpp_int &x,
                                                                    const cpp_int &y,
                                                                    const cpp_int &z) const {
            return data().multiply_mod_order(x, y, z);
        }

        cpp_int ec_group::inverse_mod_order(const cpp_int &x) const {
            return data().inverse_mod_order(x);
        }

        const oid_t &ec_group::get_curve_oid() const {
            return data().oid();
        }

        size_t ec_group::point_size(point_gfp::compression_type format) const {
            // Hybrid and standard format are (x,y), compressed is y, +1 format byte
            if (format == point_gfp::COMPRESSED) {
                return (1 + get_p_bytes());
            } else {
                return (1 + 2 * get_p_bytes());
            }
        }

        point_gfp ec_group::os2ecp(const uint8_t bits[], size_t len) const {
            return nil::crypto3::os2ecp(bits, len, data().curve());
        }

        point_gfp ec_group::point(const cpp_int &x,
                                  const cpp_int &y) const {
            // TODO: randomize the representation?
            return point_gfp(data().curve(), x, y);
        }

        point_gfp ec_group::point_multiply(const cpp_int &x, const point_gfp &pt,
                                           const cpp_int &y) const {
            point_gfp_multi_point_precompute xy_mul(get_base_point(), pt);
            return xy_mul.multi_exp(x, y);
        }

        point_gfp ec_group::blinded_base_point_multiply(const cpp_int &k,
                                                        random_number_generator &rng,
                                                        std::vector<cpp_int> &ws) const {
            return data().blinded_base_point_multiply(k, rng, ws);
        }

        cpp_int ec_group::blinded_base_point_multiply_x(const cpp_int &k,
                                                                               random_number_generator &rng, std::vector<
                cpp_int> &ws) const {
            const point_gfp pt = data().blinded_base_point_multiply(k, rng, ws);

            if (pt == 0) {
                return 0;
            }
            return pt.get_affine_x();
        }

        cpp_int ec_group::random_scalar(random_number_generator &rng) const {
            return cpp_int::random_integer(rng, 1, get_order());
        }

        point_gfp ec_group::blinded_var_point_multiply(const point_gfp &point, const cpp_int &k,
                                                       random_number_generator &rng,
                                                       std::vector<cpp_int> &ws) const {
            point_gfp_var_point_precompute mul(point, rng, ws);
            return mul.mul(k, rng, get_order(), ws);
        }

        point_gfp ec_group::zero_point() const {
            return point_gfp(data().curve());
        }

        std::vector<uint8_t> ec_group::der_encode(ec_group_encoding form) const {
            std::vector<uint8_t> output;

            der_encoder der(output);

            if (form == EC_DOMPAR_ENC_EXPLICIT) {
                const size_t ecpVers1 = 1;
                const oid_t curve_type("1.2.840.10045.1.1"); // prime field

                const size_t p_bytes = get_p_bytes();

                der.start_cons(SEQUENCE).encode(ecpVers1).start_cons(SEQUENCE).encode(curve_type).encode(
                        get_p()).end_cons().start_cons(SEQUENCE).encode(
                        cpp_int::encode_1363(get_a(), p_bytes), OCTET_STRING).encode(
                        cpp_int::encode_1363(get_b(), p_bytes), OCTET_STRING).end_cons().encode(
                        get_base_point().encode(point_gfp::UNCOMPRESSED), OCTET_STRING).encode(get_order()).encode(
                        get_cofactor()).end_cons();
            } else if (form == EC_DOMPAR_ENC_oid_t) {
                const oid_t oid = get_curve_oid();
                if (oid.empty()) {
                    throw Encoding_Error("Cannot encode ec_group as oid_t because oid_t not set");
                }
                der.encode(oid);
            } else if (form == EC_DOMPAR_ENC_IMPLICITCA) {
                der.encode_null();
            } else {
                throw Internal_Error("ec_group::der_encode: Unknown encoding");
            }

            return output;
        }

        std::string ec_group::pem_encode() const {
            const std::vector<uint8_t> der = der_encode(EC_DOMPAR_ENC_EXPLICIT);
            return pem_code::encode(der, "EC PARAMETERS");
        }

        bool ec_group::operator==(const ec_group &other) const {
            if (m_data == other.m_data) {
                return true;
            } // same shared rep

            /*
            * No point comparing order/cofactor as they are uniquely determined
            * by the curve equation (p,a,b) and the base point.
            */
            return (get_p() == other.get_p() && get_a() == other.get_a() && get_b() == other.get_b() &&
                    get_g_x() == other.get_g_x() && get_g_y() == other.get_g_y());
        }

        bool ec_group::verify_public_element(const point_gfp &point) const {
            //check that public point is not at infinity
            if (point == 0) {
                return false;
            }

            //check that public point is on the curve
            if (!point.on_the_curve()) {
                return false;
            }

            //check that public point has order q
            if (!(point * get_order()) == 0) {
                return false;
            }

            if (get_cofactor() > 1) {
                if ((point * get_cofactor()) == 0) {
                    return false;
                }
            }

            return true;
        }

        bool ec_group::verify_group(random_number_generator &rng, bool) const {
            const cpp_int &p = get_p();
            const cpp_int &a = get_a();
            const cpp_int &b = get_b();
            const cpp_int &order = get_order();
            const point_gfp &base_point = get_base_point();

            if (a < 0 || a >= p) {
                return false;
            }
            if (b <= 0 || b >= p) {
                return false;
            }
            if (order <= 0) {
                return false;
            }

            //check if field modulus is prime
            if (!miller_rabin_test(p, 128, rng)) {
                return false;
            }

            //check if order is prime
            if (!miller_rabin_test(order, 128, rng)) {
                return false;
            }

            //compute the discriminant: 4*a^3 + 27*b^2 which must be nonzero
            const modular_reducer mod_p(p);

            const cpp_int discriminant = mod_p.reduce(
                    mod_p.multiply(4, mod_p.cube(a)) + mod_p.multiply(27, mod_p.square(b)));

            if (discriminant == 0) {
                return false;
            }

            //check for valid cofactor
            if (get_cofactor() < 1) {
                return false;
            }

            //check if the base point is on the curve
            if (!base_point.on_the_curve()) {
                return false;
            }
            if ((base_point * get_cofactor()) == 0) {
                return false;
            }
            //check if order of the base point is correct
            return (base_point * order) == 0;
        }
    }
}