#ifndef CRYPTO3_PUBKEY_POINT_GFP_HPP
#define CRYPTO3_PUBKEY_POINT_GFP_HPP

#include <boost/random.hpp>

#include <nil/crypto3/pubkey/ec_group/curve_gfp.hpp>

#include <nil/crypto3/utilities/exceptions.hpp>

#include <vector>

namespace nil {
    namespace crypto3 {

        /**
         * Exception thrown if you try to convert a zero point to an affine
         * coordinate
         */
        class illegal_transformation final : public std::exception {
        public:
            explicit illegal_transformation(const std::string &err = "Requested transformation is not possible") {
            }
        };

        /**
         * Exception thrown if some form of illegal point is decoded
         */
        class illegal_point final : public std::exception {
        public:
            explicit illegal_point(const std::string &err = "Malformed ECP point detected") {
            }
        };

        /*!
         * @brief This class represents one point on a curve of GF(p)
         * @tparam CurveType
         */
        template<typename CurveType>
        class point_gfp {
        public:
            typedef CurveType curve_type;
            typedef typename curve_type::number_type number_type;

            enum compression_type { UNCOMPRESSED = 0, COMPRESSED = 1, HYBRID = 2 };

            enum { WORKSPACE_SIZE = 8 };

            /**
             * Construct an uninitialized point_gfp
             */
            point_gfp() = default;

            /**
             * @brief Construct the zero point
             * @param curve The base curve
             *
             * @note Assumes Montgomery rep of zero is zero
             */
            explicit point_gfp(const curve_type &curve) :
                m_curve(curve), m_coord_x(0), m_coord_y(curve.get_1_rep()), m_coord_z(0) {
            }

            /**
             * Copy constructor
             */
            point_gfp(const point_gfp<CurveType> &) = default;

            /**
             * Move Constructor
             */
            point_gfp(point_gfp<CurveType> &&other) {
                this->swap(other);
            }

            /**
             * Standard Assignment
             */
            point_gfp<CurveType> &operator=(const point_gfp<CurveType> &) = default;

            /**
             * Move Assignment
             */
            point_gfp<CurveType> &operator=(point_gfp<CurveType> &&other) {
                if (this != &other) {
                    this->swap(other);
                }
                return (*this);
            }

            /**
             * Construct a point from its affine coordinates
             * @param curve the base curve
             * @param x affine x coordinate
             * @param y affine y coordinate
             */
            template<typename Backend, expression_template_option ExpressionTemplates>
            point_gfp(const curve_type &curve, const number<Backend, ExpressionTemplates> &x,
                      const number<Backend, ExpressionTemplates> &y) :
                m_curve(curve),
                m_coord_x(x), m_coord_y(y), m_coord_z(m_curve.get_1_rep()) {
                if (x <= 0 || x >= curve.get_p()) {
                    throw std::invalid_argument("Invalid point_gfp affine x");
                }
                if (y <= 0 || y >= curve.get_p()) {
                    throw std::invalid_argument("Invalid point_gfp affine y");
                }

                secure_vector<word> monty_ws(m_curve.get_ws_size());
                m_curve.to_rep(m_coord_x, monty_ws);
                m_curve.to_rep(m_coord_y, monty_ws);
            }

            /**
             * EC2OSP - elliptic curve to octet string primitive
             * @param format which format to encode using
             */
            std::vector<uint8_t> encode(point_gfp<CurveType>::compression_type format) const;

            /**
             * += Operator
             * @param rhs the point_gfp to add to the local value
             * @result resulting point_gfp
             */
            point_gfp<CurveType> &operator+=(const point_gfp<CurveType> &rhs) {
                std::vector<number_type> ws(point_gfp<CurveType>::WORKSPACE_SIZE);
                add(rhs, ws);
                return *this;
            }

            /**
             * -= Operator
             * @param rhs the point_gfp to subtract from the local value
             * @result resulting point_gfp
             */
            point_gfp<CurveType> &operator-=(const point_gfp<CurveType> &rhs) {
                point_gfp<CurveType> minus_rhs = point_gfp<CurveType>(rhs).negate();

                if (is_zero()) {
                    *this = minus_rhs;
                } else {
                    *this += minus_rhs;
                }

                return *this;
            }

            /**
             * *= Operator
             * @param scalar the point_gfp to multiply with *this
             * @result resulting point_gfp
             */
            template<typename Backend, expression_template_option ExpressionTemplates>
            point_gfp<CurveType> &operator*=(const number<Backend, ExpressionTemplates> &scalar) {
                *this = scalar * *this;
                return *this;
            }

            /**
             * Negate this point
             * @return *this
             */
            point_gfp<CurveType> &negate() {
                if (!is_zero()) {
                    m_coord_y = m_curve.get_p() - m_coord_y;
                }
                return *this;
            }

            /**
             * get affine x coordinate
             * @result affine x coordinate
             */
            number_type get_affine_x() const {
                if (is_zero()) {
                    throw illegal_transformation("Cannot convert zero point to affine");
                }

                secure_vector<word> monty_ws;

                if (is_affine()) {
                    return m_curve.from_rep(m_coord_x, monty_ws);
                }

                number_type z2 = m_curve.sqr_to_tmp(m_coord_z, monty_ws);
                z2 = m_curve.invert_element(z2, monty_ws);

                number_type r;
                m_curve.mul(r, m_coord_x, z2, monty_ws);
                m_curve.from_rep(r, monty_ws);
                return r;
            }

            /**
             * get affine y coordinate
             * @result affine y coordinate
             */
            number_type get_affine_y() const {
                if (is_zero()) {
                    throw illegal_transformation("Cannot convert zero point to affine");
                }

                secure_vector<word> monty_ws;

                if (is_affine()) {
                    return m_curve.from_rep(m_coord_y, monty_ws);
                }

                const number_type z2 = m_curve.sqr_to_tmp(m_coord_z, monty_ws);
                const number_type z3 = m_curve.mul_to_tmp(m_coord_z, z2, monty_ws);
                const number_type z3_inv = m_curve.invert_element(z3, monty_ws);

                number_type r;
                m_curve.mul(r, m_coord_y, z3_inv, monty_ws);
                m_curve.from_rep(r, monty_ws);
                return r;
            }

            const number_type &get_x() const {
                return m_coord_x;
            }

            const number_type &get_y() const {
                return m_coord_y;
            }

            const number_type &get_z() const {
                return m_coord_z;
            }

            template<typename Backend, expression_template_option ExpressionTemplates>
            void swap_coords(number<Backend, ExpressionTemplates> &new_x, number<Backend, ExpressionTemplates> &new_y,
                             number<Backend, ExpressionTemplates> &new_z) {
                m_coord_x.swap(new_x);
                m_coord_y.swap(new_y);
                m_coord_z.swap(new_z);
            }

            /**
             * Force this point to affine coordinates
             */
            void force_affine() {
                if (is_zero()) {
                    throw invalid_state("Cannot convert zero ECC point to affine");
                }

                secure_vector<word> ws;

                const number_type z_inv = m_curve.invert_element(m_coord_z, ws);
                const number_type z2_inv = m_curve.sqr_to_tmp(z_inv, ws);
                const number_type z3_inv = m_curve.mul_to_tmp(z_inv, z2_inv, ws);
                m_coord_x = m_curve.mul_to_tmp(m_coord_x, z2_inv, ws);
                m_coord_y = m_curve.mul_to_tmp(m_coord_y, z3_inv, ws);
                m_coord_z = m_curve.get_1_rep();
            }

            /**
             * Force all points on the list to affine coordinates
             *
             * @note For >= 2 points use Montgomery's trick
             *
             * See Algorithm 2.26 in "Guide to Elliptic Curve Cryptography"
             * (Hankerson, Menezes, Vanstone)
             *
             * TODO is it really necessary to save all k points in c?
             */
            template<typename Backend, expression_template_option ExpressionTemplates>
            static void force_all_affine(std::vector<point_gfp> &points, secure_vector<word> &ws) {
                if (points.size() <= 1) {
                    for (size_t i = 0; i != points.size(); ++i) {
                        points[i].force_affine();
                    }
                    return;
                }

                const curve_gfp<number<Backend, ExpressionTemplates>> &curve = points[0].m_curve;
                const number<Backend, ExpressionTemplates> &rep_1 = curve.get_1_rep();

                if (ws.size() < curve.get_ws_size()) {
                    ws.resize(curve.get_ws_size());
                }

                std::vector<number<Backend, ExpressionTemplates>> c(points.size());
                c[0] = points[0].m_coord_z;

                for (size_t i = 1; i != points.size(); ++i) {
                    curve.mul(c[i], c[i - 1], points[i].m_coord_z, ws);
                }

                number<Backend, ExpressionTemplates> s_inv = curve.invert_element(c[c.size() - 1], ws);

                number<Backend, ExpressionTemplates> z_inv, z2_inv, z3_inv;

                for (size_t i = points.size() - 1; i != 0; i--) {
                    point_gfp &point = points[i];

                    curve.mul(z_inv, s_inv, c[i - 1], ws);

                    s_inv = curve.mul_to_tmp(s_inv, point.m_coord_z, ws);

                    curve.sqr(z2_inv, z_inv, ws);
                    curve.mul(z3_inv, z2_inv, z_inv, ws);
                    point.m_coord_x = curve.mul_to_tmp(point.m_coord_x, z2_inv, ws);
                    point.m_coord_y = curve.mul_to_tmp(point.m_coord_y, z3_inv, ws);
                    point.m_coord_z = rep_1;
                }

                curve.sqr(z2_inv, s_inv, ws);
                curve.mul(z3_inv, z2_inv, s_inv, ws);
                points[0].m_coord_x = curve.mul_to_tmp(points[0].m_coord_x, z2_inv, ws);
                points[0].m_coord_y = curve.mul_to_tmp(points[0].m_coord_y, z3_inv, ws);
                points[0].m_coord_z = rep_1;
            }

            bool is_affine() const {
                return m_curve.is_one(m_coord_z);
            }

            /**
             * Is this the point at infinity?
             * @result true, if this point is at infinity, false otherwise.
             */
            bool is_zero() const {
                return (m_coord_x == 0 && m_coord_z == 0);
            }

            /**
             * Checks whether the point is to be found on the underlying
             * curve; used to prevent fault attacks.
             * @return if the point is on the curve
             */
            bool on_the_curve() const {
                /*
                Is the point still on the curve?? (If everything is correct, the
                point is always on its curve; then the function will return true.
                If somehow the state is corrupted, which suggests a fault attack
                (or internal computational error), then return false.
                */
                if (is_zero()) {
                    return true;
                }

                secure_vector<word> monty_ws;

                const number_type y2 = m_curve.from_rep(m_curve.sqr_to_tmp(m_coord_y, monty_ws), monty_ws);
                const number_type x3 = m_curve.mul_to_tmp(m_coord_x, m_curve.sqr_to_tmp(m_coord_x, monty_ws), monty_ws);
                const number_type ax = m_curve.mul_to_tmp(m_coord_x, m_curve.get_a_rep(), monty_ws);
                const number_type z2 = m_curve.sqr_to_tmp(m_coord_z, monty_ws);

                if (m_coord_z == z2)    // Is z equal to 1 (in Montgomery form)?
                {
                    if (y2 != m_curve.from_rep(x3 + ax + m_curve.get_b_rep(), monty_ws)) {
                        return false;
                    }
                }

                const number_type z3 = m_curve.mul_to_tmp(m_coord_z, z2, monty_ws);
                const number_type ax_z4 = m_curve.mul_to_tmp(ax, m_curve.sqr_to_tmp(z2, monty_ws), monty_ws);
                const number_type b_z6
                    = m_curve.mul_to_tmp(m_curve.get_b_rep(), m_curve.sqr_to_tmp(z3, monty_ws), monty_ws);

                return !(y2 != m_curve.from_rep(x3 + ax_z4 + b_z6, monty_ws)) && true;
            }

            /**
             * swaps the states of *this and other, does not throw!
             * @param other the object to swap values with
             */
            void swap(point_gfp<CurveType> &other) {
                m_curve.swap(other.m_curve);
                m_coord_x.swap(other.m_coord_x);
                m_coord_y.swap(other.m_coord_y);
                m_coord_z.swap(other.m_coord_z);
            }

            /**
             * Randomize the point representation
             * The actual value (get_affine_x, get_affine_y) does not change
             */
            template<typename UniformRandomGenerator>
            void randomize_repr(UniformRandomGenerator &rng) {
                secure_vector<word> ws(m_curve.get_ws_size());
                randomize_repr(rng, ws);
            }

            /**
             * Randomize the point representation
             * The actual value (get_affine_x, get_affine_y) does not change
             */
            template<typename UniformRandomGenerator>
            void randomize_repr(UniformRandomGenerator &rng, secure_vector<word> &ws) {
                const number_type mask = random_integer(rng, 2, m_curve.get_p());

                /*
                 * No reason to convert this to Montgomery representation first,
                 * just pretend the random mask was chosen as Redc(mask) and the
                 * random mask we generated above is in the Montgomery
                 * representation.
                 * //m_curve.to_rep(mask, ws);
                 */
                const number_type mask2 = m_curve.sqr_to_tmp(mask, ws);
                const number_type mask3 = m_curve.mul_to_tmp(mask2, mask, ws);

                m_coord_x = m_curve.mul_to_tmp(m_coord_x, mask2, ws);
                m_coord_y = m_curve.mul_to_tmp(m_coord_y, mask3, ws);
                m_coord_z = m_curve.mul_to_tmp(m_coord_z, mask, ws);
            }

            /**
             * Equality operator
             */
            bool operator==(const point_gfp<CurveType> &other) const {
                if (m_curve != other.m_curve) {
                    return false;
                }

                // If this is zero, only equal if other is also zero
                if (is_zero()) {
                    return other.is_zero();
                }

                return (get_affine_x() == other.get_affine_x() && get_affine_y() == other.get_affine_y());
            }

            /**
             * Point addition
             * @param other the point to add to *this
             * @param workspace temp space, at least WORKSPACE_SIZE elements
             */
            template<typename Backend, expression_template_option ExpressionTemplates>
            void add(const point_gfp &other, std::vector<number<Backend, ExpressionTemplates>> &workspace) {
                BOOST_ASSERT(m_curve == other.m_curve);

                const size_t p_words = m_curve.get_p_words();

                add(other.m_coord_x.data(), std::min(p_words, other.m_coord_x.size()), other.m_coord_y.data(),
                    std::min(p_words, other.m_coord_y.size()), other.m_coord_z.data(),
                    std::min(p_words, other.m_coord_z.size()), workspace);
            }

            /**
             * Point addition. Array version.
             *
             * @param x_words the words of the x coordinate of the other point
             * @param x_size size of x_words
             * @param y_words the words of the y coordinate of the other point
             * @param y_size size of y_words
             * @param z_words the words of the z coordinate of the other point
             * @param z_size size of z_words
             * @param workspace temp space, at least WORKSPACE_SIZE elements
             */
            void add(const word x_words[], size_t x_size, const word y_words[], size_t y_size, const word z_words[],
                     size_t z_size, std::vector<cpp_int> &workspace) {
                if (all_zeros(x_words, x_size) && all_zeros(z_words, z_size)) {
                    return;
                }

                if (is_zero()) {
                    m_coord_x.set_words(x_words, x_size);
                    m_coord_y.set_words(y_words, y_size);
                    m_coord_z.set_words(z_words, z_size);
                    return;
                }

                resize_ws(ws_bn, m_curve.get_ws_size());

                secure_vector<word> &ws = ws_bn[0].get_word_vector();
                secure_vector<word> &sub_ws = ws_bn[1].get_word_vector();

                number<Backend, ExpressionTemplates> &T0 = ws_bn[2];
                number<Backend, ExpressionTemplates> &T1 = ws_bn[3];
                number<Backend, ExpressionTemplates> &T2 = ws_bn[4];
                number<Backend, ExpressionTemplates> &T3 = ws_bn[5];
                number<Backend, ExpressionTemplates> &T4 = ws_bn[6];
                number<Backend, ExpressionTemplates> &T5 = ws_bn[7];

                /*
                https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
                */

                const number<Backend, ExpressionTemplates> &p = m_curve.get_p();

                m_curve.sqr(T0, z_words, z_size, ws);        // z2^2
                m_curve.mul(T1, m_coord_x, T0, ws);          // x1*z2^2
                m_curve.mul(T3, z_words, z_size, T0, ws);    // z2^3
                m_curve.mul(T2, m_coord_y, T3, ws);          // y1*z2^3

                m_curve.sqr(T3, m_coord_z, ws);              // z1^2
                m_curve.mul(T4, x_words, x_size, T3, ws);    // x2*z1^2

                m_curve.mul(T5, m_coord_z, T3, ws);          // z1^3
                m_curve.mul(T0, y_words, y_size, T5, ws);    // y2*z1^3

                T4.mod_sub(T1, p, sub_ws);    // x2*z1^2 - x1*z2^2

                T0.mod_sub(T2, p, sub_ws);

                if (T4 == 0) {
                    if (T0 == 0) {
                        mult2(ws_bn);
                        return;
                    }

                    // setting to zero:
                    m_coord_x = 0;
                    m_coord_y = m_curve.get_1_rep();
                    m_coord_z = 0;
                    return;
                }

                m_curve.sqr(T5, T4, ws);

                m_curve.mul(T3, T1, T5, ws);

                m_curve.mul(T1, T5, T4, ws);

                m_curve.sqr(m_coord_x, T0, ws);
                m_coord_x.mod_sub(T1, p, sub_ws);
                m_coord_x.mod_sub(T3, p, sub_ws);
                m_coord_x.mod_sub(T3, p, sub_ws);

                T3.mod_sub(m_coord_x, p, sub_ws);

                m_curve.mul(m_coord_y, T0, T3, ws);
                m_curve.mul(T3, T2, T1, ws);

                m_coord_y.mod_sub(T3, p, sub_ws);

                m_curve.mul(T3, z_words, z_size, m_coord_z, ws);
                m_curve.mul(m_coord_z, T3, T4, ws);
            }

            /**
             * Point addition - mixed J+A
             * @param other affine point to add - assumed to be affine!
             * @param workspace temp space, at least WORKSPACE_SIZE elements
             */
            void add_affine(const point_gfp &other, std::vector<number<Backend, ExpressionTemplates>> &workspace) {
                BOOST_ASSERT(m_curve == other.m_curve);
                CRYPTO3_DEBUG_ASSERT(other.is_affine());

                const size_t p_words = m_curve.get_p_words();
                add_affine(other.m_coord_x.data(), std::min(p_words, other.m_coord_x.size()), other.m_coord_y.data(),
                           std::min(p_words, other.m_coord_y.size()), workspace);
            }

            /**
             * Point addition - mixed J+A. Array version.
             *
             * @param x_words the words of the x coordinate of the other point
             * @param x_size size of x_words
             * @param y_words the words of the y coordinate of the other point
             * @param y_size size of y_words
             * @param workspace temp space, at least WORKSPACE_SIZE elements
             */
            void add_affine(const word x_words[], size_t x_size, const word y_words[], size_t y_size,
                            std::vector<number<Backend, ExpressionTemplates>> &workspace) {
                if (all_zeros(x_words, x_size) && all_zeros(y_words, y_size)) {
                    return;
                }

                if (is_zero()) {
                    m_coord_x.set_words(x_words, x_size);
                    m_coord_y.set_words(y_words, y_size);
                    m_coord_z = m_curve.get_1_rep();
                    return;
                }

                resize_ws(ws_bn, m_curve.get_ws_size());

                secure_vector<word> &ws = ws_bn[0].get_word_vector();
                secure_vector<word> &sub_ws = ws_bn[1].get_word_vector();

                number<Backend, ExpressionTemplates> &T0 = ws_bn[2];
                number<Backend, ExpressionTemplates> &T1 = ws_bn[3];
                number<Backend, ExpressionTemplates> &T2 = ws_bn[4];
                number<Backend, ExpressionTemplates> &T3 = ws_bn[5];
                number<Backend, ExpressionTemplates> &T4 = ws_bn[6];

                /*
                    https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
                    simplified with Z2 = 1
                */

                const number<Backend, ExpressionTemplates> &p = m_curve.get_p();

                m_curve.sqr(T3, m_coord_z, ws);              // z1^2
                m_curve.mul(T4, x_words, x_size, T3, ws);    // x2*z1^2

                m_curve.mul(T2, m_coord_z, T3, ws);          // z1^3
                m_curve.mul(T0, y_words, y_size, T2, ws);    // y2*z1^3

                T4.mod_sub(m_coord_x, p, sub_ws);    // x2*z1^2 - x1*z2^2

                T0.mod_sub(m_coord_y, p, sub_ws);

                if (T4 == 0) {
                    if (T0 == 0) {
                        mult2(ws_bn);
                        return;
                    }

                    // setting to zero:
                    m_coord_x = 0;
                    m_coord_y = m_curve.get_1_rep();
                    m_coord_z = 0;
                    return;
                }

                m_curve.sqr(T2, T4, ws);

                m_curve.mul(T3, m_coord_x, T2, ws);

                m_curve.mul(T1, T2, T4, ws);

                m_curve.sqr(m_coord_x, T0, ws);
                m_coord_x.mod_sub(T1, p, sub_ws);
                m_coord_x.mod_sub(T3, p, sub_ws);
                m_coord_x.mod_sub(T3, p, sub_ws);

                T3.mod_sub(m_coord_x, p, sub_ws);

                T2 = m_coord_y;
                m_curve.mul(T2, T0, T3, ws);
                m_curve.mul(T3, m_coord_y, T1, ws);
                T2.mod_sub(T3, p, sub_ws);
                m_coord_y = T2;

                m_curve.mul(T3, m_coord_z, T4, ws);
                m_coord_z = T3;
            }

            /**
             * Point doubling
             * @param workspace temp space, at least WORKSPACE_SIZE elements
             */
            void mult2(std::vector<cpp_int> &ws_bn) {
                if (is_zero()) {
                    return;
                }

                if (m_coord_y == 0) {
                    *this = point_gfp(m_curve);    // setting myself to zero
                    return;
                }

                resize_ws(ws_bn, m_curve.get_ws_size());

                secure_vector<word> &ws = ws_bn[0].get_word_vector();
                secure_vector<word> &sub_ws = ws_bn[1].get_word_vector();

                number<Backend, ExpressionTemplates> &T0 = ws_bn[2];
                number<Backend, ExpressionTemplates> &T1 = ws_bn[3];
                number<Backend, ExpressionTemplates> &T2 = ws_bn[4];
                number<Backend, ExpressionTemplates> &T3 = ws_bn[5];
                number<Backend, ExpressionTemplates> &T4 = ws_bn[6];

                /*
                https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-1986-cc
                */
                const cpp_int &p = m_curve.get_p();

                m_curve.sqr(T0, m_coord_y, ws);

                m_curve.mul(T1, m_coord_x, T0, ws);
                T1 <<= 2;    // * 4
                m_curve.redc_mod_p(T1, sub_ws);

                if (m_curve.a_is_zero()) {
                    // if a == 0 then 3*x^2 + a*z^4 is just 3*x^2
                    m_curve.sqr(T4, m_coord_x, ws);    // x^2
                    T4 *= 3;                           // 3*x^2
                    m_curve.redc_mod_p(T4, sub_ws);
                } else if (m_curve.a_is_minus_3()) {
                    /*
                    if a == -3 then
                      3*x^2 + a*z^4 == 3*x^2 - 3*z^4 == 3*(x^2-z^4) == 3*(x-z^2)*(x+z^2)
                    */
                    m_curve.sqr(T3, m_coord_z, ws);    // z^2

                    // (x-z^2)
                    T2 = m_coord_x;
                    T2.mod_sub(T3, p, sub_ws);

                    // (x+z^2)
                    T3.mod_add(m_coord_x, p, sub_ws);

                    m_curve.mul(T4, T2, T3, ws);    // (x-z^2)*(x+z^2)

                    T4 *= 3;    // 3*(x-z^2)*(x+z^2)
                    m_curve.redc_mod_p(T4, sub_ws);
                } else {
                    m_curve.sqr(T3, m_coord_z, ws);                  // z^2
                    m_curve.sqr(T4, T3, ws);                         // z^4
                    m_curve.mul(T3, m_curve.get_a_rep(), T4, ws);    // a*z^4

                    m_curve.sqr(T4, m_coord_x, ws);    // x^2
                    T4 *= 3;                           // 3*x^2
                    T4.mod_add(T3, p, sub_ws);         // 3*x^2 + a*z^4
                }

                m_curve.sqr(T2, T4, ws);
                T2.mod_sub(T1, p, sub_ws);
                T2.mod_sub(T1, p, sub_ws);

                m_curve.sqr(T3, T0, ws);
                T3 <<= 3;
                m_curve.redc_mod_p(T3, sub_ws);

                T1.mod_sub(T2, p, sub_ws);

                m_curve.mul(T0, T4, T1, ws);
                T0.mod_sub(T3, p, sub_ws);

                m_coord_x = T2;

                m_curve.mul(T2, m_coord_y, m_coord_z, ws);
                T2 <<= 1;
                m_curve.redc_mod_p(T2, sub_ws);

                m_coord_y = T0;
                m_coord_z = T2;
            }

            /**
             * Repeated point doubling
             * @param i number of doublings to perform
             * @param workspace temp space, at least WORKSPACE_SIZE elements
             */
            void mult2i(size_t iterations, std::vector<cpp_int> &ws_bn) {
                if (iterations == 0) {
                    return;
                }

                if (m_coord_y == 0) {
                    *this = point_gfp(m_curve);    // setting myself to zero
                    return;
                }

                /*
                TODO we can save 2 squarings per iteration by computing
                a*Z^4 using values cached from previous iteration
                */
                for (size_t i = 0; i != iterations; ++i) {
                    mult2(ws_bn);
                }
            }

            /**
             * Point addition
             * @param other the point to add to *this
             * @param workspace temp space, at least WORKSPACE_SIZE elements
             * @return other plus *this
             */
            point_gfp plus(const point_gfp &other, std::vector<cpp_int> &workspace) const {
                point_gfp x = (*this);
                x.add(other, workspace);
                return x;
            }

            /**
             * Point doubling
             * @param workspace temp space, at least WORKSPACE_SIZE elements
             * @return *this doubled
             */
            point_gfp double_of(std::vector<cpp_int> &workspace) const {
                point_gfp x = (*this);
                x.mult2(workspace);
                return x;
            }

            /**
             * Return the zero (aka infinite) point associated with this curve
             */
            point_gfp zero() const {
                return point_gfp(m_curve);
            }

            /**
             * Return base curve of this point
             * @result the curve over GF(p) of this point
             *
             * You should not need to use this
             */
            const curve_gfp<Backend, ExpressionTemplates> &get_curve() const {
                return m_curve;
            }

        protected:
            inline bool all_zeros(const word x[], size_t len) {
                word z = 0;
                for (size_t i = 0; i != len; ++i) {
                    z |= x[i];
                }
                return (z == 0);
            }

            inline void resize_ws(std::vector<number<Backend, ExpressionTemplates>> &ws_bn, size_t cap_size) {
                BOOST_ASSERT_MSG(ws_bn.size() >= point_gfp::WORKSPACE_SIZE, "Expected size for point_gfp workspace");

                for (size_t i = 0; i != ws_bn.size(); ++i) {
                    if (ws_bn[i].size() < cap_size) {
                        ws_bn[i].get_word_vector().resize(cap_size);
                    }
                }
            }

            curve_type m_curve;
            number_type m_coord_x, m_coord_y, m_coord_z;
        };

        /**
         * Point multiplication operator
         * @param scalar the scalar value
         * @param point the point value
         * @return scalar*point on the curve
         */
        template<typename CurveType>
        point_gfp<CurveType> operator*(const number<Backend, ExpressionTemplates> &scalar,
                                       const point_gfp<CurveType> &point) {
            CRYPTO3_DEBUG_ASSERT(point.on_the_curve());

            const size_t scalar_bits = msb(scalar);

            std::vector<number<Backend, ExpressionTemplates>> ws(point_gfp<CurveType>::WORKSPACE_SIZE);

            point_gfp<CurveType> R[2] = {point.zero(), point};

            for (size_t i = scalar_bits; i > 0; i--) {
                const std::size_t b = bit_test(scalar, i - 1);
                R[b ^ 1].add(R[b], ws);
                R[b].mult2(ws);
            }

            if (scalar < 0) {
                R[0].negate();
            }

            CRYPTO3_DEBUG_ASSERT(R[0].on_the_curve());

            return R[0];
        }

        // relational operators
        inline bool operator!=(const point_gfp &lhs, const point_gfp &rhs) {
            return !(rhs == lhs);
        }

        // arithmetic operators
        inline point_gfp operator-(const point_gfp &lhs) {
            return point_gfp(lhs).negate();
        }

        inline point_gfp operator+(const point_gfp &lhs, const point_gfp &rhs) {
            point_gfp tmp(lhs);
            return tmp += rhs;
        }

        inline point_gfp operator-(const point_gfp &lhs, const point_gfp &rhs) {
            point_gfp tmp(lhs);
            return tmp -= rhs;
        }

        inline point_gfp operator*(const point_gfp &point, const cpp_int &scalar) {
            return scalar * point;
        }

        /**
         * Perform point decoding
         * Use ec_group::os2ecp instead
         */
        point_gfp os2ecp(const uint8_t data[], size_t data_len, const curve_gfp &curve);

        /**
         * Perform point decoding
         * Use ec_group::os2ecp instead
         *
         * @param data the encoded point
         * @param data_len length of data in bytes
         * @param curve_p the curve equation prime
         * @param curve_a the curve equation a parameter
         * @param curve_b the curve equation b parameter
         */
        std::pair<cpp_int, cpp_int> os2ecp(const uint8_t data[], size_t data_len, const cpp_int &curve_p,
                                           const cpp_int &curve_a, const cpp_int &curve_b);

        template<typename Alloc>
        point_gfp os2ecp(const std::vector<uint8_t, Alloc> &data, const curve_gfp &curve) {
            return os2ecp(data.data(), data.size(), curve);
        }

    }    // namespace crypto3
}    // namespace nil

namespace std {

    template<>
    inline void swap<nil::crypto3::point_gfp>(nil::crypto3::point_gfp &x, nil::crypto3::point_gfp &y) {
        x.swap(y);
    }

}    // namespace std

#endif