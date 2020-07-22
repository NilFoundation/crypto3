//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_POINT_GFP_HPP
#define CRYPTO3_PUBKEY_POINT_GFP_HPP

#include <boost/random.hpp>

#include <nil/algebra/curves/curve_gfp.hpp>

#include <vector>

namespace nil {
    namespace algebra {
        namespace curves {
            /*!
             * @brief This class represents one point on a curve of GF(p)
             * @tparam CurveType
             */
            template<typename Curve>
            struct point {
                typedef Curve curve_type;
                typedef typename curve_type::number_type number_type;

                point() = default;

                /**
                 * @brief Construct the zero point
                 * @param curve The base curve
                 *
                 * @note Assumes Montgomery rep of zero is zero
                 */
                explicit point(const curve_type &curve) :
                    m_curve(curve), m_coord_x(0), m_coord_y(get_1()), m_coord_z(0) {
                }

                /**
                 * Copy constructor
                 */
                point(const point<CurveType> &) = default;

                /**
                 * Move Constructor
                 */
                point(point<curve_type> &&other) {
                    this->swap(other);
                }

                /**
                 * Construct a point from its affine coordinates
                 * @param curve the base curve
                 * @param x affine x coordinate
                 * @param y affine y coordinate
                 */
                point(const curve_type &curve, const number_type &x, const number_type &y) :
                    m_curve(curve), m_coord_x(x), m_coord_y(y), m_coord_z(get_1()) {
                }

                number_type m_coord_x, m_coord_y, m_coord_z;

            protected:
                number_type get_1() {
                }

                void swap(point<curve_type> &other) {
                    m_curve.swap(other.m_curve);
                    m_coord_x.swap(other.m_coord_x);
                    m_coord_y.swap(other.m_coord_y);
                    m_coord_z.swap(other.m_coord_z);
                }

                curve_type m_curve;
            };
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif