///////////////////////////////////////////////////////////////////////////////
//  Copyright 2015 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <boost/type_traits/is_nothrow_move_constructible.hpp>
#include <boost/type_traits/is_nothrow_move_assignable.hpp>
#include <boost/type_traits/has_nothrow_constructor.hpp>
#include <boost/type_traits/has_nothrow_assign.hpp>
#include <boost/type_traits/has_nothrow_copy.hpp>
#include <boost/static_assert.hpp>

#ifndef BOOST_NO_CXX11_NOEXCEPT

#if !defined(BOOST_NO_CXX11_NOEXCEPT) && !defined(BOOST_NO_SFINAE_EXPR) || defined(BOOST_IS_NOTHROW_MOVE_CONSTRUCT)
//
// Move construct:
//
BOOST_STATIC_ASSERT(boost::is_nothrow_move_constructible<nil::crypto3::multiprecision::cpp_int>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_constructible<nil::crypto3::multiprecision::int128_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_constructible<nil::crypto3::multiprecision::checked_int128_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_constructible<nil::crypto3::multiprecision::uint128_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_constructible<nil::crypto3::multiprecision::checked_uint128_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_constructible<nil::crypto3::multiprecision::int512_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_constructible<nil::crypto3::multiprecision::checked_int512_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_constructible<nil::crypto3::multiprecision::uint512_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_constructible<nil::crypto3::multiprecision::checked_uint512_t>::value);

#endif

#if !defined(BOOST_NO_CXX11_NOEXCEPT) && !defined(BOOST_NO_SFINAE_EXPR) || defined(BOOST_IS_NOTHROW_MOVE_ASSIGN)
//
// Move assign:
//
BOOST_STATIC_ASSERT(boost::is_nothrow_move_assignable<nil::crypto3::multiprecision::cpp_int>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_assignable<nil::crypto3::multiprecision::int128_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_assignable<nil::crypto3::multiprecision::checked_int128_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_assignable<nil::crypto3::multiprecision::uint128_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_assignable<nil::crypto3::multiprecision::checked_uint128_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_assignable<nil::crypto3::multiprecision::int512_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_assignable<nil::crypto3::multiprecision::checked_int512_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_assignable<nil::crypto3::multiprecision::uint512_t>::value);
BOOST_STATIC_ASSERT(boost::is_nothrow_move_assignable<nil::crypto3::multiprecision::checked_uint512_t>::value);

#endif

//
// Construct:
//
#ifdef BOOST_HAS_NOTHROW_CONSTRUCTOR
BOOST_STATIC_ASSERT(boost::has_nothrow_constructor<nil::crypto3::multiprecision::cpp_int>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_constructor<nil::crypto3::multiprecision::int128_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_constructor<nil::crypto3::multiprecision::checked_int128_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_constructor<nil::crypto3::multiprecision::uint128_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_constructor<nil::crypto3::multiprecision::checked_uint128_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_constructor<nil::crypto3::multiprecision::int512_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_constructor<nil::crypto3::multiprecision::checked_int512_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_constructor<nil::crypto3::multiprecision::uint512_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_constructor<nil::crypto3::multiprecision::checked_uint512_t>::value);
#endif
//
// Copy construct:
//
#ifdef BOOST_HAS_NOTHROW_COPY
BOOST_STATIC_ASSERT(!boost::has_nothrow_copy<nil::crypto3::multiprecision::cpp_int>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_copy<nil::crypto3::multiprecision::int128_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_copy<nil::crypto3::multiprecision::checked_int128_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_copy<nil::crypto3::multiprecision::uint128_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_copy<nil::crypto3::multiprecision::checked_uint128_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_copy<nil::crypto3::multiprecision::int512_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_copy<nil::crypto3::multiprecision::checked_int512_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_copy<nil::crypto3::multiprecision::uint512_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_copy<nil::crypto3::multiprecision::checked_uint512_t>::value);
#endif
//
// Assign:
//
#ifdef BOOST_HAS_NOTHROW_ASSIGN
BOOST_STATIC_ASSERT(!boost::has_nothrow_assign<nil::crypto3::multiprecision::cpp_int>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_assign<nil::crypto3::multiprecision::int128_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_assign<nil::crypto3::multiprecision::checked_int128_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_assign<nil::crypto3::multiprecision::uint128_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_assign<nil::crypto3::multiprecision::checked_uint128_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_assign<nil::crypto3::multiprecision::int512_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_assign<nil::crypto3::multiprecision::checked_int512_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_assign<nil::crypto3::multiprecision::uint512_t>::value);
BOOST_STATIC_ASSERT(boost::has_nothrow_assign<nil::crypto3::multiprecision::checked_uint512_t>::value);
#endif
//
// Construct from int:
//
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::cpp_int(std::declval<nil::crypto3::multiprecision::signed_limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::int128_t(std::declval<nil::crypto3::multiprecision::signed_limb_type>())));
BOOST_STATIC_ASSERT(noexcept(
    nil::crypto3::multiprecision::checked_int128_t(std::declval<nil::crypto3::multiprecision::signed_limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::uint128_t(std::declval<nil::crypto3::multiprecision::signed_limb_type>())));
BOOST_STATIC_ASSERT(!noexcept(
    nil::crypto3::multiprecision::checked_uint128_t(std::declval<nil::crypto3::multiprecision::signed_limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::int512_t(std::declval<nil::crypto3::multiprecision::signed_limb_type>())));
BOOST_STATIC_ASSERT(noexcept(
    nil::crypto3::multiprecision::checked_int512_t(std::declval<nil::crypto3::multiprecision::signed_limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::uint512_t(std::declval<nil::crypto3::multiprecision::signed_limb_type>())));
BOOST_STATIC_ASSERT(!noexcept(
    nil::crypto3::multiprecision::checked_uint512_t(std::declval<nil::crypto3::multiprecision::signed_limb_type>())));
//
// Construct from unsigned int:
//
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::cpp_int(std::declval<nil::crypto3::multiprecision::limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::int128_t(std::declval<nil::crypto3::multiprecision::limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::checked_int128_t(std::declval<nil::crypto3::multiprecision::limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::uint128_t(std::declval<nil::crypto3::multiprecision::limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::checked_uint128_t(std::declval<nil::crypto3::multiprecision::limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::int512_t(std::declval<nil::crypto3::multiprecision::limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::checked_int512_t(std::declval<nil::crypto3::multiprecision::limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::uint512_t(std::declval<nil::crypto3::multiprecision::limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::checked_uint512_t(std::declval<nil::crypto3::multiprecision::limb_type>())));
//
// Assign from int:
//
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::cpp_int>() =
                                 std::declval<nil::crypto3::multiprecision::signed_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::int128_t>() =
                                 std::declval<nil::crypto3::multiprecision::signed_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::checked_int128_t>() =
                                 std::declval<nil::crypto3::multiprecision::signed_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::uint128_t>() =
                                 std::declval<nil::crypto3::multiprecision::signed_limb_type>()));
BOOST_STATIC_ASSERT(!noexcept(std::declval<nil::crypto3::multiprecision::checked_uint128_t>() =
                                  std::declval<nil::crypto3::multiprecision::signed_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::int512_t>() =
                                 std::declval<nil::crypto3::multiprecision::signed_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::checked_int512_t>() =
                                 std::declval<nil::crypto3::multiprecision::signed_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::uint512_t>() =
                                 std::declval<nil::crypto3::multiprecision::signed_limb_type>()));
BOOST_STATIC_ASSERT(!noexcept(std::declval<nil::crypto3::multiprecision::checked_uint512_t>() =
                                  std::declval<nil::crypto3::multiprecision::signed_limb_type>()));
//
// Assign from unsigned int:
//
BOOST_STATIC_ASSERT(noexcept(
    std::declval<nil::crypto3::multiprecision::cpp_int>() = std::declval<nil::crypto3::multiprecision::limb_type>()));
BOOST_STATIC_ASSERT(noexcept(
    std::declval<nil::crypto3::multiprecision::int128_t>() = std::declval<nil::crypto3::multiprecision::limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::checked_int128_t>() =
                                 std::declval<nil::crypto3::multiprecision::limb_type>()));
BOOST_STATIC_ASSERT(noexcept(
    std::declval<nil::crypto3::multiprecision::uint128_t>() = std::declval<nil::crypto3::multiprecision::limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::checked_uint128_t>() =
                                 std::declval<nil::crypto3::multiprecision::limb_type>()));
BOOST_STATIC_ASSERT(noexcept(
    std::declval<nil::crypto3::multiprecision::int512_t>() = std::declval<nil::crypto3::multiprecision::limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::checked_int512_t>() =
                                 std::declval<nil::crypto3::multiprecision::limb_type>()));
BOOST_STATIC_ASSERT(noexcept(
    std::declval<nil::crypto3::multiprecision::uint512_t>() = std::declval<nil::crypto3::multiprecision::limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::checked_uint512_t>() =
                                 std::declval<nil::crypto3::multiprecision::limb_type>()));

#if defined(BOOST_LITTLE_ENDIAN) && !defined(BOOST_MP_TEST_NO_LE)
//
// We can also nothrow construct from a double_limb_type (or smaller obviously) as long as double_limb_type is smaller
// than the type in question (so don't test 128-bit integers in case double_limb_type is __int128).
//
// Construct from int:
//
BOOST_STATIC_ASSERT(noexcept(
    nil::crypto3::multiprecision::cpp_int(std::declval<nil::crypto3::multiprecision::signed_double_limb_type>())));
BOOST_STATIC_ASSERT(noexcept(
    nil::crypto3::multiprecision::int512_t(std::declval<nil::crypto3::multiprecision::signed_double_limb_type>())));
BOOST_STATIC_ASSERT(noexcept(nil::crypto3::multiprecision::checked_int512_t(
    std::declval<nil::crypto3::multiprecision::signed_double_limb_type>())));
BOOST_STATIC_ASSERT(noexcept(
    nil::crypto3::multiprecision::uint512_t(std::declval<nil::crypto3::multiprecision::signed_double_limb_type>())));
BOOST_STATIC_ASSERT(!noexcept(nil::crypto3::multiprecision::checked_uint512_t(
    std::declval<nil::crypto3::multiprecision::signed_double_limb_type>())));
//
// Construct from unsigned int:
//
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::cpp_int(std::declval<nil::crypto3::multiprecision::double_limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::int512_t(std::declval<nil::crypto3::multiprecision::double_limb_type>())));
BOOST_STATIC_ASSERT(noexcept(
    nil::crypto3::multiprecision::checked_int512_t(std::declval<nil::crypto3::multiprecision::double_limb_type>())));
BOOST_STATIC_ASSERT(
    noexcept(nil::crypto3::multiprecision::uint512_t(std::declval<nil::crypto3::multiprecision::double_limb_type>())));
BOOST_STATIC_ASSERT(noexcept(
    nil::crypto3::multiprecision::checked_uint512_t(std::declval<nil::crypto3::multiprecision::double_limb_type>())));
//
// Assign from int:
//
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::cpp_int>() =
                                 std::declval<nil::crypto3::multiprecision::signed_double_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::int512_t>() =
                                 std::declval<nil::crypto3::multiprecision::signed_double_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::checked_int512_t>() =
                                 std::declval<nil::crypto3::multiprecision::signed_double_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::uint512_t>() =
                                 std::declval<nil::crypto3::multiprecision::signed_double_limb_type>()));
BOOST_STATIC_ASSERT(!noexcept(std::declval<nil::crypto3::multiprecision::checked_uint512_t>() =
                                  std::declval<nil::crypto3::multiprecision::signed_double_limb_type>()));
//
// Assign from unsigned int:
//
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::cpp_int>() =
                                 std::declval<nil::crypto3::multiprecision::double_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::int512_t>() =
                                 std::declval<nil::crypto3::multiprecision::double_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::checked_int512_t>() =
                                 std::declval<nil::crypto3::multiprecision::double_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::uint512_t>() =
                                 std::declval<nil::crypto3::multiprecision::double_limb_type>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<nil::crypto3::multiprecision::checked_uint512_t>() =
                                 std::declval<nil::crypto3::multiprecision::double_limb_type>()));

#endif    // little endian

typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
    32, 32, nil::crypto3::multiprecision::signed_magnitude, nil::crypto3::multiprecision::checked, void>>
    checked_int32_t;
typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
    32, 32, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>
    checked_uint32_t;
typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
    32, 32, nil::crypto3::multiprecision::signed_magnitude, nil::crypto3::multiprecision::unchecked, void>>
    unchecked_int32_t;
typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
    32, 32, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::unchecked, void>>
    unchecked_uint32_t;

//
// Construct from int:
//
BOOST_STATIC_ASSERT(noexcept(unchecked_int32_t(std::declval<boost::int32_t>())));
BOOST_STATIC_ASSERT(noexcept(checked_int32_t(std::declval<boost::int32_t>())));
BOOST_STATIC_ASSERT(noexcept(unchecked_uint32_t(std::declval<boost::int32_t>())));
BOOST_STATIC_ASSERT(!noexcept(checked_uint32_t(std::declval<boost::int32_t>())));
//
// Construct from unsigned int:
//
BOOST_STATIC_ASSERT(noexcept(unchecked_int32_t(std::declval<boost::uint32_t>())));
BOOST_STATIC_ASSERT(noexcept(checked_int32_t(std::declval<boost::uint32_t>())));
BOOST_STATIC_ASSERT(noexcept(unchecked_uint32_t(std::declval<boost::uint32_t>())));
BOOST_STATIC_ASSERT(noexcept(checked_uint32_t(std::declval<boost::uint32_t>())));
//
// Assign from int:
//
BOOST_STATIC_ASSERT(noexcept(std::declval<unchecked_int32_t>() = std::declval<boost::int32_t>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<checked_int32_t>() = std::declval<boost::int32_t>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<unchecked_uint32_t>() = std::declval<boost::int32_t>()));
BOOST_STATIC_ASSERT(!noexcept(std::declval<checked_uint32_t>() = std::declval<boost::int32_t>()));
//
// Assign from unsigned int:
//
BOOST_STATIC_ASSERT(noexcept(std::declval<unchecked_int32_t>() = std::declval<boost::uint32_t>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<checked_int32_t>() = std::declval<boost::uint32_t>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<unchecked_uint32_t>() = std::declval<boost::uint32_t>()));
BOOST_STATIC_ASSERT(noexcept(std::declval<checked_uint32_t>() = std::declval<boost::uint32_t>()));

//
// And finally some things which should *not* be noexcept:
//
typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
    30, 30, nil::crypto3::multiprecision::signed_magnitude, nil::crypto3::multiprecision::checked, void>>
    checked_int30_t;
typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
    30, 30, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>
    checked_uint30_t;
typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
    30, 30, nil::crypto3::multiprecision::signed_magnitude, nil::crypto3::multiprecision::unchecked, void>>
    unchecked_int30_t;
typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
    30, 30, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::unchecked, void>>
    unchecked_uint30_t;

//
// Construct from int:
//
BOOST_STATIC_ASSERT(!noexcept(checked_int30_t(std::declval<boost::int32_t>())));
BOOST_STATIC_ASSERT(!noexcept(checked_uint30_t(std::declval<boost::int32_t>())));
BOOST_STATIC_ASSERT(!noexcept(checked_int32_t(std::declval<boost::int64_t>())));
BOOST_STATIC_ASSERT(!noexcept(checked_uint32_t(std::declval<boost::int64_t>())));
//
// Construct from unsigned int:
//
BOOST_STATIC_ASSERT(!noexcept(checked_int30_t(std::declval<boost::uint32_t>())));
BOOST_STATIC_ASSERT(!noexcept(checked_uint30_t(std::declval<boost::uint32_t>())));
BOOST_STATIC_ASSERT(!noexcept(checked_int32_t(std::declval<boost::uint64_t>())));
BOOST_STATIC_ASSERT(!noexcept(checked_uint32_t(std::declval<boost::uint64_t>())));
//
// Assign from int:
//
BOOST_STATIC_ASSERT(!noexcept(std::declval<checked_int30_t>() = std::declval<boost::int32_t>()));
BOOST_STATIC_ASSERT(!noexcept(std::declval<checked_uint30_t>() = std::declval<boost::int32_t>()));
BOOST_STATIC_ASSERT(!noexcept(std::declval<checked_int32_t>() = std::declval<boost::int64_t>()));
BOOST_STATIC_ASSERT(!noexcept(std::declval<checked_uint32_t>() = std::declval<boost::int64_t>()));
//
// Assign from unsigned int:
//
BOOST_STATIC_ASSERT(!noexcept(std::declval<checked_int30_t>() = std::declval<boost::uint32_t>()));
BOOST_STATIC_ASSERT(!noexcept(std::declval<checked_uint30_t>() = std::declval<boost::uint32_t>()));
BOOST_STATIC_ASSERT(!noexcept(std::declval<checked_int32_t>() = std::declval<boost::uint64_t>()));
BOOST_STATIC_ASSERT(!noexcept(std::declval<checked_uint32_t>() = std::declval<boost::uint64_t>()));

#endif    // noexcept
