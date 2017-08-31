/* boost random/nierderreiter_base2.hpp header file
 *
 * Copyright Justinas Vygintas Daugmaudis 2010-2017
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 */

#ifndef BOOST_RANDOM_NIEDERREITER_BASE2_HPP
#define BOOST_RANDOM_NIEDERREITER_BASE2_HPP

#include <boost/random/detail/gray_coded_qrng_base.hpp>
#include <boost/random/detail/config.hpp>
#include <boost/random/detail/operators.hpp>

#include <limits>
#include <boost/cstdint.hpp>

#include <boost/dynamic_bitset.hpp>
#include <boost/multi_array.hpp>

//!\file
//!Describes the quasi-random number generator class template niederreiter_base2.
//!
//!\b Note: it is especially useful in conjunction with class template uniform_real.

namespace boost {
namespace random {

/** @cond */
namespace detail {
namespace nb2 {

/*
  Primitive polynomials in binary encoding
  {
    { 1, 0, 0, 0, 0, 0 },    1
    { 0, 1, 0, 0, 0, 0 },    x
    { 1, 1, 0, 0, 0, 0 },    1 + x
    { 1, 1, 1, 0, 0, 0 },    1 + x + x^2
    { 1, 1, 0, 1, 0, 0 },    1 + x + x^3
    { 1, 0, 1, 1, 0, 0 },    1 + x^2 + x^3
    { 1, 1, 0, 0, 1, 0 },    1 + x + x^4
    { 1, 0, 0, 1, 1, 0 },    1 + x^3 + x^4
    { 1, 1, 1, 1, 1, 0 },    1 + x + x^2 + x^3 + x^4
    { 1, 0, 1, 0, 0, 1 },    1 + x^2 + x^5
    { 1, 0, 0, 1, 0, 1 },    1 + x^3 + x^5
    { 1, 1, 1, 1, 0, 1 },    1 + x + x^2 + x^3 + x^5
    { 1, 1, 1, 0, 1, 1 }     1 + x + x^2 + x^4 + x^5
  };
*/

// Maximum allowed space dimension
#define BOOST_RANDOM_NIEDERREITER_BASE2_MAX_DIMENSION 54

struct niederreiter_tables
{
  BOOST_STATIC_CONSTANT(int, max_dimension = BOOST_RANDOM_NIEDERREITER_BASE2_MAX_DIMENSION);

  // Binary irreducible polynomials (primes in the ring GF(2)[X]), evaluated at X=2. 
  static unsigned short polynomial(std::size_t n)
  {
    static const unsigned short nb2_a[max_dimension] = {
      2, 3, 7, 11, 13, 19, 25, 31, 37, 41,
      47, 55, 59, 61, 67, 73, 87, 91, 97, 103,
      109, 115, 117, 131, 137, 143, 145, 157,
      167, 171, 185, 191, 193, 203, 211, 213,
      229, 239, 241, 247, 253, 283, 285, 299, 
      301, 313, 319, 333, 351, 355, 357, 361, 369, 
      375
    };

    return nb2_a[n];
  }
};

// Return the base 2 logarithm for a given bitset v
template <typename Block, typename Allocator>
inline typename boost::dynamic_bitset<Block, Allocator>::size_type 
bitset_log2(const boost::dynamic_bitset<Block, Allocator>& v)
{
  typedef boost::dynamic_bitset<Block, Allocator> bitset_t;
  typedef typename bitset_t::size_type size_type;

  if (v.none())
    throw std::invalid_argument("bitset_log2");

  size_type up  = v.size() - 1;
  size_type low = v.find_next(0);

  // Binary lookup for the most significant set bit
  while (low < up)
  {
    size_type m = low + (up - low) / 2;
 
    // Check if any bit is present after mid
    size_type p = v.find_next(m);
    if (p != bitset_t::npos)
        low = p;
    else
        up = m;
  }

  return low;
}


// Multiply polynomials over Z_2.
template <typename Block, typename Allocator>
inline boost::dynamic_bitset<Block, Allocator>
modulo2_multiply(int P, boost::dynamic_bitset<Block, Allocator> v)
{
  boost::dynamic_bitset<Block, Allocator> pt (v.size());
  for (; P; P >>= 1, v <<= 1)
    if (P & 1) pt ^= v;
  return pt;
}


// Calculate the values of the constants V(J,R) as
// described in BFN section 3.3.
//
// px = appropriate irreducible polynomial for current dimension
// pb = polynomial defined in section 2.3 of BFN.
// pb is modified
template <typename Block, typename Allocator, typename T>
inline void calculate_v(const boost::dynamic_bitset<Block, Allocator>& pb,
  int& pb_degree, std::vector<T>& v)
{
  const T arbitrary_element = static_cast<T>(1);  // arbitray element of Z_2

  // Now choose a value of Kj as defined in section 3.3.
  // We must have 0 <= Kj < E*J = M.
  // The limit condition on Kj does not seem very relevant
  // in this program.
  int kj = pb_degree;

  pb_degree = bitset_log2(pb);

  // Now choose values of V in accordance with
  // the conditions in section 3.3.
  std::fill(v.begin(), v.begin() + kj, T());

  // Quoting from BFN: "Our program currently sets each K_q
  // equal to eq. This has the effect of setting all unrestricted
  // values of v to 1."
  // Actually, it sets them to the arbitrary chosen value.
  // Whatever.
  for (int r = kj; r < pb_degree; ++r)
    v[r] = arbitrary_element;

  // Calculate the remaining V's using the recursion of section 2.3,
  // remembering that the B's have the opposite sign.
  for (int r = pb_degree; r < v.size(); ++r)
  {
    T term = T /*zero*/ ();
    boost::dynamic_bitset<> pb_c = pb;
    for (int k = -pb_degree; k < 0; ++k, pb_c >>= 1)
    {
      if( pb_c.test(0) )
        term ^= v[r + k];
    }
    v[r] = term;
  }
}

} // namespace nb2

template<typename IntType>
struct niederreiter_base2_lattice
{
  typedef IntType value_type;

  BOOST_STATIC_CONSTANT(int, bit_count = std::numeric_limits<IntType>::digits);

  explicit niederreiter_base2_lattice(std::size_t dimension)
  {
    resize(dimension);
  }

  void resize(std::size_t dimension)
  {
    if (dimension > nb2::niederreiter_tables::max_dimension)
    {
      throw std::invalid_argument("The Niederreiter base 2 quasi-random number generator only supports up to " 
        BOOST_PP_STRINGIZE(BOOST_RANDOM_NIEDERREITER_BASE2_MAX_DIMENSION) " dimensions.");
    }

    // Initialize the bit array
    bits.resize(boost::extents[bit_count][dimension]);
     
    // Reserve temporary space for lattice computation
    boost::multi_array<IntType, 2> ci(boost::extents[bit_count][bit_count]);

    std::vector<IntType> v;

    // Compute Niedderreiter base 2 lattice
    for (std::size_t dim = 0; dim != dimension; ++dim)
    {
      const int poly = nb2::niederreiter_tables::polynomial(dim);
      if (static_cast<std::size_t>(poly) > 
          static_cast<std::size_t>(std::numeric_limits<IntType>::max())) {
        boost::throw_exception( std::range_error("niederreiter_base2: polynomial value outside the given IntType range") );
      }

      const int degree = multiprecision::detail::find_msb(poly); // integer log2(poly)
      const int max_degree = degree * ((bit_count / degree) + 1);

      v.resize(degree + max_degree);
  
      // For each dimension, we need to calculate powers of an
      // appropriate irreducible polynomial, see Niederreiter
      // page 65, just below equation (19).
      // Copy the appropriate irreducible polynomial into PX,
      // and its degree into E.  Set polynomial B = PX ** 0 = 1.
      // M is the degree of B.  Subsequently B will hold higher
      // powers of PX.
      int pb_degree = 0;
      boost::dynamic_bitset<> pb(max_degree, 1);
  
      int j = 0;
      while (j < bit_count)
      {
        // Now multiply B by PX so B becomes PX**J.
        // In section 2.3, the values of Bi are defined with a minus sign :
        // don't forget this if you use them later!
        nb2::modulo2_multiply(poly, boost::move(pb)).swap(pb);

        // If U = 0, we need to set B to the next power of PX
        // and recalculate V.
        nb2::calculate_v(pb, pb_degree, v);
  
        // Niederreiter (page 56, after equation (7), defines two
        // variables Q and U.  We do not need Q explicitly, but we
        // do need U.
  
        // Advance Niederreiter's state variables.
        for (int u = 0; u < degree && j < bit_count; ++u, ++j)
        {
          // Now C is obtained from V.  Niederreiter
          // obtains A from V (page 65, near the bottom), and then gets
          // C from A (page 56, equation (7)).  However this can be done
          // in one step.  Here CI(J,R) corresponds to
          // Niederreiter's C(I,J,R).
          for (int r = 0; r < bit_count; ++r) {
            ci[r][j] = v[r + u];
          }
        }
      }
  
      // The array CI now holds the values of C(I,J,R) for this value
      // of I.  We pack them into array CJ so that CJ(I,R) holds all
      // the values of C(I,J,R) for J from 1 to NBITS.
      for (int r = 0; r < bit_count; ++r)
      {
        IntType term = 0;
        for (int j = 0; j < bit_count; ++j)
          term = 2*term + ci[r][j];
        bits[r][dim] = term;
      }
    }
  }

  value_type operator()(int i, int j) const
  {
    return bits[i][j];
  }

private:
  boost::multi_array<IntType, 2> bits;
};

} // namespace detail
/** @endcond */

//!class template niederreiter_base2 implements a quasi-random number generator as described in
//! \blockquote
//!Bratley, Fox, Niederreiter, ACM Trans. Model. Comp. Sim. 2, 195 (1992).
//! \endblockquote
//!
//!\attention \b Important: This implementation supports up to 20 dimensions.
//!
//!In the following documentation @c X denotes the concrete class of the template
//!niederreiter_base2 returning objects of type @c IntType, u and v are the values of @c X.
//!
//!Some member functions may throw exceptions of type std::overflow_error. This
//!happens when the quasi-random domain is exhausted and the generator cannot produce
//!any more values. The length of the low discrepancy sequence is given by
//! \f$L=Dimension \times 2^{digits}\f$, where digits = std::numeric_limits<IntType>::digits.
template<typename IntType>
class niederreiter_base2 : public detail::gray_coded_qrng_base<
                                    niederreiter_base2<IntType>,
                                    detail::niederreiter_base2_lattice<IntType> >
{
  typedef niederreiter_base2<IntType> self_t;
  typedef detail::niederreiter_base2_lattice<IntType> lattice_t;
  typedef detail::gray_coded_qrng_base<self_t, lattice_t> base_t;

public:
  typedef IntType result_type;

  //!Returns: Tight lower bound on the set of values returned by operator().
  //!
  //!Throws: nothing.
  static result_type min BOOST_PREVENT_MACRO_SUBSTITUTION () { return 0; }

  //!Returns: Tight upper bound on the set of values returned by operator().
  //!
  //!Throws: nothing.
  static result_type max BOOST_PREVENT_MACRO_SUBSTITUTION () { return std::numeric_limits<IntType>::max(); }

  //!Effects: Constructs the default s-dimensional Niederreiter base 2 quasi-random number generator.
  //!
  //!Throws: bad_alloc, invalid_argument, range_error.
  explicit niederreiter_base2(std::size_t s)
    : base_t(s) // initialize lattice here
  {}

  //!Requirements: *this is mutable.
  //!
  //!Effects: Resets the quasi-random number generator state to
  //!the one given by the default construction. Equivalent to u.seed(0).
  //!
  //!\brief Throws: nothing.
  void seed()
  {
    base_t::reset_state();
  }

  //!Requirements: *this is mutable.
  //!
  //!Effects: Effectively sets the quasi-random number generator state to the init-th
  //!vector in the s-dimensional quasi-random domain, where s == X::dimension().
  //!\code
  //!X u, v;
  //!for(int i = 0; i < N; ++i)
  //!    for( std::size_t j = 0; j < u.dimension(); ++j )
  //!        u();
  //!v.seed(N);
  //!assert(u() == v());
  //!\endcode
  //!
  //!\brief Throws: overflow_error.
  void seed(std::size_t init)
  {
    base_t::seed(init, "niederreiter_base2::seed");
  }

  //=========================Doxygen needs this!==============================

  //!Requirements: *this is mutable.
  //!
  //!Returns: Returns a successive element of an s-dimensional
  //!(s = X::dimension()) vector at each invocation. When all elements are
  //!exhausted, X::operator() begins anew with the starting element of a
  //!subsequent s-dimensional vector.
  //!
  //!Throws: overflow_error.
  result_type operator()()
  {
    return base_t::operator()();
  }

  //!Requirements: *this is mutable.
  //!
  //!Effects: Advances *this state as if z consecutive
  //!X::operator() invocations were executed.
  //!\code
  //!X u = v;
  //!for(int i = 0; i < N; ++i)
  //!    u();
  //!v.discard(N);
  //!assert(u() == v());
  //!\endcode
  //!
  //!Throws: overflow_error.
  void discard(std::size_t z)
  {
    base_t::discard(z);
  }
};

} // namespace random

typedef random::niederreiter_base2<uint32_t> niederreiter_base2;

} // namespace boost

#endif // BOOST_RANDOM_NIEDERREITER_BASE2_HPP
