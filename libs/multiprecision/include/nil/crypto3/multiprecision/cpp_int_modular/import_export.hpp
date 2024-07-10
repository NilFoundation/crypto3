///////////////////////////////////////////////////////////////
//  Copyright 2015 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifndef CRYPTO3_MP_CPP_INT_IMPORT_EXPORT_HPP
#define CRYPTO3_MP_CPP_INT_IMPORT_EXPORT_HPP

#include <climits>
#include <cstring>

#include <boost/predef/os/macos.h>
#include <boost/multiprecision/traits/std_integer_traits.hpp>
#include <boost/multiprecision/detail/endian.hpp>
#include <boost/multiprecision/cpp_int/import_export.hpp> // For 'extract_bits'.

namespace boost {
    namespace multiprecision {
        namespace detail {

            template<unsigned Bits, class Unsigned>
            void assign_bits(boost::multiprecision::backends::cpp_int_modular_backend<Bits>& val,
                             Unsigned bits, std::size_t bit_location, std::size_t chunk_bits,
                             const std::integral_constant<bool, false>& tag) {
                unsigned limb = bit_location / (sizeof(limb_type) * CHAR_BIT);
                unsigned shift = bit_location % (sizeof(limb_type) * CHAR_BIT);

                limb_type mask = chunk_bits >= sizeof(limb_type) * CHAR_BIT ?
                                     ~static_cast<limb_type>(0u) :
                                     (static_cast<limb_type>(1u) << chunk_bits) - 1;

                limb_type value = static_cast<limb_type>(bits & mask) << shift;
                if (value) {
                    // We are ignoring any bits that will not fit into the number.
                    // We are not throwing, we will use as many bits from the input as we need to.
                    if (val.size() > limb)
                        val.limbs()[limb] |= value;
                }

                if (chunk_bits > sizeof(limb_type) * CHAR_BIT - shift) {
                    shift = sizeof(limb_type) * CHAR_BIT - shift;
                    chunk_bits -= shift;
                    bit_location += shift;
                    bits >>= shift;
                    if (bits)
                        assign_bits(val, bits, bit_location, chunk_bits, tag);
                }
            }

#ifdef BOOST_OS_MACOS_AVAILABLE
            // Especially for mac, for the case when a vector<bool> is being converted to a number.
            // When you dereference an iterator to std::vector<bool> you will receive 
            // std::__bit_const_reference<std::vector<bool>>>.
            template<unsigned Bits>
            void assign_bits(boost::multiprecision::backends::cpp_int_modular_backend<Bits>& val,
                             std::__bit_const_reference<std::vector<bool>> bits,
                            std::size_t bit_location, std::size_t chunk_bits,
                             const std::integral_constant<bool, false>& tag) {
               assign_bits(val, static_cast<bool>(bits), bit_location, chunk_bits, tag);
            }
#endif

            template<unsigned Bits, class Unsigned>
            void assign_bits(boost::multiprecision::backends::cpp_int_modular_backend<Bits>& val,
                             Unsigned bits, std::size_t bit_location, std::size_t chunk_bits,
                             const std::integral_constant<bool, true>&) {
                using local_limb_type = typename boost::multiprecision::backends::cpp_int_modular_backend<Bits>::local_limb_type;
                //
                // Check for possible overflow, this may trigger an exception, or have no effect
                // depending on whether this is a checked integer or not:
                //
                // We are not throwing, we will use as many bits from the input as we need to.
                // BOOST_ASSERT(!((bit_location >= sizeof(local_limb_type) * CHAR_BIT) && bits));

                local_limb_type mask = chunk_bits >= sizeof(local_limb_type) * CHAR_BIT ?
                                           ~static_cast<local_limb_type>(0u) :
                                           (static_cast<local_limb_type>(1u) << chunk_bits) - 1;
                local_limb_type value = (static_cast<local_limb_type>(bits) & mask) << bit_location;
                *val.limbs() |= value;

                //
                // Check for overflow bits:
                //
                bit_location = sizeof(local_limb_type) * CHAR_BIT - bit_location;

                // We are not throwing, we will use as many bits from the input as we need to.
                // BOOST_ASSERT(!((bit_location < sizeof(bits) * CHAR_BIT) && (bits >>= bit_location)));
            }

            template<unsigned Bits, expression_template_option ExpressionTemplates, class Iterator>
            number<boost::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>&
            import_bits_generic(number<boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
                ExpressionTemplates>& val, Iterator i, Iterator j, std::size_t chunk_size = 0, bool msv_first = true) {
                boost::multiprecision::backends::cpp_int_modular_backend<Bits> newval;

                using value_type = typename std::iterator_traits<Iterator>::value_type;
                using difference_type = typename std::iterator_traits<Iterator>::difference_type;
                using size_type = typename ::boost::multiprecision::detail::make_unsigned<difference_type>::type;
                using tag_type = typename boost::multiprecision::backends::cpp_int_modular_backend<Bits>::trivial_tag;

                if (!chunk_size)
                   chunk_size = std::numeric_limits<value_type>::digits;

                size_type limbs = std::distance(i, j);
                size_type bits  = limbs * chunk_size;

                // We are not throwing, we will use as many bits from the input as we need to.
                // BOOST_ASSERT(bits <= Bits);

                difference_type bit_location        = msv_first ? bits - chunk_size : 0;
                difference_type bit_location_change = msv_first ? -static_cast<difference_type>(chunk_size) : chunk_size;

                while (i != j)
                {
                    assign_bits(
                      newval, *i,
                      static_cast<std::size_t>(bit_location), chunk_size, tag_type());
                    ++i;
                    bit_location += bit_location_change;
                }

                // This will remove the upper bits using upper_limb_mask.
                newval.normalize();

                val.backend() = std::move(newval);
                return val;
            }

            template <unsigned Bits, expression_template_option ExpressionTemplates, class T>
            inline typename std::enable_if<!boost::multiprecision::backends::is_trivial_cpp_int_modular<boost::multiprecision::backends::cpp_int_modular_backend<Bits> >::value, number<boost::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>&>::type
            import_bits_fast(
                number<boost::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>& val,
                T* i, T* j, std::size_t chunk_size = 0)
            {
                std::size_t byte_len = (j - i) * (chunk_size ? chunk_size / CHAR_BIT : sizeof(*i));
                std::size_t limb_len = byte_len / sizeof(limb_type);
                if (byte_len % sizeof(limb_type))
                   ++limb_len;

                boost::multiprecision::backends::cpp_int_modular_backend<Bits>& result = val.backend();
                BOOST_ASSERT(result.size() > limb_len);

                result.limbs()[result.size() - 1] = 0u;
                std::memcpy(result.limbs(), i, (std::min)(byte_len, result.size() * sizeof(limb_type)));

                // This is probably unneeded, but let it stay for now.
                result.normalize();
                return val;
            }

            template <unsigned Bits, expression_template_option ExpressionTemplates, class T>
            inline typename std::enable_if<boost::multiprecision::backends::is_trivial_cpp_int_modular<boost::multiprecision::backends::cpp_int_modular_backend<Bits> >::value, number<boost::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>&>::type
            import_bits_fast(
                number<boost::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>& val,
                T* i, T* j, std::size_t chunk_size = 0)
            {
                boost::multiprecision::backends::cpp_int_modular_backend<Bits>& result   = val.backend();
                std::size_t byte_len = (j - i) * (chunk_size ? chunk_size / CHAR_BIT : sizeof(*i));
                std::size_t limb_len = byte_len / sizeof(result.limbs()[0]);
                if (byte_len % sizeof(result.limbs()[0]))
                   ++limb_len;
                BOOST_ASSERT(result.size() > limb_len);

                result.limbs()[0] = 0u;
                std::memcpy(result.limbs(), i, (std::min)(byte_len, result.size() * sizeof(result.limbs()[0])));

                // This is probably unneeded, but let it stay for now.
                result.normalize();
                return val;
            }
        } // namespace detail

        template <unsigned Bits, expression_template_option ExpressionTemplates, class Iterator>
        inline number<boost::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>&
        import_bits(
            number<boost::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>& val,
            Iterator i, Iterator j, std::size_t chunk_size = 0, bool msv_first = true)
        {
            return detail::import_bits_generic(val, i, j, chunk_size, msv_first);
        }

        template <unsigned Bits, expression_template_option ExpressionTemplates, class T>
        inline number<boost::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>&
        import_bits(
            number<boost::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>& val,
            T* i, T* j, std::size_t chunk_size = 0, bool msv_first = true)
        {
        #if CRYPTO3_MP_ENDIAN_LITTLE_BYTE
            if (((chunk_size % CHAR_BIT) == 0) && !msv_first && (sizeof(*i) * CHAR_BIT == chunk_size))
               return detail::import_bits_fast(val, i, j, chunk_size);
        #endif
            return detail::import_bits_generic(val, i, j, chunk_size, msv_first);
        }

        template <unsigned Bits, expression_template_option ExpressionTemplates,
            class OutputIterator>
        OutputIterator export_bits(
            const number<boost::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>& val,
                OutputIterator out, std::size_t chunk_size, bool msv_first = true)
        {
        #ifdef BOOST_MSVC
        #pragma warning(push)
        #pragma warning(disable : 4244)
        #endif
            using tag_type = typename boost::multiprecision::backends::cpp_int_modular_backend<Bits>::trivial_tag;
            if (!val)
            {
               *out = 0;
               ++out;
               return out;
            }
            std::size_t bitcount = eval_msb_imp(val.backend()) + 1;

            std::ptrdiff_t bit_location = msv_first ? static_cast<std::ptrdiff_t>(bitcount - chunk_size) : 0;
            const std::ptrdiff_t bit_step = msv_first ? static_cast<std::ptrdiff_t>(-static_cast<std::ptrdiff_t>(chunk_size)) : static_cast<std::ptrdiff_t>(chunk_size);
            while (bit_location % bit_step)
               ++bit_location;
            do
            {
               *out = detail::extract_bits(val.backend(), bit_location, chunk_size, tag_type());
               ++out;
               bit_location += bit_step;
            } while ((bit_location >= 0) && (bit_location < static_cast<int>(bitcount)));

            return out;
        #ifdef BOOST_MSVC
        #pragma warning(pop)
        #endif
        }
    }    // namespace multiprecision
}    // namespace boost

#endif // CRYPTO3_MP_CPP_INT_IMPORT_EXPORT_HPP
