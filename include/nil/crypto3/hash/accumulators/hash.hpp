//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Aleksey Moskvin <zerg1996@yandex.ru>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ACCUMULATORS_HASH_HPP
#define CRYPTO3_ACCUMULATORS_HASH_HPP

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <boost/container/static_vector.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/static_digest.hpp>

#include <nil/crypto3/hash/accumulators/bits_count.hpp>

#include <nil/crypto3/hash/accumulators/parameters/bits.hpp>
#include <nil/crypto3/hash/accumulators/parameters/salt.hpp>
//#include <nil/crypto3/detail/inject.hpp>

#include <boost/accumulators/statistics/count.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Hash>
                struct hash_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Hash hash_type;
                    typedef typename hash_type::construction::type construction_type;
                    typedef typename hash_type::construction::params_type params_type;


                    typedef typename params_type::digest_endian endian_type;


                    constexpr static const std::size_t word_bits = construction_type::word_bits;
                    typedef typename construction_type::word_type word_type;

                    constexpr static const std::size_t state_bits = construction_type::state_bits;
                    constexpr static const std::size_t state_words = construction_type::state_words;
                    typedef typename construction_type::state_type state_type;

                    constexpr static const std::size_t block_bits = construction_type::block_bits;
                    constexpr static const std::size_t block_words = construction_type::block_words;
                    typedef typename construction_type::block_type block_type;

                    constexpr static const std::size_t length_bits = params_type::length_bits;
                    // FIXME: do something more intelligent than capping at 64
                    constexpr static const std::size_t length_type_bits =
                        length_bits < word_bits ? word_bits : length_bits > 64 ? 64 : length_bits;
                    typedef typename boost::uint_t<length_type_bits>::least length_type;
                    constexpr static const std::size_t length_words = length_bits / word_bits;
                    BOOST_STATIC_ASSERT(!length_bits || length_bits % word_bits == 0);

                public:
                    typedef typename hash_type::digest_type result_type;

                    // The constructor takes an argument pack.
                    hash_impl(boost::accumulators::dont_care) : total_seen(0) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        total_seen = extract::bits_count(args);
                        resolve_type(args[boost::accumulators::sample],
                                     args[::nil::crypto3::accumulators::bits | std::size_t()]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        construction_type res = construction;
                        return res.digest(cache, total_seen);
                    }

                protected:

                    /*static void print_word(const word_type &word) {
                        for (length_type j = 0; j != word_bits; ++j)
                            std::cout << (bool) (word & (left_bits<word_type>(1) >> j));                    
                    }

                    static void print_bits(const block_type &block) {
                        std::cout<<"Here is the block: \n";
                        for (length_type i = 0; i != block_words; ++i) {
                            std::cout << "Word " << i << ": ";
                            print_word(block[i]);
                            std::cout << std::endl;
                        }
                    }*/

                    inline void resolve_type(const block_type &value, std::size_t bits) {
                        process(value, bits);
                    }

                    inline void resolve_type(const word_type &value, std::size_t bits) {
                        process(value, bits);
                    }


                // Creates mask with shift left bits
                template<typename T>
                static T left_bits(length_type shift) {
                    return (shift == word_bits)? ~T() : ~(~T() >> shift);
                }

                // Creates mask with shift right bits
                template<typename T>
                static T right_bits(length_type shift) {
                    return (shift == word_bits)? ~T() : ~(~T() << shift);
                }   

                template<typename Endianness>
                struct endian_shift;

                template<int UnitBits>
                struct endian_shift<stream_endian::big_unit_big_bit<UnitBits>> {
                    static word_type& to_msb(word_type &w, length_type shift) {
                        //shift to most significant bits according to endianness
                        w <<= shift;
                        return w;
                    }
                };

                template<int UnitBits>
                struct endian_shift<stream_endian::little_unit_big_bit<UnitBits>> {
                    static word_type& to_msb(word_type &w, length_type shift) {
                        //shift to most significant bits according to endianness
                        length_type shift_rem = shift % UnitBits;
                        length_type shift_unit_bits = shift - shift_rem;
                        
                        length_type sz[2] = {UnitBits - shift_rem, shift_rem};
                        length_type masks[2] = {right_bits<word_type>(sz[0]) << shift_unit_bits, 
                        right_bits<word_type>(sz[1]) << (shift_unit_bits + UnitBits + sz[0])};
                        length_type bits_left = word_bits - shift;
                        word_type w_combined = 0;
                        int ind = 0;

                        while (bits_left) {
                            w_combined |= (!ind ? ((w & masks[0]) << shift_rem) : ((w & masks[1]) >> (UnitBits + sz[0])));
                            bits_left -= sz[ind];
                            masks[ind] <<= UnitBits;
                            ind = 1 - ind;
                        }

                        w = w_combined >> shift_unit_bits;
                        return w;
                    }
                };

                template<int UnitBits>
                struct endian_shift<stream_endian::big_unit_little_bit<UnitBits>> {
                    static word_type& to_msb(word_type &w, length_type shift) {
                        //shift to most significant bits according to endianness
                        length_type shift_rem = shift % UnitBits;
                        length_type shift_unit_bits = shift - shift_rem;

                        length_type sz[2] = {UnitBits - shift_rem, shift_rem};
                        length_type masks[2] = {left_bits<word_type>(sz[0]) >> shift_unit_bits, 
                        left_bits<word_type>(sz[1]) >> (shift_unit_bits + UnitBits + sz[0])};

                        length_type bits_left = word_bits - shift;
                        word_type w_combined = 0;
                        int ind = 0;

                        while (bits_left) {
                            w_combined |= (!ind ? ((w & masks[0]) >> shift_rem) : ((w & masks[1]) << (UnitBits + sz[0])));
                            bits_left -= sz[ind];
                            masks[ind] >>= UnitBits;
                            ind = 1 - ind;
                        }

                        w = w_combined << shift_unit_bits;
                        return w;
                    }
                };

                template<int UnitBits> 
                struct endian_shift<stream_endian::little_unit_little_bit<UnitBits>> {
                    static word_type& to_msb(word_type &w, length_type shift) {
                        //shift to most significant bits according to endianness
                        w >>= shift;
                        return w;
                    }
                };

                template<typename Endianness>
                struct injector;

                template<int UnitBits>
                struct injector<stream_endian::big_unit_big_bit<UnitBits>> {
                    static void inject(word_type w, length_type word_seen, block_type &b, length_type &block_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (block_seen + word_seen <= block_bits) {
                            length_type last_word_ind = block_seen / word_bits;
                            length_type last_word_seen = block_seen % word_bits;
                            // Remove garbage
                            w &= left_bits<word_type>(word_seen);
                            b[last_word_ind] &= left_bits<word_type>(last_word_seen);

                            // Add significant word bits to block word
                            b[last_word_ind] |= (w >> last_word_seen);
                            // If we fall out of the block word, push the remainder of element to the next block word
                            if (last_word_seen + word_seen > word_bits)
                                b[last_word_ind + 1] = w << (word_bits - last_word_seen);

                            block_seen += word_seen;
                        }
                    }

                    static void inject(const block_type &b_src, length_type b_src_seen, block_type &b_dst, length_type &b_dst_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (b_src_seen + b_dst_seen <= block_bits) {
                            
                            for (length_type i = 0; i< (b_src_seen / word_bits); i++){
                                inject(b_src[i], word_bits, b_dst, b_dst_seen);
                            }

                            if(b_src_seen%word_bits){
                                inject(b_src[b_src_seen / word_bits], b_src_seen%word_bits, b_dst, b_dst_seen);
                            }

                        }
                    }
                };

                template<int UnitBits>
                struct injector<stream_endian::little_unit_big_bit<UnitBits>> {
                    static void inject(word_type w, length_type word_seen, block_type &b, length_type block_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (block_seen + word_seen <= block_bits) {
                            length_type last_word_ind = block_seen / word_bits;
                            length_type last_word_seen = block_seen % word_bits;
                            // Remove garbage
                            length_type w_rem = word_seen % UnitBits;
                            length_type w_unit_bits = word_seen - w_rem;
                            word_type mask = right_bits<word_type>(w_unit_bits) | (right_bits<word_type>(w_rem) << (w_unit_bits + UnitBits - w_rem)); 
                            w &= mask; 
                            length_type b_rem = last_word_seen % UnitBits;
                            length_type b_unit_bits = last_word_seen - b_rem;
                            mask = right_bits<word_type>(b_unit_bits) | (right_bits<word_type>(b_rem) << (b_unit_bits + UnitBits - b_rem));
                            b[last_word_ind] &= mask;   
                            // Split and combine parts of unit values
                            length_type sz[2] = {UnitBits - b_rem, b_rem};
                            word_type masks[2] = {right_bits<word_type>(UnitBits - b_rem) << b_rem, right_bits<word_type>(b_rem)};
                            length_type bw_space = word_bits - last_word_seen;
                            word_type w_split = 0;
                            std::size_t sz_ind = 0;
                              
                            while (bw_space && w) {
                                w_split |= (!sz_ind ? ((w & masks[0]) >> b_rem) : ((w & masks[1]) << (UnitBits + sz[0]))); 
                                bw_space -= sz[sz_ind];
                                w &= ~masks[sz_ind];
                                masks[sz_ind] <<= UnitBits;
                                sz_ind = 1 - sz_ind;
                            }
                            // Add significant word bits to block word
                            b[last_word_ind] |= w_split << b_unit_bits;
                            // If we fall out of the block word, push the remainder of element to the next block word
                            if (w) {
                                w >>= (word_bits - b_unit_bits - UnitBits);
                                w_split = 0;
                                masks[0] = right_bits<word_type>(UnitBits - b_rem) << b_rem; 
                                masks[1] = right_bits<word_type>(b_rem);

                                while (w) {
                                    w_split |= (!sz_ind ? ((w & masks[0]) >> b_rem) : ((w & masks[1]) << (UnitBits + sz[0]))); 
                                    w &= ~masks[sz_ind];
                                    masks[sz_ind] <<= UnitBits;
                                    sz_ind = 1 - sz_ind;
                                }

                                b[last_word_ind + 1] = w_split >> UnitBits;
                            }

                            block_seen += word_seen;
                        }
                    }

                    static void inject(const block_type &b_src, length_type b_src_seen, block_type &b_dst, length_type &b_dst_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (b_src_seen + b_dst_seen <= block_bits) {
                            
                            for (length_type i = 0; i< (b_src_seen / word_bits); i++){
                                inject(b_src[i], word_bits, b_dst, b_dst_seen);
                            }

                            inject(b_src[b_src_seen / word_bits + (b_src_seen%word_bits? 1 : 0)], b_src_seen%word_bits, b_dst, b_dst_seen);

                        }
                    }
                };

                template<int UnitBits>
                struct injector<stream_endian::big_unit_little_bit<UnitBits>> {
                    static void inject(word_type w, length_type word_seen, block_type &b, length_type block_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (block_seen + word_seen <= block_bits) {
                            length_type last_word_ind = block_seen / word_bits;
                            length_type last_word_seen = block_seen % word_bits;
                            // Remove garbage
                            length_type w_rem = word_seen % UnitBits;
                            length_type w_unit_bits = word_seen - w_rem;
                            word_type mask = left_bits<word_type>(w_unit_bits) | (left_bits<word_type>(w_rem) >> (w_unit_bits + UnitBits - w_rem)); 
                            w &= mask; 
                            length_type b_rem = last_word_seen % UnitBits;
                            length_type b_unit_bits = last_word_seen - b_rem;
                            mask = left_bits<word_type>(b_unit_bits) | (left_bits<word_type>(b_rem) >> (b_unit_bits + UnitBits - b_rem));
                            b[last_word_ind] &= mask; 
                            // Split and combine parts of unit values 
                            length_type sz[2] = {UnitBits - b_rem, b_rem};
                            word_type masks[2] = {left_bits<word_type>(UnitBits - b_rem) >> b_rem, left_bits<word_type>(b_rem)};
                            length_type bw_space = word_bits - last_word_seen;
                            word_type w_split = 0;
                            std::size_t sz_ind = 0;
                             
                            while (bw_space && w) {
                                w_split |= (!sz_ind ? ((w & masks[0]) << b_rem) : ((w & masks[1]) >> (UnitBits + sz[0]))); 
                                bw_space -= sz[sz_ind];
                                w &= ~masks[sz_ind];
                                masks[sz_ind] >>= UnitBits;
                                sz_ind = 1 - sz_ind;
                            }
                            // Add significant word bits to block word
                            b[last_word_ind] |= w_split >> b_unit_bits;
                            // If we fall out of the block word, push the remainder of element to the next block word
                            if (w) {
                                w <<= (word_bits - b_unit_bits - UnitBits);
                                w_split = 0;
                                masks[0] = left_bits<word_type>(UnitBits - b_rem) >> b_rem; 
                                masks[1] = left_bits<word_type>(b_rem);

                                while (w) {
                                    w_split |= (!sz_ind ? ((w & masks[0]) << b_rem) : ((w & masks[1]) >> (UnitBits + sz[0]))); 
                                    w &= ~masks[sz_ind];
                                    masks[sz_ind] >>= UnitBits;
                                    sz_ind = 1 - sz_ind;
                                }

                                b[last_word_ind + 1] = w_split << UnitBits;
                            }
                            block_seen += word_seen;
                        }
                    }

                    static void inject(const block_type &b_src, length_type b_src_seen, block_type &b_dst, length_type &b_dst_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (b_src_seen + b_dst_seen <= block_bits) {
                            
                            for (length_type i = 0; i< (b_src_seen / word_bits); i++){
                                inject(b_src[i], word_bits, b_dst, b_dst_seen);
                            }

                            inject(b_src[b_src_seen / word_bits + (b_src_seen%word_bits? 1 : 0)], b_src_seen%word_bits, b_dst, b_dst_seen);

                        }
                    }
                };

                template<int UnitBits>
                struct injector<stream_endian::little_unit_little_bit<UnitBits>> {
                    static void inject(word_type w, length_type word_seen, block_type &b, length_type block_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (block_seen + word_seen <= block_bits) {
                            length_type last_word_ind = block_seen / word_bits;
                            length_type last_word_seen = block_seen % word_bits;
                            // Remove garbage
                            w &= right_bits<word_type>(word_seen);
                            b[last_word_ind] &= right_bits<word_type>(last_word_seen);
                            // Add significant word bits to block word
                            b[last_word_ind] |= (w << last_word_seen);
                            // If we fall out of the block word, push the remainder of element to the next block word
                            if (last_word_seen + word_seen > word_bits)
                                b[last_word_ind + 1] = w >> (word_bits - last_word_seen);

                            block_seen += word_seen;
                        }
                    }

                    static void inject(const block_type &b_src, length_type b_src_seen, block_type &b_dst, length_type &b_dst_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (b_src_seen + b_dst_seen <= block_bits) {
                            
                            for (length_type i = 0; i< (b_src_seen / word_bits); i++){
                                inject(b_src[i], word_bits, b_dst, b_dst_seen);
                            }

                            inject(b_src[b_src_seen / word_bits + (b_src_seen%word_bits? 1 : 0)], b_src_seen%word_bits, b_dst, b_dst_seen);

                        }
                    }
                };

                    inline void process(const block_type &value, std::size_t value_seen) {

                        length_type cached_bits = (total_seen - value_seen) % block_bits;

                        if (cached_bits != 0) {
                            //If there are already any bits in the cache

                            length_type needed_to_fill_bits = block_bits - cached_bits;
                            length_type new_bits_to_append = (needed_to_fill_bits > value_seen)? value_seen : needed_to_fill_bits;

                            //injector<endian_type>::inject(value, new_bits_to_append, cache, cached_bits);
                            injector<endian_type>::inject(value, new_bits_to_append, cache, cached_bits);

                            if (cached_bits == block_bits) {
                                //If there are enough bits in the incoming value to fill the block

                                construction.process_block(cache, cached_bits);

                                if (value_seen > new_bits_to_append){
                                    //If there are some remaining bits in the incoming value - put them into the cache, which is now empty

                                    length_type added_words = new_bits_to_append/word_bits;



                                    length_type remaining_bits = value_seen - new_bits_to_append;

                                    length_type remaining_in_last_word_bits = (remaining_bits > (word_bits - new_bits_to_append%word_bits) )? word_bits - new_bits_to_append%word_bits : remaining_bits;

                                    remaining_bits -= remaining_in_last_word_bits;

                                    word_type first_word_shifted = value[added_words];

                                    endian_shift<endian_type>::to_msb(first_word_shifted, new_bits_to_append%word_bits);
                                    
                                    cached_bits = 0;

                                    injector<endian_type>::inject(first_word_shifted, remaining_in_last_word_bits, cache, cached_bits);

                                    for (length_type i = 0; i< (remaining_bits / word_bits); i++){
                                         injector<endian_type>::inject(value[added_words + 1 + i], word_bits, cache, cached_bits);
                                        
                                    }

                                    if(remaining_bits % word_bits){
                                        injector<endian_type>::inject(value[added_words + 1 + remaining_bits / word_bits + (remaining_bits % word_bits? 1 : 0)], remaining_bits % word_bits, cache, cached_bits);
                                    }

                                }

                            }

                        } else {
                            //If there are no bits in the cache
                            if (value_seen == block_bits) {
                                //The incoming value is a full block
                                construction.process_block(value, value_seen);
                            } else {
                                //The incoming value is not a full block
                                std::move(value.begin(), value.begin() + value_seen/word_bits + (value_seen%word_bits? 1 : 0), cache.begin());
                            }
                        }
                    }

                    inline void process(const word_type &value, std::size_t value_seen) {

                        length_type cached_bits = (total_seen - value_seen) % block_bits;

                        if (cached_bits != 0) {
                            length_type needed_to_fill_bits = block_bits - cached_bits;
                            length_type new_bits_to_append = (needed_to_fill_bits > value_seen)? value_seen : needed_to_fill_bits;

                            injector<endian_type>::inject(value, new_bits_to_append, cache, cached_bits);

                            if (cached_bits + new_bits_to_append == block_bits) {
                                //If there are enough bits in the incoming value to fill the block
                                construction.process_block(cache, cached_bits);

                                if (value_seen > new_bits_to_append){
                                    //If there are some remaining bits in the incoming value - put them into the cache, which is now empty
                                    cached_bits = 0;

                                    word_type word_shifted = value;

                                    injector<endian_type>::inject(endian_shift<endian_type>::to_msb(word_shifted, new_bits_to_append), value_seen - new_bits_to_append, cache, cached_bits);
                                }

                            }

                        } else {
                            cache[0] = value;
                        }
                    }

                    length_type total_seen;
                    block_type cache;
                    construction_type construction;
                };
            }    // namespace impl

            namespace tag {
                template<typename Hash>
                struct hash : boost::accumulators::depends_on<bits_count> {
                    typedef Hash hash_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::hash_impl<Hash>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Hash, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::hash<Hash>>::type::result_type
                    hash(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::hash<Hash>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_BLOCK_HPP