//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Aleksey Moskvin <zerg1996@yandex.ru>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef MARSHALLING_ACCUMULATORS_MARSHALLING_HPP
#define MARSHALLING_ACCUMULATORS_MARSHALLING_HPP

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>
#include <boost/accumulators/statistics/count.hpp>

#include <boost/container/static_vector.hpp>

#include <nil/marshalling/accumulators/parameters/buffer_length.hpp>
#include <nil/marshalling/detail/type_traits.hpp>

namespace nil {
    namespace marshalling {
        namespace accumulators {
            namespace impl {
                template<typename TypeToProcess>
                struct marshalling_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef TypeToProcess field_type;
                    
                public:
                    typedef field_type result_type;

                    // The constructor takes an argument pack.
                    marshalling_impl(boost::accumulators::dont_care) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        status_type marshalling_status = resolve_type(args[boost::accumulators::sample],
                                     args[::nil::marshalling::accumulators::buffer_length | std::size_t()]);
                    }

                    inline field_type result(boost::accumulators::dont_care) const {
                        return processed_field;
                    }

                protected:
                    // for byte iterator only,
                    // because byte iterator can be directly processed
                    template<typename InputIterator>
                    inline typename std::enable_if<
                                        marshalling::detail::is_iterator<InputIterator>::value && 
                                        (std::is_same<std::uint8_t, typename std::iterator_traits<InputIterator>::value_type>::value ||
                                         std::is_same<std::int8_t, typename std::iterator_traits<InputIterator>::value_type>::value), 
                                    status_type>::type
                     resolve_type(InputIterator first, std::size_t buf_len) {

                        return processed_field.read(first, buf_len);
                    }

                    template<typename InputIterator>
                    inline typename std::enable_if<
                                        marshalling::detail::is_iterator<InputIterator>::value && 
                                        !(std::is_same<std::uint8_t, typename std::iterator_traits<InputIterator>::value_type>::value ||
                                         std::is_same<std::int8_t, typename std::iterator_traits<InputIterator>::value_type>::value) &&
                                        marshalling::detail::is_marshalling_field<typename std::iterator_traits<InputIterator>::value_type>::value, 
                                    status_type>::type
                    resolve_type(const InputIterator other_field_begin, std::size_t buf_len) {

                        using type_to_process = typename std::iterator_traits<InputIterator>::value_type;
                        status_type final_status = status_type::success;

                        // hardcoded to be little-endian by default. If the user wants to process a container
                        // in other order (for example, in reverse or by skipping some first elements), he should
                        // define type of the container using array_list and process it not by iterator, but by 
                        // processing it as marshaling type (at the moment it is the resolve_type function under 
                        // this one).
                        using marhsalling_array_type = 
                            types::array_list<
                                marshalling::field_type<nil::marshalling::option::little_endian>,
                                type_to_process>;
                        using nil_marshalling_array_internal_sequential_container_type = typename marhsalling_array_type::value_type;

                        nil_marshalling_array_internal_sequential_container_type sequentional_container;

                        std::copy (other_field_begin, other_field_begin + buf_len, sequentional_container.begin());
                        
                        marhsalling_array_type input_data(sequentional_container);

                        return resolve_type(input_data, 1);
                    }

                    // Probably there is a way to directly convert between marshalling fields
                    template<typename OtherFieldType>
                    inline typename std::enable_if<
                                    !marshalling::detail::is_iterator<OtherFieldType>::value && 
                                    marshalling::detail::is_marshalling_field<OtherFieldType>::value, 
                                    status_type>::type
                    resolve_type(const OtherFieldType other_field, ...) {

                        std::vector<std::uint8_t> buffer (other_field.length());
                        typename std::vector<std::uint8_t>::iterator buffer_begin = buffer.begin();
                        status_type write_status = 
                            other_field.write(buffer_begin, buffer.size());



                        status_type read_status = 
                            processed_field.read(buffer_begin, buffer.size());

                        return read_status | write_status;
                    }

                    field_type processed_field;
                };
            }    // namespace impl

            namespace tag {
                template<typename TypeToProcess>
                struct marshalling : boost::accumulators::depends_on<> {
                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::marshalling_impl<TypeToProcess>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename TypeToProcess, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::marshalling<TypeToProcess>>::type::result_type
                    marshalling(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::marshalling<TypeToProcess>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_ACCUMULATORS_MARSHALLING_HPP
