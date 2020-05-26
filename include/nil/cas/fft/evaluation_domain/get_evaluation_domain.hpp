//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CAS_FFT_GET_EVALUATION_DOMAIN_HPP
#define CAS_FFT_GET_EVALUATION_DOMAIN_HPP

#include <memory>

#include <nil/cas/fft/evaluation_domain/evaluation_domain.hpp>

#include <nil/cas/fft/evaluation_domain/domains/arithmetic_sequence_domain.hpp>
#include <nil/cas/fft/evaluation_domain/domains/basic_radix2_domain.hpp>
#include <nil/cas/fft/evaluation_domain/domains/extended_radix2_domain.hpp>
#include <nil/cas/fft/evaluation_domain/domains/geometric_sequence_domain.hpp>
#include <nil/cas/fft/evaluation_domain/domains/step_radix2_domain.hpp>
#include <nil/cas/fft/evaluation_domain/evaluation_domain.hpp>

#include <nil/cas/fft/tools/exceptions.hpp>

namespace nil {
    namespace cas {
        namespace fft {

            /*!
            @brief
             A convenience method for choosing an evaluation domain
             Returns an evaluation domain object in which the domain S has size
             |S| >= min_size.
             The function chooses from different supported domains, depending on min_size.
            */

            template<typename FieldT>
            std::shared_ptr<evaluation_domain<FieldT>> get_evaluation_domain(const size_t min_size) {
                std::shared_ptr<evaluation_domain<FieldT>> result;

                const size_t big = 1ul << (ff::log2(min_size) - 1);
                const size_t small = min_size - big;
                const size_t rounded_small = (1ul << ff::log2(small));

                try {
                    result.reset(new basic_radix2_domain<FieldT>(min_size));
                } catch (...) {
                    try {
                        result.reset(new extended_radix2_domain<FieldT>(min_size));
                    } catch (...) {
                        try {
                            result.reset(new step_radix2_domain<FieldT>(min_size));
                        } catch (...) {
                            try {
                                result.reset(new basic_radix2_domain<FieldT>(big + rounded_small));
                            } catch (...) {
                                try {
                                    result.reset(new extended_radix2_domain<FieldT>(big + rounded_small));
                                } catch (...) {
                                    try {
                                        result.reset(new step_radix2_domain<FieldT>(big + rounded_small));
                                    } catch (...) {
                                        try {
                                            result.reset(new geometric_sequence_domain<FieldT>(min_size));
                                        } catch (...) {
                                            try {
                                                result.reset(new arithmetic_sequence_domain<FieldT>(min_size));
                                            } catch (...) {
                                                throw DomainSizeException("get_evaluation_domain: no matching domain");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                return result;
            }

        }    // namespace fft
    }        // namespace cas
}    // namespace nil

#endif    // CAS_FFT_GET_EVALUATION_DOMAIN_HPP
