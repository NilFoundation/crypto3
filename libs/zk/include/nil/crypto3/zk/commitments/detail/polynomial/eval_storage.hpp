//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLACEHOLDER_EVAL_STORAGE_HPP
#define CRYPTO3_ZK_PLACEHOLDER_EVAL_STORAGE_HPP

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                template<typename FieldType>
                class eval_storage{
                private:
                    std::map<std::size_t, std::vector<std::vector<typename FieldType::value_type>>> z;
                public:
                    using field_type = FieldType;
                    
                    bool operator==(const eval_storage& other) const{
                        return this->z == other.z;
                    }
                    eval_storage &operator=(const eval_storage& other){
                        this->z = other.z;
                        return *this;
                    }
                    std::vector<std::size_t> get_batches() const{
                        std::vector<std::size_t> batches;

                        for(auto it = z.begin(); it != z.end(); ++it){
                            batches.push_back(it->first);
                        }
                        return batches;
                    }
                    std::map<std::size_t, std::size_t> get_batch_info() const{
                        std::map<std::size_t, std::size_t> batch_info;

                        for(auto it = z.begin(); it != z.end(); ++it){
                            batch_info[it->first] = it->second.size();
                        }
                        return batch_info;
                    }
                    std::size_t get_batches_num() const{
                        return z.size();
                    }
                    std::size_t get_batch_size(std::size_t batch_id) const{
                        return z.at(batch_id).size();
                    }
                    std::size_t get_poly_points_number(std::size_t batch_id, std::size_t poly_id) const{
                        return z.at(batch_id)[poly_id].size();
                    }
                    const std::vector<std::vector<typename FieldType::value_type>> &get(std::size_t batch_id) const{
                        return z.at(batch_id);
                    }
                    const std::vector<typename FieldType::value_type> &get(std::size_t batch_id, std::size_t poly_id) const{
                        return z.at(batch_id)[poly_id];
                    }
                    const typename FieldType::value_type &get(std::size_t batch_id, std::size_t poly_id, size_t point_id) const{
                        return z.at(batch_id)[poly_id][point_id];
                    }

                    void set_batch_size(std::size_t batch_id, std::size_t batch_size){
                        z[batch_id] = {};
                        z[batch_id].resize(batch_size);
                    }
                    void set_poly_points_number(std::size_t batch_id, std::size_t poly_id, std::size_t points_number){
                        z[batch_id][poly_id] = {};
                        z[batch_id][poly_id].resize(points_number);
                    }
                    void set(std::size_t batch_id, std::size_t poly_id, size_t point_id, const typename FieldType::value_type &value){
                        z[batch_id][poly_id][point_id] = value;
                    }
                };
            }
        }
    }
}
#endif