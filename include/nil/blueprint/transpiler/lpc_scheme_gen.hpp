#ifndef __LPC_SCHEME_GEN_HPP__
#define __LPC_SCHEME_GEN_HPP__

#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>

#include <boost/algorithm/string.hpp> 
#include <nil/blueprint/transpiler/util.hpp>

namespace nil {
    namespace blueprint {
        template <typename PlaceholderParams>
        using common_data_type = typename nil::crypto3::zk::snark::placeholder_public_preprocessor<
            typename PlaceholderParams::field_type, 
            PlaceholderParams
        >::preprocessed_data_type::common_data_type;
        
        std::string rot_string (int j){
            if(j == 0) return "xi"; else 
            if(j == 1 ) return "mulmod(xi, omega, modulus)"; else 
            if(j == -1) return "mulmod(xi, inversed_omega, modulus)"; else 
            if(j > 0) return "mulmod(xi, field.pow_small(omega, " + to_string(j) + ", modulus), modulus)"; else
            if(j < 0) return "mulmod(xi, field.pow_small(inversed_omega, " + to_string(-j) + ", modulus), modulus)";
            return "";
        }


        template<typename PlaceholderParams> 
        void commitment_scheme_replaces(
            transpiler_replacements& replacements,
            const common_data_type<PlaceholderParams> &common_data,
            const typename PlaceholderParams::commitment_scheme_type& lpc_scheme,
            std::size_t permutation_size,
            bool use_lookups
        ){
            std::set<std::string> unique_points;
            std::vector<std::string> points;

            for(std::size_t i = 0; i < permutation_size*2; i++){
                points.push_back(rot_string(0) + "& _etha& ");
            }
            unique_points.insert(rot_string(0) + "& _etha& ");
            points.push_back(rot_string(0) + "& "+ rot_string(1) + "& _etha& ");
            points.push_back(rot_string(0) + "& "+ rot_string(1) + "& _etha& ");
            unique_points.insert(rot_string(0) + "& "+ rot_string(1) + "& _etha& ");

            for(std::size_t i = 0; i < PlaceholderParams::constant_columns; i++){
                std::stringstream str;
                for(auto j:common_data.columns_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns]){
                    str << rot_string(j) << "& ";
                }
                str << "_etha& ";
                unique_points.insert(str.str());
                points.push_back(str.str());
            }

            for(std::size_t i = 0; i < PlaceholderParams::selector_columns; i++){
                std::stringstream str;
                for(auto j:common_data.columns_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns + PlaceholderParams::constant_columns]){
                    str << rot_string(j) << "& ";
                }
                str << "_etha& ";
                unique_points.insert(str.str());
                points.push_back(str.str());
            }

            for(std::size_t i = 0; i < PlaceholderParams::witness_columns; i++){
                std::stringstream str;
                for(auto j:common_data.columns_rotations[i]){
                    str << rot_string(j) << "& ";
                }
                unique_points.insert(str.str());
                points.push_back(str.str());
            }

            for(std::size_t i = 0; i < PlaceholderParams::public_input_columns; i++){
                std::stringstream str;
                for(auto j:common_data.columns_rotations[i + PlaceholderParams::witness_columns]){
                    str << rot_string(j) << "& ";
                }
                unique_points.insert(str.str());
                points.push_back(str.str());
            }

            unique_points.insert(rot_string(0) + "& " + rot_string(1) + "& ");//Permutation
            unique_points.insert(rot_string(0) + "& ");// Quotient
            if(use_lookups)
                unique_points.insert(rot_string(0) + "& " + rot_string(1) + "& " + rot_string(common_data.usable_rows_amount) + "& "); // Lookups

            std::size_t permutation_point_id;
            std::size_t quotient_point_id;
            std::size_t lookup_point_id;
            std::size_t j = 0;
            for( const auto &unique_point:unique_points){
                if( unique_point == rot_string(0) + "& ") quotient_point_id = j;
                if( unique_point == rot_string(0) + "& " + rot_string(1) + "& " + rot_string(common_data.usable_rows_amount) + "& " ) lookup_point_id = j;
                if( unique_point == rot_string(0) + "& " + rot_string(1) + "& " ) permutation_point_id = j;
                std::cout << unique_point << std::endl;
                j++;
            }

            std::stringstream points_ids;
            for(std::size_t i = 0; i < points.size(); i++){
                std::size_t j = 0;
                for(const auto &unique_point:unique_points){
                    if(points[i] == unique_point){
                        points_ids << std::hex << std::setw(2) << std::setfill('0') << j;
                        break;
                    }
                    j++;
                }
            }
            std::cout << points_ids.str() << std::endl;

            std::stringstream points_initializer;
            std::size_t i = 0;
            for(const auto& point: unique_points){
                points_initializer << "\t\t result[" << i << "] = new uint256[](" << std::count(point.begin(), point.end(), '&') << ");" << std::endl;
                std::size_t prev = 0;
                std::size_t found = point.find("& ");
                std::size_t j = 0;
                while (found!=std::string::npos){
                    points_initializer << "\t\t result[" << i << "][" << j << "] = " << point.substr(prev, found-prev) << ";" << std::endl;
                    prev = found + 2;
                    found = point.find("& ",prev);
                    j++;
                }
                i++;
            }
            std::cout << "points_initializer = " << points_initializer.str() << std::endl;
            
            auto fri_params = lpc_scheme.get_fri_params();
            replacements["$R$"] = to_string(fri_params.r);
            replacements["$LAMBDA$"] = to_string(PlaceholderParams::commitment_scheme_type::fri_type::lambda);
            replacements["$D0_SIZE$"] = to_string(fri_params.D[0]->m);
            replacements["$D0_OMEGA$"] = to_string(fri_params.D[0]->get_domain_element(1));
            replacements["$MAX_DEGREE$"] = to_string(fri_params.max_degree);
            replacements["$UNIQUE_POINTS$"] = to_string(unique_points.size());
            replacements["$DIFFERENT_POINTS$"] = to_string(unique_points.size());
            replacements["$PERMUTATION_POINTS_ID$"] = to_string(permutation_point_id);
            replacements["$QUOTIENT_POINTS_ID$"] = to_string(quotient_point_id);
            replacements["$LOOKUP_POINTS_ID$"] = to_string(lookup_point_id);
            replacements["$POINTS_IDS$"] = points_ids.str();
            replacements["$POINTS_INITIALIZATION$"] = points_initializer.str();
            if( PlaceholderParams::commitment_scheme_type::fri_type::use_grinding){
                replacements["$GRINDING_CHECK$"] = modular_commitment_grinding_check_template;
            } else {
                replacements["$GRINDING_CHECK$"] = "";
            } 
        }

        template<typename PlaceholderParams>
        std::string generate_commitment_scheme_code(
            const common_data_type<PlaceholderParams> &common_data,
            const typename PlaceholderParams::commitment_scheme_type& lpc_scheme
        ){
            auto fri_params = lpc_scheme.get_fri_params();
            BOOST_ASSERT(fri_params.step_list.size() == fri_params.r);
            for(std::size_t i = 0; i < fri_params.step_list.size(); i++){
                BOOST_ASSERT(fri_params.step_list[i] == 1);
            }
            std::stringstream out;

            return out.str();
        }
    }
}

#endif //__MODULAR_CONTRACTS_TEMPLATES_HPP__