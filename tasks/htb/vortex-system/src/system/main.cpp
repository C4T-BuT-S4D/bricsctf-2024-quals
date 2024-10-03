#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <random>

#include "aes.hpp"

#define KEY_SIZE 16

uint8_t key[KEY_SIZE];

auto files = {"/etc/shadow", "/root/.profile", "/root/.bashrc"};
uint64_t timestamp = time(0);

std::map<int, int> table = {{0, 213},{1, 162},{2, 229},{3, 199},{4, 128},{5, 69},{6, 226},{7, 136},{8, 148},{9, 125},{10, 133},{11, 64},{12, 218},{13, 99},{14, 10},{15, 195},{16, 151},{17, 70},{18, 98},{19, 255},{20, 216},{21, 237},{22, 130},{23, 125},{24, 26},{25, 146},{26, 177},{27, 94},{28, 238},{29, 72},{30, 175},{31, 82},{32, 146},{33, 210},{34, 75},{35, 44},{36, 97},{37, 90},{38, 241},{39, 114},{40, 109},{41, 4},{42, 110},{43, 190},{44, 108},{45, 245},{46, 16},{47, 18},{48, 58},{49, 25},{50, 235},{51, 76},{52, 138},{53, 57},{54, 161},{55, 120},{56, 60},{57, 171},{58, 203},{59, 119},{60, 171},{61, 35},{62, 68},{63, 102},{64, 122},{65, 162},{66, 71},{67, 93},{68, 97},{69, 137},{70, 102},{71, 169},{72, 128},{73, 88},{74, 138},{75, 49},{76, 31},{77, 175},{78, 238},{79, 19},{80, 188},{81, 141},{82, 18},{83, 150},{84, 251},{85, 179},{86, 69},{87, 20},{88, 87},{89, 194},{90, 4},{91, 29},{92, 5},{93, 210},{94, 199},{95, 228},{96, 183},{97, 140},{98, 178},{99, 4},{100, 186},{101, 223},{102, 69},{103, 122},{104, 245},{105, 148},{106, 146},{107, 212},{108, 83},{109, 213},{110, 160},{111, 178},{112, 212},{113, 80},{114, 109},{115, 256},{116, 101},{117, 152},{118, 165},{119, 251},{120, 226},{121, 173},{122, 80},{123, 230},{124, 221},{125, 25},{126, 151},{127, 164},{128, 26},{129, 19},{130, 158},{131, 35},{132, 76},{133, 134},{134, 256},{135, 118},{136, 226},{137, 109},{138, 91},{139, 39},{140, 172},{141, 124},{142, 43},{143, 208},{144, 59},{145, 98},{146, 30},{147, 173},{148, 153},{149, 14},{150, 119},{151, 74},{152, 216},{153, 96},{154, 29},{155, 130},{156, 35},{157, 6},{158, 45},{159, 161},{160, 44},{161, 47},{162, 224},{163, 4},{164, 241},{165, 168},{166, 97},{167, 238},{168, 138},{169, 207},{170, 2},{171, 30},{172, 252},{173, 194},{174, 47},{175, 174},{176, 81},{177, 224},{178, 147},{179, 9},{180, 85},{181, 97},{182, 48},{183, 173},{184, 50},{185, 1},{186, 104},{187, 193},{188, 60},{189, 29},{190, 42},{191, 212},{192, 207},{193, 254},{194, 63},{195, 188},{196, 58},{197, 187},{198, 201},{199, 66},{200, 35},{201, 169},{202, 86},{203, 174},{204, 189},{205, 63},{206, 207},{207, 72},{208, 90},{209, 170},{210, 162},{211, 58},{212, 179},{213, 62},{214, 223},{215, 210},{216, 248},{217, 133},{218, 75},{219, 168},{220, 10},{221, 105},{222, 88},{223, 26},{224, 164},{225, 90},{226, 42},{227, 24},{228, 33},{229, 158},{230, 194},{231, 223},{232, 232},{233, 115},{234, 160},{235, 153},{236, 41},{237, 175},{238, 236},{239, 82},{240, 154},{241, 117},{242, 103},{243, 112},{244, 110},{245, 197},{246, 160},{247, 219},{248, 180},{249, 163},{250, 246},{251, 115},{252, 250},{253, 44},{254, 121},{255, 13}};

void generate_key() {
    for (auto i = 0; i < KEY_SIZE; ++i) {
        key[i] = i;
    }

    std::vector<uint8_t> t_v(key, key + sizeof(key) / sizeof(key[0]));
    std::reverse(t_v.begin(), t_v.end());

    std::mt19937 rnd(timestamp);

    for (auto i = 0; i < KEY_SIZE; ++i) {
        t_v[i] ^= (rnd() % 256);
    }

    for (auto i = 0; i < KEY_SIZE; ++i) {
        key[i] = table[t_v[i]];
    }
}

void encrypt_backup(std::string filename) {
    const std::vector<unsigned char> ekey(key, key + sizeof(key) / sizeof(key[0]));
    unsigned char iv[16];
    std::ifstream rnd("/dev/urandom");
    rnd.read((char*)iv, 16);
    rnd.close();

    std::ifstream input_file(filename, std::ios::binary | std::ios::ate);
    size_t file_size = input_file.tellg();
    input_file.seekg(0);
    uint8_t* data = new uint8_t[file_size];
    input_file.read((char*)data, file_size);
    input_file.close();

    const unsigned long encrypted_size = plusaes::get_padded_encrypted_size(file_size);
    std::vector<unsigned char> encrypted(encrypted_size);
    
    plusaes::encrypt_cbc((unsigned char*)data, file_size, &ekey[0], KEY_SIZE, &iv, &encrypted[0], encrypted.size(), true);

    std::ofstream out_file(filename);
    out_file.write((const char*)encrypted.data(), encrypted.size());
    out_file.write((const char*)iv, 16);
    out_file.close();
}

int main() {

    // check that files is existing
    for (auto filepath : files) {
        if (std::filesystem::exists(filepath)) {
            std::ifstream t(filepath);
            if (t.is_open()) {
                continue;;
            } else {
                std::cout << "Access denied!" << std::endl;
            }
        } else {
            continue;
        }
    }

    std::string backup_filename("backup_" + std::to_string(timestamp) + ".zip");

    // archivate files
    std::string archive_cmd("zip " + backup_filename + " ");
    for (auto filepath : files) {
        archive_cmd += filepath;
        archive_cmd += " ";
    }

    system(archive_cmd.c_str());

    // generate key (machine fingerprint)
    generate_key();
    
    // encrypt archive
    encrypt_backup(backup_filename);
    // store backup
    return 0;
}