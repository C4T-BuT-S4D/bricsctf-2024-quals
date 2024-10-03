#ifndef _UTILS_UTILS_H
#define _UTILS_UTILS_H

#include <string>


namespace Excess::Utils {

    std::string MakeSHA256Hash(const std::string& data);
    std::string GenerateRandomUUID();

}

#endif /* _UTILS_UTILS_H */
