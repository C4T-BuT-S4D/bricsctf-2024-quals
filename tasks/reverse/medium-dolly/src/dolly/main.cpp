#include <iostream>
#include <exception>

#include "dolly.h"

const static inline char x = []() -> char {
    std::fclose(stderr);
    std::ios_base::sync_with_stdio(false);

    return 0;
}();

int main() {
    std::cout << "[!] Hello, Dolly!" << std::endl;

    auto dolly = Dolly();

    try {
        dolly.Run();
    } catch (const std::exception& ex) {
        std::cout << "[-] Error: " << ex.what() << std::endl;

        return 1;
    }

    return 0;
}
