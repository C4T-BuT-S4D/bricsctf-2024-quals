#ifndef _DROPPER_H
#define _DROPPER_H

#include <vector>
/* #include <thread> */
#include <experimental/filesystem>

class Dropper {

    public:
        Dropper();
        ~Dropper();

        void Drop();
        void Wait();

        std::experimental::filesystem::path GetRuntimePath();

    private:
        /* std::vector<std::thread> Threads; */

        std::experimental::filesystem::path RuntimeDirectory;

};

#endif /* _DROPPER_H */
