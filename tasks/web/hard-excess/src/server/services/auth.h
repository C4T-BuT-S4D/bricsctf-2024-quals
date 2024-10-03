#ifndef _SERVICES_AUTH_H
#define _SERVICES_AUTH_H

#include <string>
#include <stdexcept>

#include <models/author.h>
#include <storage/storage.h>


namespace Excess::Services {

    class InvalidCredentialsError final : public std::runtime_error {
    public:
        InvalidCredentialsError(const std::string& error)
            : std::runtime_error(error) { }
    };

    class Auth final {
    public:
        Auth(Storage::IStorage& storage);
        ~Auth();

        Models::Author Login(const std::string& name, const std::string& password);
        Models::Author Register(const std::string& name, const std::string& password);

    private:
        Storage::IStorage& Storage;
    };

}

#endif /* _SERVICES_AUTH_H */
