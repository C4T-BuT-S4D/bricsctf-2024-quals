#ifndef _SERVICES_SESSION_H
#define _SERVICES_SESSION_H

#include <string>
#include <stdexcept>


namespace Excess::Services {

    class InvalidSessionError final : public std::runtime_error {
    public:
        InvalidSessionError(const std::string& error)
            : std::runtime_error(error) { }
    };

    class Session final {
    public:
        Session(const std::string& keyfile);
        ~Session();

        std::string Serialize(const std::string& data);
        std::string Deserialize(const std::string& session);

    private:
        const std::string Key;
    };

}

#endif /* _SERVICES_SESSION_H */
