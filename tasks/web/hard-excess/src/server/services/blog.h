#ifndef _SERVICES_BLOG_H
#define _SERVICES_BLOG_H

#include <vector>
#include <string>
#include <stdexcept>

#include <models/message.h>
#include <storage/storage.h>


namespace Excess::Services {

    class MessageNotFoundError final : public std::runtime_error {
    public:
        MessageNotFoundError(const std::string& error)
            : std::runtime_error(error) { }
    };

    class Blog final {
    public:
        Blog(Storage::IStorage& storage);
        ~Blog();

        Models::Message CreateMessage(
            const std::string& author,
            const std::string& title,
            const std::string& content
        );
        Models::Message GetMessage(
            const std::string& id
        );
        std::vector<Models::Message> GetAllMessages(const std::string& author);

    private:
        Storage::IStorage& Storage;
    };

}

#endif /* _SERVICES_BLOG_H */
