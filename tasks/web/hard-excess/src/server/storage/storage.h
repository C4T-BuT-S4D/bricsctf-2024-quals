#ifndef _STORAGE_STORAGE_H
#define _STORAGE_STORAGE_H

#include <string>
#include <vector>
#include <optional>
#include <stdexcept>

#include <models/author.h>
#include <models/message.h>


namespace Excess::Storage {

    class AuthorAlreadyExistsError final : public std::runtime_error {
    public:
        AuthorAlreadyExistsError(const std::string& error)
            : std::runtime_error(error) { }
    };

    class MessageAlreadyExistsError final : public std::runtime_error {
    public:
        MessageAlreadyExistsError(const std::string& error)
            : std::runtime_error(error) { }
    };

    class IStorage {
    public:
        virtual ~IStorage() { }

        virtual void CreateAuthor(const Models::Author& author) = 0;
        virtual std::optional<Models::Author> GetAuthorByName(const std::string& name) = 0;

        virtual void CreateMessage(const Models::Message& message) = 0;
        virtual std::optional<Models::Message> GetMessageById(const std::string& id) = 0;

        virtual std::vector<Models::Message> FindMessagesByAuthor(const std::string& author) = 0;
    };

}

#endif /* _STORAGE_STORAGE_H */
