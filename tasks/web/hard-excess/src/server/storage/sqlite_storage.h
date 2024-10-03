#ifndef _STORAGE_SQLITE_STORAGE_H
#define _STORAGE_SQLITE_STORAGE_H

#include <map>
#include <string>
#include <vector>
#include <optional>

#include <models/author.h>
#include <models/message.h>
#include <storage/storage.h>


namespace Excess::Storage {

    using ResultRow = std::map<std::string, std::string>;
    using ResultRows = std::vector<ResultRow>;
    using SqliteContext = void *;

    class SqliteStorage final : public IStorage {
    public:
        SqliteStorage(const std::string& filename);
        ~SqliteStorage();

        void CreateAuthor(const Models::Author& author);
        std::optional<Models::Author> GetAuthorByName(const std::string& name);

        void CreateMessage(const Models::Message& message);
        std::optional<Models::Message> GetMessageById(const std::string& id);

        std::vector<Models::Message> FindMessagesByAuthor(const std::string& author);

    private:
        ResultRows ExecuteSql(const std::string& sql, const std::vector<std::string>& arguments);

        SqliteContext Context = nullptr;
    };

}

#endif /* _STORAGE_SQLITE_STORAGE_H */
