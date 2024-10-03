#include <storage/sqlite_storage.h>

#include <optional>
#include <stdexcept>

#include <sqlite3.h>

using namespace std::string_literals;

using namespace Excess;
using namespace Excess::Storage;


class SqliteConflictError final : public std::exception { };

Models::Author ResultRowToAuthor(const ResultRow& row) {
    try {
        auto author = Models::Author(
            row.at("name"),
            row.at("password")
        );

        if (author.GetName().empty()) {
            throw std::runtime_error("got author with incorrect name"s);
        }

        return author;
    } catch (const std::out_of_range&) {
        throw std::runtime_error("failed to convert row to author"s);
    }
}

Models::Message ResultRowToMessage(const ResultRow& row) {
    try {
        auto message = Models::Message(
            row.at("id"),
            row.at("author"),
            row.at("title"),
            row.at("content")
        );

        if (message.GetId().empty()) {
            throw std::runtime_error("got message with incorrect id"s);
        }

        return message;
    } catch (const std::out_of_range&) {
        throw std::runtime_error("failed to convert row to message"s);
    }
}

SqliteStorage::SqliteStorage(const std::string& filename) {
    sqlite3 *context = nullptr;

    auto result = sqlite3_open(filename.c_str(), &context);

    if (result != 0) {
        throw std::runtime_error(
            "failed to open sqlite3 database: "s + sqlite3_errmsg(context)
        );
    }

    Context = context;
}

SqliteStorage::~SqliteStorage() {
    if (Context != nullptr) {
        auto context = reinterpret_cast<sqlite3*>(Context);
        sqlite3_close_v2(context);

        Context = nullptr;
    }
}

void SqliteStorage::CreateAuthor(const Models::Author& author) {
    auto sql = "insert into authors (name, password) values (?, ?)"s;

    try {
        ExecuteSql(sql, { author.GetName(), author.GetPassword() });
    } catch (const SqliteConflictError&) {
        throw AuthorAlreadyExistsError("author " + author.GetName() + " already exists"s);
    }
}

std::optional<Models::Author> SqliteStorage::GetAuthorByName(const std::string& name) {
    auto sql = "select name, password from authors where name = ?"s;

    auto result = ExecuteSql(sql, { name });

    if (result.size() == 0) {
        return { };
    }

    return ResultRowToAuthor(result[0]);
}

void SqliteStorage::CreateMessage(const Models::Message& message) {
    auto sql = "insert into messages (id, author, title, content) values (?, ?, ?, ?)"s;

    try {
        ExecuteSql(
            sql, { message.GetId(), message.GetAuthor(), message.GetTitle(), message.GetContent() }
        );
    } catch (const SqliteConflictError&) {
        throw MessageAlreadyExistsError("message " + message.GetId() + "already exists"s);
    }
}

std::optional<Models::Message> SqliteStorage::GetMessageById(const std::string& id) {
    auto sql = "select id, author, title, content from messages where id = ?"s;

    auto result = ExecuteSql(sql, { id });

    if (result.size() == 0) {
        return { };
    }

    return ResultRowToMessage(result[0]);
}

std::vector<Models::Message> SqliteStorage::FindMessagesByAuthor(const std::string& author) {
    auto sql = "select id, author, title, content from messages where author = ?"s;

    auto result = ExecuteSql(sql, { author });

    std::vector<Models::Message> messages;

    for (auto& row : result) {
        messages.emplace_back(ResultRowToMessage(row));
    }

    return messages;
}

ResultRows SqliteStorage::ExecuteSql(
    const std::string& sql,
    const std::vector<std::string>& arguments
) {
    auto context = reinterpret_cast<sqlite3*>(Context);

    int result;

    sqlite3_stmt *stmt = nullptr;
    result = sqlite3_prepare_v2(context, sql.c_str(), sql.size(), &stmt, nullptr);

    if (result != SQLITE_OK) {
        throw std::runtime_error(
            "failed to prepare sqlite3 statement: "s + sqlite3_errmsg(context)
        );
    }

    for (auto i = 0; i < arguments.size(); i += 1) {
        auto argument = arguments[i];
        result = sqlite3_bind_text(stmt, i + 1, argument.c_str(), argument.size(), SQLITE_TRANSIENT);

        if (result != SQLITE_OK) {
            sqlite3_finalize(stmt);

            throw std::runtime_error(
                "failed to bind text to sqlite3 statement: "s + sqlite3_errmsg(context)
            );
        }
    }

    std::vector<std::string> columns;

    for (auto i = 0; i < sqlite3_column_count(stmt); i += 1) {
        columns.emplace_back(sqlite3_column_name(stmt, i));
    }

    ResultRows rows;

    while (true) {
        result = sqlite3_step(stmt);

        if (result == SQLITE_DONE || result == SQLITE_OK) {
            break;
        } else if (result == SQLITE_CONSTRAINT) {
            sqlite3_finalize(stmt);

            throw SqliteConflictError();
        } else if (result != SQLITE_ROW) {
            sqlite3_finalize(stmt);

            throw std::runtime_error(
                "failed to execute sqlite3 statement: "s + sqlite3_errmsg(context)
            );
        }

        ResultRow row;

        for (auto i = 0; i < columns.size(); i += 1) {
            row[columns[i]] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
        }

        rows.push_back(row);
    }

    sqlite3_finalize(stmt);

    return rows;
}
