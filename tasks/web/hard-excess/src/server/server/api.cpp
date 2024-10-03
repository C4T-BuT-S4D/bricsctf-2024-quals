#include <server/api.h>

#include <map>
#include <sstream>

#include <server/render.h>
#include <storage/storage.h>

#include <third_party/json.h>

using namespace std::string_literals;

using namespace Excess;
using namespace Excess::Server;


const auto JsonContentType = "application/json"s;
const auto SessionCookiePrefix = "session="s;

bool ValidateInput(const std::string& input) {
    if (input.empty()) {
        return false;
    }

    if (input.find('\x00') != std::string::npos) {
        return false;
    }

    return true;
}

std::map<std::string, std::string> ParseFormBody(const std::string& body) {
    std::map<std::string, std::string> result;

    auto previous = 0;

    while (previous < body.size()) {
        auto index = body.find('&', previous);

        if (index == std::string::npos) {
            index = body.size();
        }

        auto part = body.substr(previous, index - previous);
        previous = index + 1;

        auto delim = part.find('=');

        if (delim == std::string::npos) {
            continue;
        }

        auto key = part.substr(0, delim);
        auto value = part.substr(delim + 1);

        result[key] = value;
    }

    return result;
}

Api::Api(Services::Auth& auth, Services::Blog& blog, Services::Session& session)
    : AuthService(auth)
    , BlogService(blog)
    , SessionService(session) { }

Api::~Api() { }

void Api::HandleRegister(const httplib::Request& req, httplib::Response& res) {
    auto form = ParseFormBody(req.body);

    if (!form.contains("name")) {
        throw BadRequestError("parameter `name` is required");
    }
    if (!form.contains("password")) {
        throw BadRequestError("parameter `password` is required");
    }

    auto name = form.at("name");
    auto password = form.at("password");

    if (!ValidateInput(name) || !ValidateInput(password)) {
        throw BadRequestError("incorrect `name` and `password` values");
    }

    auto author = AuthService.Register(name, password);
    SetCurrentAuthor(res, author.GetName());

    nlohmann::json result = {
        {"success", true},
        {"response", {
            {"name", author.GetName()},
        }},
    };

    res.status = httplib::StatusCode::Created_201;
    res.set_content(result.dump(), JsonContentType);
}

void Api::HandleLogin(const httplib::Request& req, httplib::Response& res) {
    auto form = ParseFormBody(req.body);

    if (!form.contains("name")) {
        throw BadRequestError("parameter `name` is required");
    }
    if (!form.contains("password")) {
        throw BadRequestError("parameter `password` is required");
    }

    auto name = form.at("name");
    auto password = form.at("password");

    if (!ValidateInput(name) || !ValidateInput(password)) {
        throw BadRequestError("incorrect `name` and `password` values");
    }

    auto author = AuthService.Login(name, password);
    SetCurrentAuthor(res, author.GetName());

    nlohmann::json result = {
        {"success", true},
        {"response", {
            {"name", author.GetName()},
        }},
    };

    res.status = httplib::StatusCode::OK_200;
    res.set_content(result.dump(), JsonContentType);
}

void Api::HandleLogout(const httplib::Request& req, httplib::Response& res) {
    auto author = GetCurrentAuthor(req, res);

    if (author.has_value()) {
        SetCurrentAuthor(res, "");
    }

    nlohmann::json result = {
        {"success", true},
    };

    res.status = httplib::StatusCode::OK_200;
    res.set_content(result.dump(), JsonContentType);
}

void Api::HandleProfile(const httplib::Request& req, httplib::Response& res) {
    auto author = GetCurrentAuthor(req, res);

    if (!author.has_value()) {
        throw BadRequestError("anonymous user");
    }

    nlohmann::json result = {
        {"success", true},
        {"response", {
            {"name", author.value()},
        }},
    };

    res.status = httplib::StatusCode::OK_200;
    res.set_content(result.dump(), JsonContentType);
}

void Api::HandleNewMessage(const httplib::Request& req, httplib::Response& res) {
    auto author = GetCurrentAuthor(req, res);

    if (!author.has_value()) {
        throw BadRequestError("anonymous user");
    }

    auto form = ParseFormBody(req.body);

    if (!form.contains("title")) {
        throw BadRequestError("parameter `title` is required");
    }
    if (!form.contains("content")) {
        throw BadRequestError("parameter `content` is required");
    }

    auto title = form.at("title");
    auto content = form.at("content");

    if (!ValidateInput(title) || !ValidateInput(content)) {
        throw BadRequestError("incorrect `title` and `content` values");
    }

    auto message = BlogService.CreateMessage(author.value(), title, content);

    nlohmann::json result = {
        {"success", true},
        {"response", {
            {"id", message.GetId()},
        }},
    };

    res.status = httplib::StatusCode::Created_201;
    res.set_content(result.dump(), JsonContentType);
}

void Api::HandleViewMessage(const httplib::Request& req, httplib::Response& res) {
    auto id = req.path_params.at("id");

    if (id.empty()) {
        throw BadRequestError("parameter `id` is required");
    }

    if (!ValidateInput(id)) {
        throw BadRequestError("incorrect `id` value");
    }

    auto message = BlogService.GetMessage(id);

    nlohmann::json result = {
        {"success", true},
        {"response", {
            {"id", message.GetId()},
            {"author", message.GetAuthor()},
            {"title", message.GetTitle()},
            {"content", message.GetContent()},
        }},
    };

    res.status = httplib::StatusCode::OK_200;
    res.set_content(result.dump(), JsonContentType);
}

void Api::HandleSearchMessages(const httplib::Request& req, httplib::Response& res) {
    auto author = GetCurrentAuthor(req, res);

    if (!author.has_value()) {
        throw BadRequestError("anonymous user");
    }

    std::string content;

    if (req.has_param("content")) {
        content = req.get_param_value("content");

        if (!ValidateInput(content)) {
            throw BadRequestError("incorrect `content` value");
        }
    }

    auto messages = BlogService.GetAllMessages(author.value());

    std::vector<Models::Message> filtered;

    for (auto& message : messages) {
        if (message.GetContent().find(content) != std::string::npos) {
            filtered.push_back(message);
        }
    }

    if (filtered.size() == 0) {
        nlohmann::json result = {
            {"success", false},
        };

        res.status = httplib::StatusCode::NotFound_404;
        res.set_content(result.dump(), JsonContentType);

        return;
    }

    auto response = nlohmann::json::array();

    for (auto& message : filtered) {
        response.push_back({
            {"id", message.GetId()},
            {"title", message.GetTitle()},
        });
    }

    nlohmann::json result = {
        {"success", true},
        {"response", response},
    };

    res.status = httplib::StatusCode::OK_200;
    res.set_content(result.dump(), JsonContentType);
}

void Api::HandleRenderMessage(const httplib::Request& req, httplib::Response& res) {
    auto id = req.path_params.at("id");

    if (id.empty()) {
        throw BadRequestError("parameter `id` is required");
    }

    if (!ValidateInput(id)) {
        throw BadRequestError("incorrect `id` value");
    }

    auto message = BlogService.GetMessage(id);

    res.status = httplib::StatusCode::OK_200;
    res.set_content(RenderMessage(message), "text/html");
}

void Api::HandleException(const httplib::Request& req, httplib::Response& res, const std::exception_ptr ptr) {
    std::string error;

    try {
        std::rethrow_exception(ptr);
    } catch (const BadRequestError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::BadRequest_400;
    } catch (const Storage::MessageAlreadyExistsError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::Conflict_409;
    } catch (const Services::InvalidSessionError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::Unauthorized_401;
    } catch (const Services::InvalidCredentialsError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::Unauthorized_401;
    } catch (const Services::MessageNotFoundError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::NotFound_404;
    } catch (const std::exception& ex) {
        error = ex.what();
    }

    nlohmann::json result = {
        {"error", error},
    };

    res.set_content(result.dump(), JsonContentType);
}

std::optional<std::string> Api::GetCurrentAuthor(const httplib::Request& req, httplib::Response& res) {
    auto cookie = req.get_header_value("Cookie");

    if (!ValidateInput(cookie)) {
        return { };
    }

    if (!cookie.starts_with(SessionCookiePrefix)) {
        return { };
    }

    auto session = cookie.substr(SessionCookiePrefix.size());

    auto end = session.find(';');

    if (end != std::string::npos) {
        session = session.substr(0, end);
    }

    if (session.size() == 0) {
        return { };
    }

    try {
        return SessionService.Deserialize(session);
    } catch (const Services::InvalidSessionError&) {
        SetCurrentAuthor(res, "");
        throw;
    }
}

void Api::SetCurrentAuthor(httplib::Response& res, const std::string& name) {
    std::stringstream cookie;

    cookie << SessionCookiePrefix;

    if (!name.empty()) {
        cookie << SessionService.Serialize(name) << "; "s;
        cookie << "SameSite=Lax; "s;
        cookie << "HttpOnly; "s;
    }

    res.set_header("Set-Cookie", cookie.str());
}
