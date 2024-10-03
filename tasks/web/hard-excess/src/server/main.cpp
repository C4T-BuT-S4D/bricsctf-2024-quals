#include <string>

#include <server/api.h>
#include <services/auth.h>
#include <services/blog.h>
#include <services/session.h>
#include <storage/sqlite_storage.h>

#include <third_party/httplib.h>

using namespace Excess;


void SetSecurityHeaders(const httplib::Request &req, httplib::Response &res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Content-Security-Policy", "sandbox allow-scripts allow-same-origin; default-src 'self';");
    res.set_header("Cross-Origin-Resource-Policy", "same-origin");
    res.set_header("Referrer-Policy", "same-origin");
    res.set_header("X-XSS-Protection", "1; mode=block");
    res.set_header("X-Frame-Options", "SAMEORIGIN");
    res.set_header("X-Content-Type-Options", "nosniff");
}

int main() {
    httplib::Server server;

    server.set_mount_point("/static", "static");

    auto storage = Storage::SqliteStorage("db.sqlite3");

    auto auth = Services::Auth(storage);
    auto blog = Services::Blog(storage);

    auto session = Services::Session("secret.txt");

    auto api = Server::Api(auth, blog, session);

    server.set_pre_routing_handler([](const auto& req, auto& res) {
        SetSecurityHeaders(req, res);

        return httplib::Server::HandlerResponse::Unhandled;
    });

    server.set_exception_handler([&api](const auto& req, auto& res, auto ptr) {
        api.HandleException(req, res, ptr);
    });

    server.Post("/api/register", [&api](const auto& req, auto& res) {
        api.HandleRegister(req, res);
    });
    server.Post("/api/login", [&api](const auto& req, auto& res) {
        api.HandleLogin(req, res);
    });
    server.Post("/api/logout", [&api](const auto& req, auto& res) {
        api.HandleLogout(req, res);
    });
    server.Get("/api/profile", [&api](const auto& req, auto& res) {
        api.HandleProfile(req, res);
    });

    server.Post("/api/message", [&api](const auto& req, auto& res) {
        api.HandleNewMessage(req, res);
    });
    server.Get("/api/message/:id", [&api](const auto& req, auto& res) {
        api.HandleViewMessage(req, res);
    });
    server.Get("/api/messages", [&api](const auto& req, auto& res) {
        api.HandleSearchMessages(req, res);
    });

    server.Get("/api/render/:id", [&api](const auto& req, auto& res) {
        api.HandleRenderMessage(req, res);
    });

    server.Get("/.*", [](const auto& req, httplib::Response& res) {
        res.status = httplib::StatusCode::OK_200;
        res.set_file_content("index.html", "text/html");
    });

    server.listen("0.0.0.0", 31337);

    return 0;
}
