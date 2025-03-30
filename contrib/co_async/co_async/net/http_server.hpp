#pragma once
#include <co_async/std.hpp>
#include <co_async/awaiter/task.hpp>
#include <co_async/iostream/socket_stream.hpp>
#include <co_async/iostream/ssl_socket_stream.hpp>
#include <co_async/net/http_protocol.hpp>
#include <co_async/net/http_string_utils.hpp>
#include <co_async/net/uri.hpp>
#include <co_async/platform/fs.hpp>
#include <co_async/platform/pipe.hpp>
#include <co_async/platform/socket.hpp>
#include <co_async/utils/simple_map.hpp>
#include <co_async/utils/string_utils.hpp>
#include <memory>

namespace co_async {
enum class HTTPRouteMode {
    SuffixAny = 0, // "/a-9\\*g./.."
    SuffixName,    // "/a"
    SuffixPath,    // "/a/b/c"
};

struct SSLServerState {
    void initSSLctx(std::string path_crt, std::string path_key, std::string pem = "");
    SSL_CTX* ctx = NULL;
};

struct HTTPServer {
    struct IO {
        using Ptr = std::shared_ptr<IO>;
        explicit IO(std::shared_ptr<HTTPProtocol> &http) noexcept : mHttp(std::move(http)) {}

        HTTPRequest request;
        Task<Expected<bool>> readRequestHeader();
        Task<Expected<String>> request_body();
        Task<Expected<>> request_body_stream(OwningStream &out);
        Task<Expected<>> response(HTTPResponse resp, std::string_view content);
        Task<Expected<>> response(HTTPResponse resp, OwningStream &body);

        BorrowedStream &extractSocket() const noexcept {
            return mHttp->sock;
        }

    private:
        std::shared_ptr<HTTPProtocol> mHttp;
        bool mBodyRead = false;
#if CO_ASYNC_DEBUG
        HTTPResponse mResponseSavedForDebug{};
        friend HTTPServer;
#endif
        void builtinHeaders(HTTPResponse &res);
    };

    using HTTPHandler = std::function<Task<Expected<>>(IO::Ptr &)>;
    using HTTPPrefixHandler =
        std::function<Task<Expected<>>(IO::Ptr &, std::string_view)>;
    /* using HTTPHandler = Task<Expected<>>(*)(IO::Ptr &); */
    /* using HTTPPrefixHandler = Task<Expected<>>(*)(IO::Ptr &, std::string_view); */
    HTTPServer();
    ~HTTPServer();
    HTTPServer(HTTPServer &&) = delete;
#if CO_ASYNC_DEBUG
    void enableLogRequests();
#endif
    void timeout(std::chrono::steady_clock::duration timeout);
    void route(std::string_view methods, std::string_view path,
               HTTPHandler handler);
    void route(std::string_view methods, std::string_view prefix,
               HTTPRouteMode mode, HTTPPrefixHandler handler);
    void route(HTTPHandler handler);
    Task<std::shared_ptr<HTTPProtocol>>
    prepareHTTPS(SocketHandle handle, SSLServerState &https) const;
    Task<std::shared_ptr<HTTPProtocol>> prepareHTTP(SocketHandle handle) const;
    Task<Expected<>> handle_http(SocketHandle handle) const;
    Task<Expected<>> handle_http_redirect_to_https(SocketHandle handle) const;
    Task<Expected<>> handle_https(SocketHandle handle, SSLServerState &https) const;
    Task<Expected<>>
    doHandleConnection(std::shared_ptr<HTTPProtocol> http) const;
    static Task<Expected<>> make_error_response(IO::Ptr &io, int status);

private:
    struct Impl;
    std::unique_ptr<Impl> const mImpl;
};
} // namespace co_async
