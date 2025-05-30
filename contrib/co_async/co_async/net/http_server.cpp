#include <co_async/awaiter/task.hpp>
#include <co_async/iostream/socket_stream.hpp>
#include <co_async/iostream/ssl_socket_stream.hpp>
#include <co_async/net/http_protocol.hpp>
#include <co_async/net/http_server.hpp>
#include <co_async/net/http_string_utils.hpp>
#include <co_async/net/uri.hpp>
#include <co_async/platform/fs.hpp>
#include <co_async/platform/pipe.hpp>
#include <co_async/platform/socket.hpp>
#include <co_async/utils/expected.hpp>
#include <co_async/utils/simple_map.hpp>
#include <co_async/utils/string_utils.hpp>

#include <memory>

namespace co_async {

SSLServerState::~SSLServerState()
{
    if (ctx)
        SSL_CTX_free(ctx);
}

void SSLServerState::initSSLctx(std::string path_crt, std::string path_key, std::string pem)
{
    static int s_initialized = 0;
    if (s_initialized == 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
#else
        OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, NULL);
#endif
        s_initialized = 1;
    }
    // Creates a server that will negotiate the highest version of SSL/TLS supported
    // by the client it is connecting to.

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx = SSL_CTX_new(SSLv23_method());
#else
    ctx = SSL_CTX_new(TLS_method());
#endif
    if (!ctx) {
        throw std::runtime_error("Unable to create SSL context");
    }
    int mode = SSL_VERIFY_NONE;
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)(pem.c_str()));
    SSL_CTX_set_verify_depth(ctx, 10);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, path_crt.c_str()) <= 0)
    {
        throw std::runtime_error("ssl cert_file read failed!");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, path_key.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        throw std::runtime_error("ssl key_file check failed!");
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        throw std::runtime_error("ssl key_file check failed!");
    }
    if (mode == SSL_VERIFY_PEER )
    {
        SSL_CTX_set_default_verify_paths(ctx);
    }
#ifdef SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
    SSL_CTX_set_mode(ctx, SSL_CTX_get_mode(ctx) | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif
    SSL_CTX_set_verify(ctx, mode, NULL);
}

struct HTTPServer::Impl {
    struct Route {
        HTTPHandler mHandler;
        std::vector<String> mMethods;

        bool checkMethod(std::string_view method) const {
            return std::find(mMethods.begin(), mMethods.end(), method) !=
                   mMethods.end();
        }
    };

    struct PrefixRoute {
        HTTPPrefixHandler mHandler;
        HTTPRouteMode mRouteMode;
        std::vector<String> mMethods;

        bool checkMethod(std::string_view method) const {
            return std::find(mMethods.begin(), mMethods.end(), method) !=
                   mMethods.end();
        }

        bool checkSuffix(std::string_view &suffix) const {
            switch (mRouteMode) {
            case HTTPRouteMode::SuffixName: {
                if (suffix.starts_with('/')) {
                    suffix.remove_prefix(1);
                }
                if (suffix.empty()) [[unlikely]] {
                    return false;
                }
                // make sure no '/' in suffix
                if (suffix.find('/') != std::string_view::npos) [[unlikely]] {
                    return false;
                }
                return true;
            }
            case HTTPRouteMode::SuffixPath: {
                if (suffix.starts_with('/')) {
                    suffix.remove_prefix(1);
                }
                if (suffix.empty()) {
                    return true;
                }
                // make sure no ".." or "." after spliting by '/'
                for (auto const &part: split_string(suffix, '/')) {
                    switch (part.size()) {
                    case 2:
                        if (part[0] == '.' && part[1] == '.') [[unlikely]] {
                            return false;
                        }
                        break;
                    case 1:
                        if (part[0] == '.') [[unlikely]] {
                            return false;
                        }
                        break;
                    case 0: return false;
                    }
                }
                return true;
            }
            default: return true;
            }
        }
    };

    SimpleMap<String, Route> mRoutes;
    std::vector<std::pair<String, PrefixRoute>> mPrefixRoutes;
    HTTPHandler mDefaultRoute = [](IO::Ptr &io) -> Task<Expected<>> {
        co_return co_await make_error_response(io, 404);
    };
    std::chrono::steady_clock::duration mTimeout = std::chrono::seconds(30);
    Task<Expected<>> doHandleRequest(IO::Ptr &io) const {
        if (auto route = mRoutes.at(io->request.uri.path)) {
            if (!route->checkMethod(io->request.method)) [[unlikely]] {
                co_await co_await make_error_response(io, 405);
                co_return {};
            }
            co_await co_await route->mHandler(io);
            co_return {};
        }
        for (auto const &[prefix, route]: mPrefixRoutes) {
            if (io->request.uri.path.starts_with(prefix)) {
                if (!route.checkMethod(io->request.method)) [[unlikely]] {
                    co_await co_await make_error_response(io, 405);
                    co_return {};
                }
                auto suffix = std::string_view(io->request.uri.path);
                suffix.remove_prefix(prefix.size());
                if (!route.checkSuffix(suffix)) [[unlikely]] {
                    co_await co_await make_error_response(io, 405);
                    co_return {};
                }
                co_await co_await route.mHandler(io, suffix);
                co_return {};
            }
        }
        co_await co_await mDefaultRoute(io);
        co_return {};
    }
};

Task<Expected<bool>> HTTPServer::IO::readRequestHeader() {
    if (mHttp)
    {
        mHttp->initServerState();
        co_return co_await (co_await mHttp->readRequest(request)).transform([] { return true; }).or_else(eofError(), [] { return false; });
    }
    co_return {false};
}

Task<Expected<String>> HTTPServer::IO::request_body() {
    mBodyRead = true;
    String body;
    if (mHttp)
        co_await co_await mHttp->readBody(body);
    co_return body;
}

Task<Expected<>> HTTPServer::IO::request_body_stream(OwningStream &out) {
    mBodyRead = true;
    if (mHttp)
        co_await co_await mHttp->readBodyStream(out);
    co_return {};
}

Task<Expected<>> HTTPServer::IO::response(HTTPResponse resp,
                                          std::string_view content) {
    if (!mBodyRead) {
        co_await co_await request_body();
    }
    builtinHeaders(resp);
    if (mHttp)
    {
        co_await co_await mHttp->writeResponse(resp);
        co_await co_await mHttp->writeBody(content);
    }
    mBodyRead = false;
    co_return {};
}

Task<Expected<>> HTTPServer::IO::response(HTTPResponse resp,
                                          OwningStream &body) {
    if (!mBodyRead) {
        co_await co_await request_body();
    }
    builtinHeaders(resp);
    if (mHttp)
    {
        co_await co_await mHttp->writeResponse(resp);
        co_await co_await mHttp->writeBodyStream(body);
    }
    mBodyRead = false;
    co_return {};
}

void HTTPServer::IO::builtinHeaders(HTTPResponse &res) {
    res.headers.insert("server"_s, "evi_http/1.4.1"_s);
    res.headers.insert("accept"_s, "*/*"_s);
    res.headers.insert("accept-ranges"_s, "bytes"_s);
    res.headers.insert("date"_s, httpDateNow());
}

HTTPServer::HTTPServer() : mImpl(std::make_unique<Impl>()) {}

HTTPServer::~HTTPServer() = default;

void HTTPServer::timeout(std::chrono::steady_clock::duration timeout) {
    mImpl->mTimeout = timeout;
}

void HTTPServer::route(std::string_view methods, std::string_view path,
                       HTTPHandler handler) {
    mImpl->mRoutes.insert_or_assign(
        String(path),
        {handler, split_string(upper_string(methods), ' ').collect()});
}

void HTTPServer::route(std::string_view methods, std::string_view prefix,
                       HTTPRouteMode mode, HTTPPrefixHandler handler) {
    auto it = std::lower_bound(mImpl->mPrefixRoutes.begin(),
                               mImpl->mPrefixRoutes.end(), prefix,
                               [](auto const &item, auto const &prefix) {
                                   return item.first.size() > prefix.size();
                               });
    mImpl->mPrefixRoutes.insert(
        it,
        {String(prefix),
         {handler, mode, split_string(upper_string(methods), ' ').collect()}});
}

void HTTPServer::route(HTTPHandler handler) {
    mImpl->mDefaultRoute = handler;
}

auto HTTPServer::prepareHTTPS(SocketHandle handle, SSLServerState &https) const -> Task<std::shared_ptr<HTTPProtocol>> {
    using namespace std::string_view_literals;
    auto sock = co_await ssl_accept(std::move(handle), https.ctx,
                                                            mImpl->mTimeout);
    if (sock.has_error())
        co_return nullptr;

    sock->timeout(mImpl->mTimeout);
    co_return std::make_shared<HTTPProtocolVersion11>(std::move(*sock));
}

auto HTTPServer::prepareHTTP(SocketHandle handle) const -> Task<std::shared_ptr<HTTPProtocol>>{
    auto sock = make_stream<SocketStream>(std::move(handle));
    sock.timeout(mImpl->mTimeout);
    co_return std::make_shared<HTTPProtocolVersion11>(std::move(sock));
}

auto HTTPServer::handle_http(SocketHandle handle) const -> Task<Expected<>>{
    co_await co_await doHandleConnection(
        co_await prepareHTTP(std::move(handle)));
    co_return {};
}

auto HTTPServer::handle_http_redirect_to_https(SocketHandle handle) const -> Task<Expected<>> {
    using namespace std::string_literals;
    auto http = co_await prepareHTTP(std::move(handle));
    while (true) {
        IO::Ptr io = std::make_shared<IO>(http);
        if (!co_await co_await io->readRequestHeader()) {
            break;
        }
        if (auto host = io->request.headers.get("host")) {
            auto location = "https://"_s + *host + io->request.uri.dump();
            HTTPResponse res = {
                .status = 302,
                .headers =
                    {
                        {"location"_s, location},
                        {"content-type"_s, "text/plain"_s},
                    },
            };
            co_await co_await io->response(res, location);
        } else {
            co_await co_await make_error_response(io, 403);
        }
    }
    co_return {};
}

auto HTTPServer::handle_https(SocketHandle handle, SSLServerState &https) const -> Task<Expected<>> {
    auto sock = co_await prepareHTTPS(std::move(handle), https);
    if (sock)
        co_await co_await doHandleConnection(sock);
    co_return {};
}

auto HTTPServer::doHandleConnection(std::shared_ptr<HTTPProtocol> http) const -> Task<Expected<>>{
    IO::Ptr io = std::make_shared<IO>(http);
    while (true) {
        if (!co_await co_await io->readRequestHeader()) {
            break;
        }
        co_await co_await mImpl->doHandleRequest(io);
    }
    co_return {};
}

auto HTTPServer::make_error_response(IO::Ptr &io, int status) -> Task<Expected<>> {
    auto error = to_string(status) + ' ' + String(getHTTPStatusName(status));
    HTTPResponse res{
        .status = status,
        .headers =
            {
                {"content-type", "text/html;charset=utf-8"},
            },
    };
    co_await co_await io->response(
        res, "<html><head><title>" + error +
                 "</title></head><body><center><h1>" + error +
                 "</h1></center><hr><center>co_async</center></body></html>");
    co_return {};
}
} // namespace co_async
