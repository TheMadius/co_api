#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <co_async/std.hpp>
#include <co_async/awaiter/task.hpp>
#include <co_async/iostream/stream_base.hpp>
#include <co_async/platform/socket.hpp>
#include <co_async/utils/pimpl.hpp>

namespace co_async {
auto ssl_connect(char const *host, int port,
            SSL_CTX *ctx, std::string_view proxy,
            std::chrono::steady_clock::duration timeout) -> Task<Expected<OwningStream>>;

auto ssl_accept(SocketHandle file, SSL_CTX *ctx,
                std::chrono::steady_clock::duration dur) -> Task<Expected<OwningStream>>;
} // namespace co_async
