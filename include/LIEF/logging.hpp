/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 * Copyright 2024 - 2024 remoob
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIEF_PRIVATE_LOGGING_H
#define LIEF_PRIVATE_LOGGING_H
#include <cstring>
#include <memory>

#include <iostream> 
#include "LIEF/config.h"
#include <spdlog/spdlog.h>
#include <sstream>

#define CHECK(X, ...)                                                          \
    do {                                                                       \
        if (!(X)) {                                                            \
            LIEF_ERR(X);                           \
        }                                                                      \
    } while (false)

#define CHECK_FATAL(X, ...)                                                    \
    do {                                                                       \
        if ((X)) {                                                             \
            LIEF_ERR(X);                           \
            std::abort();                                                      \
        }                                                                      \
    } while (false)

namespace LIEF
{
    namespace logging
    {
        enum class LEVEL : uint32_t {
#ifndef ERROR
#ifndef DEBUG
            TRACE = 0,
            DEBUG,
            INFO,
            WARN,
            ERR,
            CRITICAL,
#endif
#endif

            Trace = 0,
            Debug,
            Info,
            Warn,
            Err,
            Critical,
        };

        class ILogHandler
        {
          public:
            virtual ~ILogHandler() = default;

            virtual void log(std::string message, LEVEL level) = 0;
        };

        class logger
        {
          public:
            logger(LEVEL level);
            ~logger();

            //
            template <typename T> logger &operator<<(T const &value)
            {
                if (level_ >= get_current_log_level()) {
                    stringstream_ << value;
                }
                return *this;
            }

            static void setLogLevel(LEVEL level);

            static void setHandler(ILogHandler *handler);

            static LEVEL get_current_log_level();

          private:
            //
            static LEVEL &get_log_level_ref();
            static ILogHandler *&get_handler_ref();
            //
            std::ostringstream stringstream_;
            LEVEL level_;
        };

        inline void critial(const char *msg)
        {
            LIEF::logging::logger(LIEF::logging::LEVEL::Critical) << msg;
        }

        template <typename... Args>
        void critial(const char *fmt, const Args &...args)
        {
            // LIEF::logging::log(LIEF::logging::LIEF::logging::LEVEL::CRITICAL,
            //   fmt::format(fmt::runtime(fmt), args...)
            //);
        }

        [[noreturn]] inline void terminate()
        {
            std::abort();
        }

        [[noreturn]] inline void fatal_error(const char *msg)
        {
            critial(msg);
            terminate();
        }

        template <typename... Args>
        [[noreturn]] void fatal_error(const char *fmt, const Args &...args)
        {
            critial(fmt, args...);
            terminate();
        }

        inline void needs_lief_extended()
        {
            if constexpr (!lief_extended) {
            }
        }
    } // namespace logging
} // namespace LIEF

#define LIEF_TRACE(msg, ...)                                                   \
    if (LIEF::logging::logger::get_current_log_level() <=                      \
        LIEF::logging::LEVEL::TRACE)                                           \
    LIEF::logging::logger(LIEF::logging::LEVEL::TRACE)                         \
        << fmt::format(msg __VA_OPT__(, ) __VA_ARGS__)

#define LIEF_DEBUG(msg, ...)                                                   \
    if (LIEF::logging::logger::get_current_log_level() <=                      \
        LIEF::logging::LEVEL::DEBUG)                                           \
    LIEF::logging::logger(LIEF::logging::LEVEL::DEBUG)                         \
        << fmt::format(msg __VA_OPT__(, ) __VA_ARGS__)

#define LIEF_INFO(msg, ...)                                                    \
    if (LIEF::logging::logger::get_current_log_level() <=                      \
        LIEF::logging::LEVEL::INFO)                                            \
    LIEF::logging::logger(LIEF::logging::LEVEL::INFO)                          \
        << fmt::format(msg __VA_OPT__(, ) __VA_ARGS__)

#define LIEF_WARN(msg, ...)                                                    \
    if (LIEF::logging::logger::get_current_log_level() <=                      \
        LIEF::logging::LEVEL::WARN)                                            \
    LIEF::logging::logger(LIEF::logging::LEVEL::WARN)                          \
        << fmt::format(msg __VA_OPT__(, ) __VA_ARGS__)

#define LIEF_ERR(msg, ...)                                                     \
    if (LIEF::logging::logger::get_current_log_level() <=                      \
        LIEF::logging::LEVEL::ERR)                                             \
    LIEF::logging::logger(LIEF::logging::LEVEL::ERR)                           \
        << fmt::format(msg __VA_OPT__(, ) __VA_ARGS__)

#endif