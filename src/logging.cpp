/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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

#include "LIEF/logging.hpp"

namespace LIEF
{
    namespace logging
    {
        class CerrLogHandler : public ILogHandler
        {
          public:
            void log(std::string message, LEVEL level) override
            {
                std::string prefix;
                switch (level) {
                    case LEVEL::TRACE:
                        prefix = "TRACE   ";
                        break;
                    case LEVEL::DEBUG:
                        prefix = "DEBUG   ";
                        break;
                    case LEVEL::INFO:
                        prefix = "INFO    ";
                        break;
                    case LEVEL::WARN:
                        prefix = "WARNING ";
                        break;
                    case LEVEL::ERR:
                        prefix = "ERROR   ";
                        break;
                    case LEVEL::CRITICAL:
                        prefix = "CRITICAL";
                        break;
                }
                std::cerr << prefix + std::string("] ") + message << std::endl;
            }
        };

        logger::logger(LEVEL level) : level_(level)
        {
        }

        logger::~logger()
        {
            if (level_ >= get_current_log_level()) {
                get_handler_ref()->log(stringstream_.str(), level_);
            }
        }

        void logger::setLogLevel(LEVEL level)
        {
            get_log_level_ref() = level;
        }

        void logger::setHandler(ILogHandler *handler)
        {
            get_handler_ref() = handler;
        }

        LEVEL logger::get_current_log_level()
        {
            return get_log_level_ref();
        }

        LEVEL &logger::get_log_level_ref()
        {
            static LEVEL current_level = static_cast<LEVEL>(1);
            return current_level;
        }

        ILogHandler *&logger::get_handler_ref()
        {
            static CerrLogHandler default_handler;
            static ILogHandler *current_handler = &default_handler;
            return current_handler;
        }

        const char *to_string(LEVEL e)
        {
            switch (e) {
                case LEVEL::Trace:
                    return "TRACE";
                case LEVEL::DEBUG:
                    return "DEBUG";
                case LEVEL::INFO:
                    return "INFO";
                case LEVEL::ERR:
                    return "ERROR";
                case LEVEL::WARN:
                    return "WARN";
                case LEVEL::CRITICAL:
                    return "CRITICAL";
                default:
                    return "UNDEFINED";
            }
            return "UNDEFINED";
        }

        // Public interface
    } // namespace logging
} // namespace LIEF