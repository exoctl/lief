/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "LIEF/config.h"
#include "LIEF/logging.hpp"
#include "LIEF/MachO.hpp"

#ifdef LIEF_JSON_SUPPORT
#include "MachO/json_internal.hpp"
#endif

namespace LIEF {
namespace MachO {

std::string to_json(const Object& v) {
#ifdef LIEF_JSON_SUPPORT
  JsonVisitor visitor;
  visitor(v);
  return visitor.get();
#else
  LIEF_WARN("JSON support is not enabled");
  return "";
#endif
}

} // namespace MachO
} // namespace LIEF
