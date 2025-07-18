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
#include <memory>

#include "LIEF/logging.hpp"

#include "LIEF/BinaryStream/BinaryStream.hpp"
#include "LIEF/PE/LoadConfigurations.hpp"
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/ImportEntry.hpp"

#include "internal_utils.hpp"
#include "frozen.hpp"
#include "PE/Structures.hpp"
#include "LIEF/PE/Parser.hpp"


namespace LIEF {
namespace PE {

template<typename PE_T>
ok_error_t Parser::parse() {

  if (!parse_headers<PE_T>()) {
    LIEF_WARN("Fail to parse regular PE headers");
    return make_error_code(lief_errors::parsing_error);
  }

  if (!parse_dos_stub()) {
    LIEF_WARN("Fail to parse DOS Stub");
  }

  if (!parse_rich_header()) {
    LIEF_WARN("Fail to parse rich header");
  }

  if (!parse_sections()) {
    LIEF_WARN("Fail to parse sections");
  }

  if (!parse_data_directories<PE_T>()) {
    LIEF_WARN("Fail to parse data directories");
  }

  if (!parse_symbols()) {
    LIEF_WARN("Fail to parse symbols");
  }

  if (!parse_overlay()) {
    LIEF_WARN("Fail to parse the overlay");
  }

  return ok();
}

template<typename PE_T>
ok_error_t Parser::parse_headers() {
  using pe_optional_header = typename PE_T::pe_optional_header;

  auto dos_hdr = stream_->peek<details::pe_dos_header>(0);
  if (!dos_hdr) {
    LIEF_ERR("Can't read the DOS Header");
    return make_error_code(dos_hdr.error());
  }

  binary_->dos_header_ = *dos_hdr;
  const uint64_t addr_new_exe = binary_->dos_header().addressof_new_exeheader();

  {
    auto pe_header = stream_->peek<details::pe_header>(addr_new_exe);
    if (!pe_header) {
      LIEF_ERR("Can't read the PE header");
      return make_error_code(pe_header.error());
    }
    binary_->header_ = *pe_header;
  }

  {
    const uint64_t offset = addr_new_exe + sizeof(details::pe_header);
    auto opt_header = stream_->peek<pe_optional_header>(offset);
    if (!opt_header) {
      LIEF_ERR("Can't read the optional header");
      return make_error_code(opt_header.error());
    }
    binary_->optional_header_ = *opt_header;
  }

  return ok();
}

template<typename PE_T>
ok_error_t Parser::parse_data_directories() {
  using pe_optional_header = typename PE_T::pe_optional_header;
  const uint32_t directories_offset = binary_->dos_header().addressof_new_exeheader() +
                                      sizeof(details::pe_header) + sizeof(pe_optional_header);
  const auto nbof_datadir = DataDirectory::DEFAULT_NB;
  stream_->setpos(directories_offset);

  // WARNING: The PE specifications require that the data directory table ends
  // with a null entry (RVA / Size, set to 0).
  //
  // Nevertheless it seems that this requirement is not enforced by the PE loader.
  // The binary bc203f2b6a928f1457e9ca99456747bcb7adbbfff789d1c47e9479aac11598af contains a non-null final
  // data directory (watermarking?)
  for (size_t i = 0; i < nbof_datadir; ++i) {
    details::pe_data_directory raw_dir;
    if (auto res = stream_->read<details::pe_data_directory>()) {
      raw_dir = *res;
    } else {
      LIEF_ERR("Can't read data directory at #{}", i);
      return make_error_code(lief_errors::read_error);
    }
    const auto dir_type = static_cast<DataDirectory::TYPES>(i);
    auto directory = std::make_unique<DataDirectory>(raw_dir, dir_type);
    if (directory->RVA() > 0) {
      const uint64_t offset = binary_->rva_to_offset(directory->RVA());
      directory->section_   = binary_->section_from_offset(offset);
      if (directory->section_ == nullptr && dir_type != DataDirectory::TYPES::CERTIFICATE_TABLE) {
        LIEF_WARN("Unable to find the section associated with {}", to_string(dir_type));
      }
    }
    binary_->data_directories_.push_back(std::move(directory));
  }

  // Import Table
  if (DataDirectory* import_data_dir = binary_->data_directory(DataDirectory::TYPES::IMPORT_TABLE)) {
    if (import_data_dir->RVA() > 0 && config_.parse_imports)
    {
      LIEF_DEBUG("Processing Import Table");
      if (Section* section = import_data_dir->section()) {
        section->add_type(PE_SECTION_TYPES::IMPORT);
      }
      parse_import_table<PE_T>();
    }
  }

  // Exports
  if (const DataDirectory* export_dir = binary_->data_directory(DataDirectory::TYPES::EXPORT_TABLE)) {
    if (export_dir->RVA() > 0 && config_.parse_exports) {
      LIEF_DEBUG("Parsing Exports");
      parse_exports();
    }
  }

  // Signature
  if (const DataDirectory* dir = binary_->data_directory(DataDirectory::TYPES::CERTIFICATE_TABLE)) {
    if (dir->RVA() > 0 && config_.parse_signature) {
      parse_signature();
    }
  }

  if (DataDirectory* dir = binary_->data_directory(DataDirectory::TYPES::TLS_TABLE)) {
    if (dir->RVA() > 0) {
      if (Section* sec = dir->section()) {
        sec->add_type(PE_SECTION_TYPES::TLS);
      }
      parse_tls<PE_T>();
    }
  }

  if (DataDirectory* dir = binary_->data_directory(DataDirectory::TYPES::LOAD_CONFIG_TABLE)) {
    if (dir->RVA() > 0) {
      LIEF_DEBUG("Parsing LoadConfiguration");
      if (Section* sec = dir->section()) {
        sec->add_type(PE_SECTION_TYPES::LOAD_CONFIG);
      }
      parse_load_config<PE_T>();
    }
  }

  if (DataDirectory* dir = binary_->data_directory(DataDirectory::TYPES::BASE_RELOCATION_TABLE)) {
    if (dir->RVA() > 0 && config_.parse_reloc) {
      LIEF_DEBUG("Parsing Relocations");
      if (Section* sec = dir->section()) {
        sec->add_type(PE_SECTION_TYPES::RELOCATION);
      }
      parse_relocations();
    }
  }

  if (DataDirectory* dir = binary_->data_directory(DataDirectory::TYPES::DEBUG_DIR)) {
    if (dir->RVA() > 0) {
      if (Section* sec = dir->section()) {
        sec->add_type(PE_SECTION_TYPES::DEBUG_TYPE);
      }
      parse_debug();
    }
  }

  if (DataDirectory* dir = binary_->data_directory(DataDirectory::TYPES::RESOURCE_TABLE)) {
    if (dir->RVA() > 0 && config_.parse_rsrc) {
      LIEF_DEBUG("Parsing Resources");
      if (Section* sec = dir->section()) {
        sec->add_type(PE_SECTION_TYPES::RESOURCE);
      }
      parse_resources();
    }
  }

  if (DataDirectory* dir = binary_->data_directory(DataDirectory::TYPES::DELAY_IMPORT_DESCRIPTOR)) {
    if (dir->RVA() > 0) {
      auto is_ok = parse_delay_imports<PE_T>();
      if (!is_ok) {
        LIEF_WARN("The parsing of delay imports has failed or is incomplete ('{}')",
                  to_string(get_error(is_ok)));
      }
    }
  }

  return ok();
}

template<typename PE_T>
ok_error_t Parser::parse_import_table() {
  using uint = typename PE_T::uint;
  DataDirectory* import_dir = binary_->data_directory(DataDirectory::TYPES::IMPORT_TABLE);
  DataDirectory* iat_dir    = binary_->data_directory(DataDirectory::TYPES::IAT);

  if (import_dir == nullptr || iat_dir == nullptr) {
    return make_error_code(lief_errors::not_found);
  }

  const uint32_t import_rva    = import_dir->RVA();
  const uint64_t import_offset = binary_->rva_to_offset(import_rva);
  const size_t   import_end    = import_offset + import_dir->size();

  stream_->setpos(import_offset);
  result<details::pe_import> imp_res;

  while (stream_->pos() < import_end && (imp_res = stream_->read<details::pe_import>())) {
    const auto raw_imp = *imp_res;
    if (BinaryStream::is_all_zero(raw_imp)) {
      break;
    }

    Import import           = raw_imp;
    import.directory_       = import_dir;
    import.iat_directory_   = iat_dir;
    import.type_            = type_;

    if (import.name_RVA_ == 0) {
      LIEF_DEBUG("Name's RVA is null");
      break;
    }

    // Offset to the Import (Library) name
    const uint64_t offset_name = binary_->rva_to_offset(import.name_RVA_);

    if (auto res_name = stream_->peek_string_at(offset_name))  {
      import.name_ = std::move(*res_name);
    } else {
      LIEF_ERR("Can't read the import name (offset: 0x{:x})", offset_name);
      continue;
    }


    // We assume that a DLL name should be at least 4 length size and "printable
    const std::string& imp_name = import.name();
    if (!is_valid_dll_name(imp_name)) {
      if (!imp_name.empty()) {
        LIEF_WARN("'{}' is not a valid import name and will be discarded", imp_name);
        continue;
      }
      continue; // skip
    }

    // Offset to import lookup table
    uint64_t LT_offset = import.import_lookup_table_rva() > 0 ?
                         binary_->rva_to_offset(import.import_lookup_table_rva()) :
                         0;


    // Offset to the import address table
    uint64_t IAT_offset = import.import_address_table_rva() > 0 ?
                          binary_->rva_to_offset(import.import_address_table_rva()) :
                          0;

    uint IAT = 0;
    uint table = 0;

    if (IAT_offset > 0) {
      if (auto res_iat = stream_->peek<uint>(IAT_offset)) {
        IAT   = *res_iat;
        table = IAT;
        IAT_offset += sizeof(uint);
      }
    }

    if (LT_offset > 0) {
      if (auto res_lt = stream_->peek<uint>(LT_offset)) {
        table      = *res_lt;
        LT_offset += sizeof(uint);
      }
    }

    size_t idx = 0;

    while (table != 0 || IAT != 0) {
      ImportEntry entry;
      entry.iat_value_ = IAT;
      entry.data_      = table > 0 ? table : IAT; // In some cases, ILT can be corrupted
      entry.type_      = type_;
      entry.rva_       = import.import_address_table_RVA_ + sizeof(uint) * (idx++);

      if (!entry.is_ordinal()) {
        const size_t hint_off = binary_->rva_to_offset(entry.hint_name_rva());
        const size_t name_off = hint_off + sizeof(uint16_t);
        if (auto entry_name = stream_->peek_string_at(name_off)) {
          entry.name_ = std::move(*entry_name);
        } else {
          LIEF_ERR("Can't read import entry name");
        }
        if (auto hint = stream_->peek<uint16_t>(hint_off)) {
          entry.hint_ = *hint;
        } else {
          LIEF_INFO("Can't read hint value @0x{:x}", hint_off);
        }

        // Check that the import name is valid
        if (is_valid_import_name(entry.name())) {
          import.entries_.push_back(std::move(entry));
        } else if (!entry.name().empty()){
          LIEF_INFO("'{}' is an invalid import name and will be discarded", entry.name());
        }

      } else {
        import.entries_.push_back(std::move(entry));
      }

      if (IAT_offset > 0) {
        if (auto iat = stream_->peek<uint>(IAT_offset)) {
          IAT = *iat;
          IAT_offset += sizeof(uint);
        } else {
          LIEF_ERR("Can't read the IAT value at 0x{:x}", IAT_offset);
          IAT = 0;
        }
      } else {
        IAT = 0;
      }

      if (LT_offset > 0) {
        if (auto lt = stream_->peek<uint>(LT_offset)) {
          table = *lt;
          LT_offset += sizeof(uint);
        } else {
          LIEF_ERR("Can't read the Lookup Table value at 0x{:x}", LT_offset);
          table = 0;
        }
      } else {
        table = 0;
      }
    }
    binary_->imports_.push_back(std::move(import));
  }

  return ok();
}


template<class PE_T>
ok_error_t Parser::parse_delay_names_table(DelayImport& import, uint32_t names_offset) {
  using uint = typename PE_T::uint;
  ScopedStream nstream(*stream_, names_offset);

  uint entry_val = 0;
  if (auto res = stream_->read<uint>()) {
    entry_val = *res;
  } else {
    LIEF_ERR("Can't read delay_imports.names_table[0]");
    return make_error_code(res.error());
  }

  while (names_offset > 0 && entry_val > 0) {
    DelayImportEntry entry{entry_val, type_};
    // Index of the current entry (-1 as we start with a read())
    const size_t index = (stream_->pos() - names_offset) / sizeof(uint) - 1;
    const uint32_t iat = index * sizeof(uint);
    if (auto res = stream_->peek<uint>(iat)) {
      entry.value_ = import.iat() + iat;
      entry.iat_value_  = *res;
      LIEF_DEBUG("  [{}].iat : 0x{:010x}", index, entry.iat_value_);
    } else {
      LIEF_WARN("Can't access the IAT value @0x{:x}", iat);
    }

    if (!entry.is_ordinal()) {
      size_t hint_off = binary_->rva_to_offset(entry.hint_name_rva());
      const size_t name_off = hint_off + sizeof(uint16_t);
      if (auto entry_name = stream_->peek_string_at(name_off)) {
        entry.name_ = std::move(*entry_name);
      } else {
        LIEF_ERR("Can't read import entry name");
      }
      if (auto hint = stream_->peek<uint16_t>(hint_off)) {
        entry.hint_ = *hint;
      } else {
        LIEF_INFO("Can't read hint value @0x{:x}", hint_off);
      }

      // Check that the import name is valid
      if (Parser::is_valid_import_name(entry.name())) {
        LIEF_DEBUG("  [{}].name: {}", index, entry.name());
        import.entries_.push_back(std::move(entry));
      } else if (!entry.name().empty()){
        LIEF_INFO("'{}' is an invalid import name and will be discarded", entry.name());
      }

    } else {
      import.entries_.push_back(std::move(entry));
    }

    if (auto res = stream_->read<uint>()) {
      entry_val = *res;
    } else {
      LIEF_ERR("Can't read the Name offset value at 0x{:x}", stream_->pos());
      break;
    }
  }
  return ok();
}

template<typename PE_T>
ok_error_t Parser::parse_delay_imports() {
  LIEF_DEBUG("Parsing Delay Import Table");
  std::string dll_name;

  const DataDirectory* dir = binary_->data_directory(DataDirectory::TYPES::DELAY_IMPORT_DESCRIPTOR);
  if (dir == nullptr) {
    return make_error_code(lief_errors::not_found);
  }

  const uint64_t size = dir->size();
  uint64_t offset = binary_->rva_to_offset(dir->RVA());
  const uint64_t delay_end = offset + size;

  stream_->setpos(offset);
  while (stream_->pos() < delay_end) {
    details::delay_imports raw_desc;
    if (auto res = stream_->read<decltype(raw_desc)>()) {
      raw_desc = *res;
    } else {
      LIEF_ERR("Can't read 'details::delay_imports'");
      return make_error_code(lief_errors::read_error);
    }
    DelayImport import{raw_desc, type_};

    if (BinaryStream::is_all_zero(raw_desc)) {
      return ok();
    }

    uint64_t name_offset = binary_->rva_to_offset(raw_desc.name);

    if (auto res = stream_->peek_string_at(name_offset)) {
      dll_name = *res;
    } else {
      LIEF_ERR("Can't read the DLL name");
      return make_error_code(lief_errors::conversion_error);
    }

    if (!is_valid_dll_name(dll_name)) {
      if (!dll_name.empty()) {
        LIEF_WARN("'{}' is not a valid DLL name and will be discarded", printable_string(dll_name));
        continue;
      }
      continue;
    }

    import.name_ = dll_name;

    LIEF_DEBUG("  delay_imports.name:       {}",       dll_name);
    LIEF_DEBUG("  delay_imports.attribute:  {}",       raw_desc.attribute);
    LIEF_DEBUG("  delay_imports.handle:     0x{:04x}", raw_desc.handle);
    LIEF_DEBUG("  delay_imports.iat:        0x{:04x}", raw_desc.iat);
    LIEF_DEBUG("  delay_imports.name_table: 0x{:04x}", raw_desc.name_table);
    LIEF_DEBUG("  delay_imports.bound_iat:  0x{:04x}", raw_desc.bound_iat);
    LIEF_DEBUG("  delay_imports.unload_iat: 0x{:04x}", raw_desc.unload_iat);
    LIEF_DEBUG("  delay_imports.timestamp:  0x{:04x}", raw_desc.timestamp);

    // Offset to Delay Import Name Table
    uint64_t names_offset = 0;

    // Offset to the import address table
    uint64_t IAT_offset = 0;

    if (raw_desc.name_table > 0) {
      names_offset = binary_->rva_to_offset(raw_desc.name_table);
    }


    if (raw_desc.iat > 0) {
      IAT_offset = binary_->rva_to_offset(raw_desc.iat);
    }
    LIEF_DEBUG("  [IAT  ]: 0x{:04x}", IAT_offset);
    LIEF_DEBUG("  [Names]: 0x{:04x}", names_offset);

    if (names_offset > 0) {
      auto is_ok = parse_delay_names_table<PE_T>(import, names_offset);
      if (!is_ok) {
        LIEF_WARN("Delay imports names table parsed with errors ('{}')",
                  to_string(get_error(is_ok)));
      }
    }

    binary_->delay_imports_.push_back(std::move(import));
  }

  return ok();
}


template<typename PE_T>
ok_error_t Parser::parse_tls() {
  using pe_tls = typename PE_T::pe_tls;
  using uint = typename PE_T::uint;

  LIEF_DEBUG("Parsing TLS");

  DataDirectory* tls_dir = binary_->data_directory(DataDirectory::TYPES::TLS_TABLE);
  if (tls_dir == nullptr) {
    return make_error_code(lief_errors::not_found);
  }
  const uint32_t tls_rva = tls_dir->RVA();
  const uint64_t offset  = binary_->rva_to_offset(tls_rva);

  stream_->setpos(offset);

  const auto tls_header = stream_->read<pe_tls>();

  if (!tls_header) {
    return make_error_code(lief_errors::read_error);
  }

  auto tls = std::make_unique<TLS>(*tls_header);

  const uint64_t imagebase = binary_->optional_header().imagebase();

  if (tls_header->RawDataStartVA >= imagebase && tls_header->RawDataEndVA > tls_header->RawDataStartVA) {
    const uint64_t start_data_rva = tls_header->RawDataStartVA - imagebase;
    const uint64_t stop_data_rva  = tls_header->RawDataEndVA - imagebase;

    const uint start_template_offset = binary_->rva_to_offset(start_data_rva);
    const uint end_template_offset   = binary_->rva_to_offset(stop_data_rva);

    const size_t size_to_read = end_template_offset - start_template_offset;

    if (size_to_read > Parser::MAX_DATA_SIZE) {
      LIEF_DEBUG("TLS's template is too large!");
    } else {
      if (!stream_->peek_data(tls->data_template_, start_template_offset, size_to_read)) {
        LIEF_WARN("TLS's template corrupted");
      }
    }
  }

  if (tls->addressof_callbacks() > imagebase) {
    uint64_t callbacks_offset = binary_->rva_to_offset(tls->addressof_callbacks() - imagebase);
    stream_->setpos(callbacks_offset);
    size_t count = 0;
    while (count++ < Parser::MAX_TLS_CALLBACKS) {
      auto res_callback_rva = stream_->read<uint>();
      if (!res_callback_rva) {
        break;
      }

      auto callback_rva = *res_callback_rva;

      if (static_cast<uint32_t>(callback_rva) == 0) {
        break;
      }
      tls->callbacks_.push_back(callback_rva);
    }
  }

  tls->directory_ = tls_dir;
  tls->section_   = tls_dir->section();
  binary_->tls_ = std::move(tls);
  return ok();
}


template<typename PE_T>
ok_error_t Parser::parse_load_config() {
  using load_configuration_t    = typename PE_T::load_configuration_t;
  using load_configuration_v0_t = typename PE_T::load_configuration_v0_t;
  using load_configuration_v1_t = typename PE_T::load_configuration_v1_t;
  using load_configuration_v2_t = typename PE_T::load_configuration_v2_t;
  using load_configuration_v3_t = typename PE_T::load_configuration_v3_t;
  using load_configuration_v4_t = typename PE_T::load_configuration_v4_t;
  using load_configuration_v5_t = typename PE_T::load_configuration_v5_t;
  using load_configuration_v6_t = typename PE_T::load_configuration_v6_t;
  using load_configuration_v7_t = typename PE_T::load_configuration_v7_t;
  using load_configuration_v8_t = typename PE_T::load_configuration_v8_t;
  using load_configuration_v9_t = typename PE_T::load_configuration_v9_t;
  using load_configuration_v10_t = typename PE_T::load_configuration_v10_t;
  using load_configuration_v11_t = typename PE_T::load_configuration_v11_t;

  CONST_MAP_ALT PE32_LOAD_CONFIGURATION_SIZES = {
    std::pair(LoadConfiguration::VERSION::UNKNOWN,               sizeof(details::PE32::load_configuration_t)),
    std::pair(LoadConfiguration::VERSION::SEH,                   sizeof(details::PE32::load_configuration_v0_t)),
    std::pair(LoadConfiguration::VERSION::WIN_8_1,               sizeof(details::PE32::load_configuration_v1_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_9879,         sizeof(details::PE32::load_configuration_v2_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_14286,        sizeof(details::PE32::load_configuration_v3_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_14383,        sizeof(details::PE32::load_configuration_v4_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_14901,        sizeof(details::PE32::load_configuration_v5_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_15002,        sizeof(details::PE32::load_configuration_v6_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_16237,        sizeof(details::PE32::load_configuration_v7_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_18362,        sizeof(details::PE32::load_configuration_v8_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_19534,        sizeof(details::PE32::load_configuration_v9_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_MSVC_2019,    sizeof(details::PE32::load_configuration_v10_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_MSVC_2019_16, sizeof(details::PE32::load_configuration_v11_t)),
  };

  CONST_MAP_ALT PE64_LOAD_CONFIGURATION_SIZES = {
    std::pair(LoadConfiguration::VERSION::UNKNOWN,               sizeof(details::PE64::load_configuration_t)),
    std::pair(LoadConfiguration::VERSION::SEH,                   sizeof(details::PE64::load_configuration_v0_t)),
    std::pair(LoadConfiguration::VERSION::WIN_8_1,               sizeof(details::PE64::load_configuration_v1_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_9879,         sizeof(details::PE64::load_configuration_v2_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_14286,        sizeof(details::PE64::load_configuration_v3_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_14383,        sizeof(details::PE64::load_configuration_v4_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_14901,        sizeof(details::PE64::load_configuration_v5_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_15002,        sizeof(details::PE64::load_configuration_v6_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_16237,        sizeof(details::PE64::load_configuration_v7_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_18362,        sizeof(details::PE64::load_configuration_v8_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_19534,        sizeof(details::PE64::load_configuration_v9_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_MSVC_2019,    sizeof(details::PE64::load_configuration_v10_t)),
    std::pair(LoadConfiguration::VERSION::WIN_10_0_MSVC_2019_16, sizeof(details::PE64::load_configuration_v11_t)),
  };

  LIEF_DEBUG("[+] Parsing Load Config");

  DataDirectory* load_config_dir = binary_->data_directory(DataDirectory::TYPES::LOAD_CONFIG_TABLE);
  if (load_config_dir == nullptr) {
    return make_error_code(lief_errors::not_found);
  }
  const uint32_t ldc_rva = load_config_dir->RVA();
  const uint64_t offset  = binary_->rva_to_offset(ldc_rva);

  const auto res = stream_->peek<uint32_t>(offset);
  if (!res) {
    return make_error_code(lief_errors::read_error);
  }

  const uint32_t size = *res;
  size_t current_size = 0;
  auto version_found = LoadConfiguration::VERSION::UNKNOWN;

  if constexpr (std::is_same_v<PE_T, details::PE32>) {
    for (const auto& [version, sz] : PE32_LOAD_CONFIGURATION_SIZES) {
      if (current_size < sz && sz <= size) {
        version_found = version;
        current_size = sz;
      }
    }
  } else {
    for (const auto& [version, sz] : PE64_LOAD_CONFIGURATION_SIZES) {
      if (current_size < sz && sz <= size) {
        version_found = version;
        current_size = sz;
      }
    }
  }

  LIEF_DEBUG("Version found: {} (size: 0x{:x})", to_string(version_found), size);
  std::unique_ptr<LoadConfiguration> ld_conf;

  switch (version_found) {

    case LoadConfigurationV0::WIN_VERSION:
      {
        if (const auto header = stream_->peek<load_configuration_v0_t>(offset)) {
          ld_conf = std::make_unique<LoadConfigurationV0>(*header);
        }
        break;
      }

    case LoadConfigurationV1::WIN_VERSION:
      {
        if (const auto header = stream_->peek<load_configuration_v1_t>(offset)) {
          ld_conf = std::make_unique<LoadConfigurationV1>(*header);
        }
        break;
      }

    case LoadConfigurationV2::WIN_VERSION:
      {
        if (const auto header = stream_->peek<load_configuration_v2_t>(offset)) {
          ld_conf = std::make_unique<LoadConfigurationV2>(*header);
        }
        break;
      }

    case LoadConfigurationV3::WIN_VERSION:
      {
        if (const auto header = stream_->peek<load_configuration_v3_t>(offset)) {
          ld_conf = std::make_unique<LoadConfigurationV3>(*header);
        }
        break;
      }

    case LoadConfigurationV4::WIN_VERSION:
      {
        if (const auto header = stream_->peek<load_configuration_v4_t>(offset)) {
          ld_conf = std::make_unique<LoadConfigurationV4>(*header);
        }
        break;
      }

    case LoadConfigurationV5::WIN_VERSION:
      {
        if (const auto header = stream_->peek<load_configuration_v5_t>(offset)) {
          ld_conf = std::make_unique<LoadConfigurationV5>(*header);
        }
        break;
      }

    case LoadConfigurationV6::WIN_VERSION:
      {
        if (const auto header = stream_->peek<load_configuration_v6_t>(offset)) {
          ld_conf = std::make_unique<LoadConfigurationV6>(*header);
        }
        break;
      }

    case LoadConfigurationV7::WIN_VERSION:
      {
        if (const auto header = stream_->peek<load_configuration_v7_t>(offset)) {
          ld_conf = std::make_unique<LoadConfigurationV7>(*header);
        }
        break;
      }

    case LoadConfigurationV8::WIN_VERSION:
      {
        if (const auto header = stream_->peek<load_configuration_v8_t>(offset)) {
          ld_conf = std::make_unique<LoadConfigurationV8>(*header);
        }
        break;
      }

    case LoadConfigurationV9::WIN_VERSION:
      {
        if (const auto header = stream_->peek<load_configuration_v9_t>(offset)) {
          ld_conf = std::make_unique<LoadConfigurationV9>(*header);
        }
        break;
      }

    case LoadConfigurationV10::WIN_VERSION:
      {
        if (const auto header = stream_->peek<load_configuration_v10_t>(offset)) {
          ld_conf = std::make_unique<LoadConfigurationV10>(*header);
        }
        break;
      }

    case LoadConfigurationV11::WIN_VERSION:
      {
        if (const auto header = stream_->peek<load_configuration_v11_t>(offset)) {
          ld_conf = std::make_unique<LoadConfigurationV11>(*header);
        }
        break;
      }

    case LoadConfiguration::VERSION::UNKNOWN:
    default:
      {
        if (const auto header = stream_->peek<load_configuration_t>(offset)) {
          ld_conf = std::make_unique<LoadConfiguration>(*header);
        }
      }
  }

  binary_->load_configuration_ = std::move(ld_conf);
  return ok();
}

}
}
