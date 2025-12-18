#include "omnisstream_ffi.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void die(const std::string& message) {
  std::cerr << "cpp_smoke: " << message << "\n";
  std::exit(2);
}

static void require_ok(int rc, const char* what) {
  if (rc == OS_OK) {
    return;
  }
  const char* msg = os_last_error_message();
  std::string err = msg ? std::string(msg) : std::string();
  die(std::string(what) + " failed rc=" + std::to_string(rc) + " err=" + err);
}

static OsSpan span_from_string(const std::string& s) {
  OsSpan span;
  span.ptr = reinterpret_cast<const unsigned char*>(s.data());
  span.len = s.size();
  return span;
}

static OsSpan span_from_bytes(const unsigned char* ptr, size_t len) {
  OsSpan span;
  span.ptr = ptr;
  span.len = len;
  return span;
}

static std::vector<unsigned char> read_file(const std::filesystem::path& p) {
  std::ifstream f(p, std::ios::binary);
  if (!f) {
    die("failed to open " + p.string());
  }

  f.seekg(0, std::ios::end);
  const std::streamoff end = f.tellg();
  if (end < 0) {
    die("failed to stat " + p.string());
  }
  f.seekg(0, std::ios::beg);

  std::vector<unsigned char> buf(static_cast<size_t>(end));
  if (!buf.empty()) {
    f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    if (!f) {
      die("failed to read " + p.string());
    }
  }
  return buf;
}

static void write_file(const std::filesystem::path& p, const std::vector<unsigned char>& bytes) {
  std::ofstream f(p, std::ios::binary | std::ios::trunc);
  if (!f) {
    die("failed to open for write " + p.string());
  }
  if (!bytes.empty()) {
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    if (!f) {
      die("failed to write " + p.string());
    }
  }
}

static std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::system_clock::now().time_since_epoch().count();
  const std::filesystem::path tmp =
      std::filesystem::temp_directory_path() / ("omnisstream_cpp_smoke_" + std::to_string(now));
  std::filesystem::create_directories(tmp);
  return tmp;
}

int main() {
  const std::filesystem::path tmp = make_temp_dir();

  // PartStore put/get smoke.
  {
    const std::filesystem::path part_root = tmp / "parts_store";
    const std::string part_root_s = part_root.string();

    OsPartStore* store = nullptr;
    require_ok(os_partstore_open(span_from_string(part_root_s), &store), "os_partstore_open");

    const std::string payload = "hello";
    OsDigest digest{};
    require_ok(os_partstore_put(store, span_from_string(payload), &digest), "os_partstore_put");

    OsOwnedBytes out{};
    require_ok(os_partstore_get(store, &digest, &out), "os_partstore_get");
    if (out.len != payload.size()) {
      die("os_partstore_get returned wrong length");
    }
    if (std::memcmp(out.ptr, payload.data(), payload.size()) != 0) {
      die("os_partstore_get returned wrong bytes");
    }
    os_owned_bytes_free(&out);
    os_partstore_close(store);
  }

  // Spec vector verify + corruption check.
  const std::filesystem::path spec_vector =
      std::filesystem::path("spec") / "omnisstream-spec" / "test-vectors" / "vector-minimal";
  if (!std::filesystem::exists(spec_vector)) {
    die("missing spec vectors at " + spec_vector.string() + " (run from repo root)");
  }

  const std::filesystem::path vec_tmp = tmp / "vector-minimal";
  std::filesystem::copy(spec_vector, vec_tmp,
                        std::filesystem::copy_options::recursive |
                            std::filesystem::copy_options::overwrite_existing);

  const std::vector<unsigned char> manifest_pb = read_file(vec_tmp / "manifest.pb");
  OsManifest* manifest = nullptr;
  require_ok(os_manifest_load_pb(span_from_bytes(manifest_pb.data(), manifest_pb.size()), &manifest),
             "os_manifest_load_pb");

  OsOwnedBytes inspect{};
  require_ok(os_manifest_inspect(manifest, &inspect), "os_manifest_inspect");
  if (inspect.ptr == nullptr || inspect.len == 0) {
    die("os_manifest_inspect returned empty output");
  }
  os_owned_bytes_free(&inspect);

  const std::string base_dir = vec_tmp.string();
  require_ok(os_verify_manifest_on_disk(manifest, span_from_string(base_dir)),
             "os_verify_manifest_on_disk");

  const std::filesystem::path part_to_corrupt = vec_tmp / "parts" / "part-0002.bin";
  std::vector<unsigned char> part_bytes = read_file(part_to_corrupt);
  if (part_bytes.empty()) {
    die("part file is empty: " + part_to_corrupt.string());
  }
  part_bytes[0] ^= 0xFF;
  write_file(part_to_corrupt, part_bytes);

  const int corrupt_rc = os_verify_manifest_on_disk(manifest, span_from_string(base_dir));
  if (corrupt_rc == OS_OK) {
    die("expected verify to fail after corruption");
  }
  const char* err = os_last_error_message();
  if (err == nullptr || std::strlen(err) == 0) {
    die("expected a non-empty error message after corruption failure");
  }
  if (std::string(err).find("hash mismatch") == std::string::npos) {
    die(std::string("unexpected verify error: ") + err);
  }

  os_manifest_free(manifest);

  std::filesystem::remove_all(tmp);
  std::cout << "cpp_smoke: ok\n";
  return 0;
}

