#ifndef POLYTRACKER_TAINTDAG_OUTPUT_H
#define POLYTRACKER_TAINTDAG_OUTPUT_H

#include <cstdint>
#include <filesystem>
#include <limits>

#include "taintdag/fnmapping.h"
#include "taintdag/fntrace.h"
#include "taintdag/taint.hpp"

namespace taintdag {

// This header is located first in the file, information is used to parse the
// file
// TODO (hbrodin): Ideally we should handle endianess etc...
// NOTE (hbrodin): Using this information it should be fairly easy to produce a
// tool to transforms a sparse file into compact encoding for sharing. Just move
// the tdag_mapping_offset (and contents) to the fd_mapping_offset +
// fd_mapping_size etc.
struct FileHdr {
  uint64_t fd_mapping_offset;
  uint64_t fd_mapping_count;
  uint64_t tdag_mapping_offset;
  uint64_t tdag_mapping_size;
  uint64_t sink_mapping_offset;
  uint64_t sink_mapping_size;
  uint64_t fn_mapping_offset;
  uint64_t fn_mapping_count;
  uint64_t fn_trace_offset;
  uint64_t fn_trace_count;
};

// Mapping sizes - correspond to output file region (max) sizes
const size_t fd_mapping_size = max_source_index * 16384;
const size_t tdag_mapping_size =
    sizeof(storage_t) * std::numeric_limits<label_t>::max();
const size_t sink_mapping_size =
    tdag_mapping_size; // TODO (hbrodin): What is a reasonable size??? It
                       // doesn't necessarily have to be fixed..
const size_t fn_mapping_size = sizeof(FnMapping::header_t) *
                               std::numeric_limits<FnMapping::index_t>::max();
const size_t fn_trace_size =
    sizeof(FnTrace::event_t) * std::numeric_limits<FnTrace::event_id_t>::max();
// Mapping offsets - corresponds to output file offsets for regions (seek
// offsets)
const size_t fd_mapping_offset = sizeof(FileHdr);
const size_t tdag_mapping_offset = fd_mapping_offset + fd_mapping_size;
const size_t sink_mapping_offset = tdag_mapping_offset + tdag_mapping_size;
const size_t fn_mapping_offset = sink_mapping_offset + sink_mapping_size;
const size_t fn_trace_offset = fn_mapping_offset + fn_mapping_size;

// Total mapping size
const size_t mapping_size = fn_trace_offset + fn_trace_size;

// TODO (hbrodin): Check alignment of returned pointers to ensure is allowed to
// cast to e.g. storage_t Relies on sparse file support to generate the output
// file. Thus it requires a filesystem that supports sparse files.
class OutputFile {
public:
  OutputFile(std::filesystem::path const &fname);
  ~OutputFile();

  OutputFile(OutputFile const &) = delete;
  OutputFile(OutputFile &&);

  OutputFile &operator=(OutputFile const &) = delete;
  OutputFile &operator=(OutputFile &&);

  using mapping_t = std::pair<char *, char *>;

  // This mapping is allowed memory to use for fd to filename mapping
  mapping_t fd_mapping();
  char *fd_mapping_begin();
  char *fd_mapping_end();

  // This mapping is allowed memory to use for function to index mapping
  mapping_t fn_mapping();
  char *fn_mapping_begin();
  char *fn_mapping_end();

  // This mapping is allowed memory to use for function to index mapping
  mapping_t fn_trace();
  char *fn_trace_begin();
  char *fn_trace_end();

  // This mapping is suitable for storing the TDAG
  mapping_t tdag_mapping();
  char *tdag_mapping_begin();
  char *tdag_mapping_end();

  // This mapping is suitable for storing sink mappings
  mapping_t sink_mapping();
  char *sink_mapping_begin();
  char *sink_mapping_end();

  // Update the fileheader size and count information (typically at exit)
  void fileheader_fd_count(size_t fd_count);
  void fileheader_tdag_size(size_t tdag_size);
  void fileheader_sink_size(size_t tdag_size);
  void fileheader_fn_count(size_t fn_count);
  void fileheader_trace_count(size_t event_count);

private:
  void init_filehdr();

  mapping_t offset_mapping(size_t offset, size_t length);

  int fd_{-1};
  void *mapping_{nullptr};
};

} // namespace taintdag
#endif