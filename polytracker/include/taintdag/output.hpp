#ifndef POLYTRACKER_TAINTDAG_OUTPUT_H
#define POLYTRACKER_TAINTDAG_OUTPUT_H

#include <filesystem>
#include <limits>

#include "taintdag/taint.hpp"

namespace taintdag {

  // This header is located first in the file, information is used to parse the file
  // TODO (hbrodin): Ideally we should handle endianess etc...
  // NOTE (hbrodin): Using this information it should be fairly easy to produce a tool to transforms a sparse file into
  // compact encoding for sharing. Just move the tdag_mapping_offset (and contents) to the fd_mapping_offset + fd_mapping_size etc.
  struct FileHdr {
    uint64_t fd_mapping_offset;
    uint64_t fd_mapping_count;
    uint64_t tdag_mapping_offset;
    uint64_t tdag_mapping_size;
    uint64_t sink_mapping_offset;
    uint64_t sink_mapping_size;
  };


  // Mapping sizes - correspond to output file region (max) sizes
  const size_t fd_mapping_size = max_source_index * 16384;
  const size_t tdag_mapping_size = sizeof(storage_t) * std::numeric_limits<label_t>::max();
  const size_t sink_mapping_size = tdag_mapping_size; // TODO (hbrodin): What is a reasonable size??? It doesn't necessarily have to be fixed..

  // Mapping offsets - corresponds to output file offsets for regions (seek offsets)
  const size_t fd_mapping_offset = sizeof(FileHdr);
  const size_t tdag_mapping_offset = fd_mapping_offset + fd_mapping_size;
  const size_t sink_mapping_offset = tdag_mapping_offset + tdag_mapping_size;

  // Total mapping size
  const size_t mapping_size = sink_mapping_offset + sink_mapping_size;

  // TODO (hbrodin): Check alignment of returned pointers to ensure is allowed to cast to e.g. storage_t
  // Relies on sparse file support to generate the output file.
  // Thus it requires a filesystem that supports sparse files.
  class OutputFile {
  public:
    OutputFile(std::filesystem::path const& fname);
    ~OutputFile();

    OutputFile(OutputFile const&) = delete;
    OutputFile(OutputFile &&);

    OutputFile& operator=(OutputFile const&) = delete;
    OutputFile& operator=(OutputFile &&);

    // This mapping is allowed memory to use for fd to filename mapping
    std::pair<char*, char*> fd_mapping(); 
    char* fd_mapping_begin();
    char* fd_mapping_end();

    // This mapping is suitable for storing the TDAG
    std::pair<char*, char*> tdag_mapping(); 
    char *tdag_mapping_begin();
    char *tdag_mapping_end();

    // This mapping is suitable for storing sink mappings
    std::pair<char*, char*> sink_mapping(); 
    char* sink_mapping_begin();
    char* sink_mapping_end();

    // Update the fileheader size and count information (typically at exit)
    void fileheader_fd_count(size_t fd_count);
    void fileheader_tdag_size(size_t tdag_size);
    void fileheader_sink_size(size_t tdag_size);
  private:

    void init_filehdr();

    std::pair<char*, char*> offset_mapping(size_t offset, size_t length);

    int fd_{-1};
    void *mapping_{nullptr};

  };
  
} // namespace taint_tree 
#endif