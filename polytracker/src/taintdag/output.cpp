#include <filesystem>

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "taintdag/error.hpp"
#include "taintdag/output.hpp"

namespace taintdag {

namespace fs = std::filesystem;

OutputFile::OutputFile(fs::path const &fname) {
  fd_ = open(fname.c_str(), O_RDWR | O_TRUNC | O_CREAT,
             S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd_ == -1)
    error_exit("Failed to create output file. Errno is: ", errno);

  if (-1 == ftruncate(fd_, mapping_size))
    error_exit("Failed to resize output file. Path is: ", fname,
               " Errno is: ", errno);

  mapping_ =
      mmap(nullptr, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
  if (mapping_ == MAP_FAILED)
    error_exit("Failed to map output file. Path is: ", fname,
               " Errno is: ", errno);

  init_filehdr();
}

OutputFile::OutputFile(OutputFile &&o) : fd_{o.fd_}, mapping_{o.mapping_} {
  o.fd_ = -1;
  o.mapping_ = nullptr;
}

OutputFile &OutputFile::operator=(OutputFile &&o) {
  std::swap(fd_, o.fd_);
  std::swap(mapping_, o.mapping_);
  return *this;
}

OutputFile::~OutputFile() {
  if (mapping_)
    if (-1 == ::munmap(mapping_, mapping_size))
      error_exit("Failed to unmap ouput file. Errno is: ", errno);

  if (fd_ != -1)
    close(fd_);
}

void OutputFile::init_filehdr() {
  auto fh = reinterpret_cast<FileHdr *>(mapping_);
  fh->fd_mapping_offset = fd_mapping_offset;
  fh->fd_mapping_count = 0;
  fh->tdag_mapping_offset = tdag_mapping_offset;
  fh->tdag_mapping_size = 0;
  fh->sink_mapping_offset = sink_mapping_offset;
  fh->sink_mapping_size = 0;
  fh->fn_mapping_offset = fn_mapping_offset;
  fh->fn_mapping_count = 0;
  fh->fn_trace_offset = fn_trace_offset;
  fh->fn_trace_count = 0;
}

OutputFile::mapping_t OutputFile::offset_mapping(size_t offset, size_t length) {
  auto m = reinterpret_cast<char *>(mapping_);
  auto begin = m + offset;
  auto end = begin + length;
  return {begin, end};
}
// files
char *OutputFile::fd_mapping_begin() {
  return reinterpret_cast<char *>(mapping_) + fd_mapping_offset;
}
char *OutputFile::fd_mapping_end() {
  return fd_mapping_begin() + fd_mapping_size;
}
OutputFile::mapping_t OutputFile::fd_mapping() {
  return {fd_mapping_begin(), fd_mapping_end()};
}
// functions
char *OutputFile::fn_mapping_begin() {
  return reinterpret_cast<char *>(mapping_) + fn_mapping_offset;
}
char *OutputFile::fn_mapping_end() {
  return fn_mapping_begin() + fn_mapping_size;
}

OutputFile::mapping_t OutputFile::fn_mapping() {
  return {fn_mapping_begin(), fn_mapping_end()};
}
// trace
char *OutputFile::fn_trace_begin() {
  return reinterpret_cast<char *>(mapping_) + fn_trace_offset;
}

char *OutputFile::fn_trace_end() { return fn_trace_begin() + fn_trace_size; }

OutputFile::mapping_t OutputFile::fn_trace() {
  return {fn_trace_begin(), fn_trace_end()};
}
// tdag
char *OutputFile::tdag_mapping_begin() {
  return reinterpret_cast<char *>(mapping_) + tdag_mapping_offset;
}
char *OutputFile::tdag_mapping_end() {
  return tdag_mapping_begin() + tdag_mapping_size;
}
OutputFile::mapping_t OutputFile::tdag_mapping() {
  return {tdag_mapping_begin(), tdag_mapping_end()};
}
// sink
char *OutputFile::sink_mapping_begin() {
  return reinterpret_cast<char *>(mapping_) + sink_mapping_offset;
}
char *OutputFile::sink_mapping_end() {
  return sink_mapping_begin() + sink_mapping_size;
}
OutputFile::mapping_t OutputFile::sink_mapping() {
  return {sink_mapping_begin(), sink_mapping_end()};
}
void OutputFile::fileheader_fd_count(size_t fd_count) {
  reinterpret_cast<FileHdr *>(mapping_)->fd_mapping_count = fd_count;
}

void OutputFile::fileheader_tdag_size(size_t tdag_size) {
  reinterpret_cast<FileHdr *>(mapping_)->tdag_mapping_size = tdag_size;
}

void OutputFile::fileheader_sink_size(size_t sink_size) {
  reinterpret_cast<FileHdr *>(mapping_)->sink_mapping_size = sink_size;
}

void OutputFile::fileheader_fn_count(size_t fn_count) {
  reinterpret_cast<FileHdr *>(mapping_)->fn_mapping_count = fn_count;
}

void OutputFile::fileheader_trace_count(size_t event_count) {
  reinterpret_cast<FileHdr *>(mapping_)->fn_trace_count = event_count;
}

} // namespace taintdag