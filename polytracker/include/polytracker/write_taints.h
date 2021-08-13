#include <polytracker/dfsan_types.h>
#include <polytracker/logging.h>
#include <polytracker/output.h>
#include <sanitizer/dfsan_interface.h>
#include <sys/types.h>
#include <unistd.h>

ssize_t poly_write_callback(int fd, void *buf, size_t count,
                            dfsan_label fd_label, dfsan_label buff_label,
                            dfsan_label count_label, dfsan_label *ret_label);