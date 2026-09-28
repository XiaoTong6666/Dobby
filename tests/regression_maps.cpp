#include "PlatformUtil/ProcessRuntimeUtility.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>

static bool reported_empty_sort = false;
static const char *map_fixture = "";
extern "C" FILE *__real_fopen(const char *, const char *);
extern "C" FILE *__wrap_fopen(const char *path, const char *mode) {
  if (strcmp(path, "/proc/self/maps") == 0) {
    FILE *stream = tmpfile();
    if (stream && *map_fixture) {
      fwrite(map_fixture, 1, strlen(map_fixture), stream);
      rewind(stream);
    }
    return stream;
  }
  return __real_fopen(path, mode);
}
extern "C" void __real_qsort(void *, size_t, size_t, int (*)(const void *, const void *));
extern "C" void __wrap_qsort(void *ptr, size_t count, size_t width,
                               int (*compare)(const void *, const void *)) {
  if (count == 0) reported_empty_sort = true;
  __real_qsort(ptr, count, width, compare);
}
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  if (strcmp(argv[1], "permissions") == 0) {
    map_fixture = "00001000-00002000 rwxp 00000000 00:00 0\n"
                  "00002000-00003000 r-xp 00000000 00:00 0\n"
                  "00003000-00004000 rw-p 00000000 00:00 0\n";
    const auto &regions = ProcessRuntimeUtility::GetProcessMemoryLayout();
    if (regions.size() != 3 || regions[0].permission != kReadWriteExecute ||
        regions[1].permission != kReadExecute || regions[2].permission != kReadWrite) {
      fprintf(stderr, "incorrect maps permission parser result\n");
      return 1;
    }
    return 0;
  }
  if (strcmp(argv[1], "empty") != 0) return 2;
  const auto &regions = ProcessRuntimeUtility::GetProcessMemoryLayout();
  const auto &modules = ProcessRuntimeUtility::GetProcessModuleMap();
  if (!regions.empty() || !modules.empty() || reported_empty_sort) {
    fprintf(stderr, "empty /proc/self/maps must not dereference or sort an empty region list\n");
    return 1;
  }
  return 0;
}
