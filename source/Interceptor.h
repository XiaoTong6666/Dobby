#pragma once

#include "dobby_internal.h"
#include "InterceptEntry.h"
#include <mutex>

class Interceptor {
public:
  static Interceptor *SharedInstance();
  // This lock spans lookup, build, patch and registry publication/removal.
  // Locking only individual vector operations leaves duplicate-hook races.
  static std::recursive_mutex &MutationMutex();

public:
  InterceptEntry *find(addr_t addr);

  InterceptEntry *remove(addr_t addr);

  void add(InterceptEntry *entry);

  const InterceptEntry *getEntry(int i);

  int count();

private:
  tinystl::vector<InterceptEntry *> entries;
  // Instrumentation closure stubs carry raw entry pointers. Their metadata
  // must remain alive until process exit, even after restoring the entry.
  tinystl::vector<InterceptEntry *> retired_instrumentation;

public:
  void retireInstrumentation(InterceptEntry *entry);
};
