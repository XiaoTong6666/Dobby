#include "Interceptor.h"

Interceptor *Interceptor::SharedInstance() {
  static Interceptor instance;
  return &instance;
}

std::recursive_mutex &Interceptor::MutationMutex() {
  static std::recursive_mutex mutex;
  return mutex;
}

InterceptEntry *Interceptor::find(addr_t addr) {
  std::lock_guard<std::recursive_mutex> guard(MutationMutex());
  for (auto *entry : entries) {
    if (entry->patched_addr == addr) {
      return entry;
    }
  }
  return nullptr;
}

void Interceptor::add(InterceptEntry *entry) {
  std::lock_guard<std::recursive_mutex> guard(MutationMutex());
  entries.push_back(entry);
}

InterceptEntry *Interceptor::remove(addr_t addr) {
  std::lock_guard<std::recursive_mutex> guard(MutationMutex());
  for (auto iter = entries.begin(); iter != entries.end(); iter++) {
    if ((*iter)->patched_addr == addr) {
      auto *entry = *iter;
      entries.erase(iter);
      return entry;
    }
  }
  return nullptr;
}

const InterceptEntry *Interceptor::getEntry(int i) {
  std::lock_guard<std::recursive_mutex> guard(MutationMutex());
  if (i < 0 || static_cast<size_t>(i) >= entries.size())
    return nullptr;
  return entries[i];
}

int Interceptor::count() {
  std::lock_guard<std::recursive_mutex> guard(MutationMutex());
  return entries.size();
}

void Interceptor::retireInstrumentation(InterceptEntry *entry) {
  std::lock_guard<std::recursive_mutex> guard(MutationMutex());
  retired_instrumentation.push_back(entry);
}
