#include "InterceptEntry.h"
#include "Interceptor.h"

InterceptEntry::InterceptEntry(InterceptEntryType type, addr_t address) {
  this->id = 0;
  this->type = type;
  this->routing = nullptr;
  this->patched_size = 0;
  this->relocated_addr = 0;
  this->relocated_size = 0;
  memset(this->origin_insns, 0, sizeof(this->origin_insns));
  this->origin_insn_size = 0;
  this->thumb_mode = false;

#if defined(TARGET_ARCH_ARM)
  if (address % 2) {
    address -= 1;
    this->thumb_mode = true;
  } else {
    this->thumb_mode = false;
  }
#endif

  this->patched_addr = address;
  this->id = Interceptor::SharedInstance()->count();
}
