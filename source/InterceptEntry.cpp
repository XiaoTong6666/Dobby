#include "InterceptEntry.h"
#include "Interceptor.h"
#include "InterceptRouting/InterceptRouting.h"

InterceptEntry::InterceptEntry(InterceptEntryType type, addr_t address) {
  this->id = 0;
  this->transaction_id = 0;
  this->type = type;
  this->routing = nullptr;
  this->state = InterceptEntryState::Installing;
  this->logical_target = 0;
  this->landing_pad_size = 0;
  this->patched_size = 0;
  this->relocated_addr = 0;
  this->relocated_size = 0;
  memset(this->origin_insns, 0, sizeof(this->origin_insns));
  this->origin_insn_size = 0;
  this->thumb_mode = false;
  this->branch_policy = DOBBY_BRANCH_LEGACY;
  this->hook_flags = 0;
  this->quiescence_user_data = nullptr;
  this->quiescence_acquire = nullptr;
  this->quiescence_release = nullptr;

#if defined(TARGET_ARCH_ARM)
  if (address % 2) {
    address -= 1;
    this->thumb_mode = true;
  } else {
    this->thumb_mode = false;
  }
#endif

  this->logical_target = address;
  this->patched_addr = address;
  this->id = Interceptor::SharedInstance()->count();
}

InterceptEntry::~InterceptEntry() {
  delete routing;
}
