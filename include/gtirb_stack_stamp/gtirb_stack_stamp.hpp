#include <gtirb/gtirb.hpp>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include <cassert>
#include <string>

namespace gtirb_stack_stamp {
class StackStamper {
public:
  StackStamper(gtirb::Context& Ctx_) : Ctx{Ctx_} {
    [[maybe_unused]] auto CSRet = cs_open(CS_ARCH_X86, CS_MODE_64, &Capstone);
    assert(CSRet == CS_ERR_OK);
    cs_option(Capstone, CS_OPT_DETAIL, CS_OPT_ON);

    [[maybe_unused]] auto KSRet =
        ks_open(KS_ARCH_X86, KS_MODE_LITTLE_ENDIAN | KS_MODE_64, &Keystone);
    assert(KSRet == KS_ERR_OK);
    ks_option(Keystone, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
  }

  ~StackStamper() {
    cs_close(&Capstone);
    ks_close(Keystone);
  }

  void insertInstructions(gtirb::ByteInterval& BI, uint64_t Offset,
                          const std::string& InsnsStr);
  void stackStampEntranceBlock(const gtirb::UUID& FunctionId,
                               gtirb::CodeBlock& Block);
  void stackStampExitBlock(const gtirb::UUID& FunctionId,
                           gtirb::CodeBlock& Block);
  void stackStampFunction(gtirb::Module& M, const gtirb::UUID& FunctionId);

private:
  gtirb::Context& Ctx;
  csh Capstone;
  ks_engine* Keystone;
};

void stackStamp(gtirb::Context Ctx, gtirb::Module& M);
void registerAuxDataSchema();

} // namespace gtirb_stack_stamp
