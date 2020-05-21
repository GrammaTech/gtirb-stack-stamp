#include <gtirb_stack_stamp/gtirb_stack_stamp.hpp>

#include <capstone/x86.h>
#include <ios>
#include <random>
#include <sstream>

template <typename BlockType>
static void modifyBlock(BlockType& Block, uint64_t Offset, uint64_t Size) {
  auto BlockOff = Block.getOffset();
  auto BlockSize = Block.getSize();

  if (BlockOff <= Offset && BlockOff + BlockSize > Offset) {
    // increase in size any blocks that intersect with the new bytes
    Block.setSize(BlockSize + Size);
  } else if (BlockOff >= Offset) {
    // move any blocks over that occur after the inserted bytes
    Block.getByteInterval()->addBlock(BlockOff + Size, &Block);
  }
}

static gtirb::CFG::vertex_descriptor blockToCFGIndex(gtirb::CFG& Cfg,
                                                     gtirb::CodeBlock* B) {
  auto Pair = boost::vertices(Cfg);
  for (auto V : boost::make_iterator_range(Pair.first, Pair.second)) {
    if (Cfg[V] == B) {
      return V;
    }
  }

  assert(!"blockToCFGIndex failed!");
  return 0;
}

static std::string getStampAssembly(const gtirb::UUID& FunctionId) {
  uint64_t Seed = 1;
  for (auto Byte : FunctionId) {
    Seed *= Byte;
  }
  std::mt19937_64 Rng{Seed};

  std::ostringstream ss;
  ss << "xorl $0x" << std::hex << Rng() << ",(%rsp); xorl $0x" << std::hex
     << Rng() << ",4(%rsp);";
  return ss.str();
}

void gtirb_stack_stamp::StackStamper::insertInstructions(
    gtirb::ByteInterval& BI, uint64_t Offset, const std::string& InsnsStr) {
  gtirb::Addr Addr{0};
  if (auto BiAddr = BI.getAddress()) {
    Addr = *BiAddr + Offset;
  }

  unsigned char* Bytes;
  size_t BytesLen, StatCount;
  [[maybe_unused]] auto KSRes =
      ks_asm(Keystone, InsnsStr.c_str(), static_cast<uint64_t>(Addr), &Bytes,
             &BytesLen, &StatCount);
  assert(KSRes == KS_ERR_OK);

  // modify contents
  BI.insertBytes<unsigned char>(BI.bytes_begin<unsigned char>() + Offset, Bytes,
                                Bytes + BytesLen);

  // modify blocks
  std::vector<gtirb::CodeBlock*> CodeBlocks;
  for (auto& Block : BI.code_blocks()) {
    CodeBlocks.push_back(&Block);
  }
  for (auto* Block : CodeBlocks) {
    modifyBlock(*Block, Offset, BytesLen);
  }

  std::vector<gtirb::DataBlock*> DataBlocks;
  for (auto& Block : BI.data_blocks()) {
    DataBlocks.push_back(&Block);
  }
  for (auto* Block : DataBlocks) {
    modifyBlock(*Block, Offset, BytesLen);
  }

  // modify symbolic expressions
  std::vector<gtirb::ByteInterval::SymbolicExpressionElement> SEEs{
      BI.symbolic_expressions_begin(), BI.symbolic_expressions_end()};
  for (auto& SEE : SEEs) {
    if (SEE.getOffset() >= Offset) {
      BI.removeSymbolicExpression(Offset);
      BI.addSymbolicExpression(Offset + BytesLen, SEE.getSymbolicExpression());
    }
  }
}

void gtirb_stack_stamp::StackStamper::stackStampEntranceBlock(
    const gtirb::UUID& FunctionId, gtirb::CodeBlock& Block) {
  insertInstructions(*Block.getByteInterval(), Block.getOffset(),
                     getStampAssembly(FunctionId));
}

void gtirb_stack_stamp::StackStamper::stackStampExitBlock(
    const gtirb::UUID& FunctionId, gtirb::CodeBlock& Block) {
  gtirb::Addr A{0};
  if (auto BA = Block.getAddress()) {
    A = *BA;
  }

  cs_insn* Insns;
  auto InsnsLen =
      cs_disasm(Capstone, Block.rawBytes<uint8_t>(), Block.getSize(),
                static_cast<uint64_t>(A), 0, &Insns);
  uint64_t Offset = Block.getOffset();
  for (size_t I = 0; I < InsnsLen; I++) {
    const auto& Insn = Insns[I];
    if (Insn.id == X86_INS_RET) {
      insertInstructions(*Block.getByteInterval(), Offset,
                         getStampAssembly(FunctionId));
      break;
    } else {
      Offset += Insn.size;
    }
  }
}

void gtirb_stack_stamp::StackStamper::stackStampFunction(
    gtirb::Module& M, const gtirb::UUID& FunctionId) {
  const auto* AllBlocks = M.getAuxData<gtirb::schema::FunctionBlocks>();
  const auto* AllEntries = M.getAuxData<gtirb::schema::FunctionEntries>();

  if (!AllBlocks || !AllEntries) {
    return;
  }

  // handle entrance blocks
  for (const auto& BlockId : AllEntries->at(FunctionId)) {
    stackStampEntranceBlock(
        FunctionId,
        *cast<gtirb::CodeBlock>(gtirb::Node::getByUUID(Ctx, BlockId)));
  }

  // handle exit blocks
  auto& Cfg = M.getIR()->getCFG();
  for (const auto& BlockId : AllBlocks->at(FunctionId)) {
    auto& Block = *cast<gtirb::CodeBlock>(gtirb::Node::getByUUID(Ctx, BlockId));
    auto OutEdges = boost::out_edges(blockToCFGIndex(Cfg, &Block), Cfg);
    if (OutEdges.first != OutEdges.second) {
      stackStampExitBlock(FunctionId, Block);
    }
  }
}

void gtirb_stack_stamp::stackStamp(gtirb::Context Ctx, gtirb::Module& M) {
  gtirb_stack_stamp::StackStamper SS{Ctx};
  if (const auto* Functions = M.getAuxData<gtirb::schema::FunctionBlocks>()) {
    for (const auto& [FnId, _] : *Functions) {
      (void)_;
      SS.stackStampFunction(M, FnId);
    }
  }
}

void gtirb_stack_stamp::registerAuxDataSchema() {
  gtirb::AuxDataContainer::registerAuxDataType<gtirb::schema::FunctionBlocks>();
  gtirb::AuxDataContainer::registerAuxDataType<
      gtirb::schema::FunctionEntries>();
}
