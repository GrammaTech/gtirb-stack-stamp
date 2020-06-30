/*******************************************************************************
Copyright (C) 2020 GrammaTech, Inc.

This code is licensed under the MIT license. See the LICENSE file in
the project root for license terms.

This project is sponsored by the Office of Naval Research, One Liberty
Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
N68335-17-C-0700.  The content of the information does not necessarily
reflect the position or policy of the Government and no official
endorsement should be inferred.
*******************************************************************************/

#include "gtirb_stack_stamp/gtirb_stack_stamp.hpp"

#include <capstone/x86.h>
#include <ios>
#include <random>
#include <sstream>

namespace gtirb {
namespace schema {

struct CfiDirectives {
  static constexpr const char* Name = "cfiDirectives";
  typedef std::map<
      gtirb::Offset,
      std::vector<std::tuple<std::string, std::vector<int64_t>, gtirb::UUID>>>
      Type;
};

struct SymbolicExpressionSizes {
  static constexpr const char* Name = "symbolicExpressionSizes";
  typedef std::map<gtirb::Offset, uint64_t> Type;
};

} // namespace schema
} // namespace gtirb

template <typename BlockType>
static void modifyBlock(BlockType& Block, uint64_t Offset, uint64_t Size) {
  uint64_t BlockOff = Block.getOffset(), BlockSize = Block.getSize();

  if (BlockOff <= Offset && BlockOff + BlockSize > Offset) {
    // increase in size any blocks that intersect with the new bytes
    Block.setSize(BlockSize + Size);
  } else if (BlockOff >= Offset) {
    // move any blocks over that occur after the inserted bytes
    Block.getByteInterval()->addBlock(BlockOff + Size, &Block);
  }
}

static std::string getStampAssembly(const gtirb::UUID& FunctionId) {
  uint64_t Seed = 1;
  for (uint8_t Byte : FunctionId) {
    Seed *= Byte;
  }
  std::mt19937_64 Rng{Seed};

  std::ostringstream ss;
  ss << "xorl $0x" << std::hex << Rng() << ",(%rsp); xorl $0x" << std::hex
     << Rng() << ",4(%rsp);";
  return ss.str();
}

void gtirb_stack_stamp::StackStamper::insertInstructions(
    gtirb::ByteInterval& BI, uint64_t Offset,
    const std::string& InsnsStr) const {
  gtirb::Addr Addr{0};
  if (auto BiAddr = BI.getAddress()) {
    Addr = *BiAddr + Offset;
  }

  unsigned char* Bytes;
  size_t BytesLen, StatCount;
  [[maybe_unused]] int KSRes =
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
  std::vector<std::tuple<uint64_t, gtirb::SymbolicExpression>> SEEs;
  for (const auto SEE : BI.symbolic_expressions()) {
    if (SEE.getOffset() >= Offset) {
      SEEs.emplace_back(SEE.getOffset(), SEE.getSymbolicExpression());
      BI.removeSymbolicExpression(SEE.getOffset());
    }
  }
  for (const auto& SEE : SEEs) {
    BI.addSymbolicExpression(std::get<0>(SEE) + BytesLen, std::get<1>(SEE));
  }

  // modify any affected aux data
  if (const auto* CFIs = BI.getSection()
                             ->getModule()
                             ->getAuxData<gtirb::schema::CfiDirectives>()) {
    gtirb::schema::CfiDirectives::Type NewCFIs;
    for (const auto& [BlockOffset, Directive] : *CFIs) {
      const auto* CB = cast<gtirb::CodeBlock>(
          gtirb::Node::getByUUID(Ctx, BlockOffset.ElementId));
      if (CB->getByteInterval() != &BI ||
          CB->getOffset() + BlockOffset.Displacement < Offset ||
          !(CB->getOffset() <= Offset &&
            CB->getOffset() + CB->getSize() > Offset)) {
        NewCFIs[BlockOffset] = Directive;
      } else {
        gtirb::Offset NewOffset = BlockOffset;
        NewOffset.Displacement += BytesLen;
        NewCFIs[NewOffset] = Directive;
      }
    }
    BI.getSection()->getModule()->addAuxData<gtirb::schema::CfiDirectives>(
        std::move(NewCFIs));
  }

  if (const auto* SymExprSizes =
          BI.getSection()
              ->getModule()
              ->getAuxData<gtirb::schema::SymbolicExpressionSizes>()) {
    gtirb::schema::SymbolicExpressionSizes::Type NewSES;
    for (const auto& [BIOffset, Size] : *SymExprSizes) {
      if (BIOffset.ElementId != BI.getUUID() ||
          BIOffset.Displacement < Offset) {
        NewSES[BIOffset] = Size;
      } else {
        gtirb::Offset NewOffset = BIOffset;
        NewOffset.Displacement += BytesLen;
        NewSES[NewOffset] = Size;
      }
    }
    BI.getSection()
        ->getModule()
        ->addAuxData<gtirb::schema::SymbolicExpressionSizes>(std::move(NewSES));
  }
}

void gtirb_stack_stamp::StackStamper::stampEntranceBlock(
    const gtirb::UUID& FunctionId, gtirb::CodeBlock& Block) const {
  insertInstructions(*Block.getByteInterval(), Block.getOffset(),
                     getStampAssembly(FunctionId));
}

void gtirb_stack_stamp::StackStamper::stampExitBlock(
    const gtirb::UUID& FunctionId, gtirb::CodeBlock& Block) const {
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
    const cs_insn& Insn = Insns[I];
    if (Insn.id == X86_INS_RET) {
      insertInstructions(*Block.getByteInterval(), Offset,
                         getStampAssembly(FunctionId));
      break;
    } else {
      Offset += Insn.size;
    }
  }
}

bool gtirb_stack_stamp::StackStamper::isExitBlock(
    const gtirb::CodeBlock& Block) const {
  gtirb::Addr A{0};
  if (auto BA = Block.getAddress()) {
    A = *BA;
  }

  cs_insn* Insns;
  size_t InsnsLen =
      cs_disasm(Capstone, Block.rawBytes<uint8_t>(), Block.getSize(),
                static_cast<uint64_t>(A), 0, &Insns);
  return Insns[InsnsLen - 1].id == X86_INS_RET;
}

void gtirb_stack_stamp::StackStamper::stampFunction(
    gtirb::Module& M, const gtirb::UUID& FunctionId) const {
  // get aux data
  const auto* AllBlocks = M.getAuxData<gtirb::schema::FunctionBlocks>();
  const auto* AllEntries = M.getAuxData<gtirb::schema::FunctionEntries>();

  if (!AllBlocks || !AllEntries) {
    return;
  }

  // if there are no entrance or exit blocks, don't add either
  if (AllEntries->at(FunctionId).empty()) {
    return;
  }

  std::vector<gtirb::CodeBlock*> ExitBlocks;
  for (const auto& BlockId : AllBlocks->at(FunctionId)) {
    auto& Block = *cast<gtirb::CodeBlock>(gtirb::Node::getByUUID(Ctx, BlockId));
    if (isExitBlock(Block)) {
      ExitBlocks.push_back(&Block);
    }
  }
  if (ExitBlocks.empty()) {
    return;
  }

  // handle entrance blocks
  for (const auto& BlockId : AllEntries->at(FunctionId)) {
    stampEntranceBlock(FunctionId, *cast<gtirb::CodeBlock>(
                                       gtirb::Node::getByUUID(Ctx, BlockId)));
  }

  // handle exit blocks
  for (auto* Block : ExitBlocks) {
    stampExitBlock(FunctionId, *Block);
  }
}

void gtirb_stack_stamp::stamp(gtirb::Context& Ctx, gtirb::Module& M) {
  gtirb_stack_stamp::StackStamper SS{Ctx};
  if (const auto* Functions = M.getAuxData<gtirb::schema::FunctionBlocks>()) {
    for (const auto& [FnId, _] : *Functions) {
      (void)_;
      SS.stampFunction(M, FnId);
    }
  }
}

void gtirb_stack_stamp::registerAuxDataSchema() {
  gtirb::AuxDataContainer::registerAuxDataType<gtirb::schema::FunctionBlocks>();
  gtirb::AuxDataContainer::registerAuxDataType<
      gtirb::schema::FunctionEntries>();
  gtirb::AuxDataContainer::registerAuxDataType<gtirb::schema::CfiDirectives>();
  gtirb::AuxDataContainer::registerAuxDataType<
      gtirb::schema::SymbolicExpressionSizes>();
}
