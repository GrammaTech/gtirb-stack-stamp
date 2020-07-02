//===- gtirb_stack_stamp.cpp ------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
//
//  This code is licensed under the MIT license. See the LICENSE file in the
//  project root for license terms.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//

#include "gtirb_stack_stamp/gtirb_stack_stamp.hpp"

#include <capstone/x86.h>
#include <ios>
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
    // Increase in size any blocks that intersect with the new bytes.
    Block.setSize(BlockSize + Size);
  } else if (BlockOff >= Offset) {
    // Move any blocks over that occur after the inserted bytes.
    Block.getByteInterval()->addBlock(BlockOff + Size, &Block);
  }
}

static std::string getStampAssembly(const gtirb::UUID& FunctionId) {
  // All that matters for these two numbers is that they are the same given the
  // same function UUID. Thus, we just take the UUID's 128-bit contents and
  // convert it into two 32-bit numbers, selected from the beginning and the end
  // of the region (as to avoid the fixed bits in the middle set to "4").
  uint32_t Num1 = *reinterpret_cast<const uint32_t*>(FunctionId.data),
           Num2 = *(reinterpret_cast<const uint32_t*>(FunctionId.data) + 3);

  std::ostringstream ss;
  ss << "xorl $0x" << std::hex << Num1 << ",(%rsp); xorl $0x" << std::hex
     << Num2 << ",4(%rsp);";
  return ss.str();
}

gtirb_stack_stamp::CapstoneExecution::CapstoneExecution(
    const gtirb_stack_stamp::StackStamper& Stamper,
    const gtirb::CodeBlock& Block) {
  assert(Block.getByteInterval() && "Block must belong to a byte interval");

  gtirb::Addr A{0};
  if (auto BA = Block.getAddress()) {
    A = *BA;
  }

  const uint8_t* RawBytes;
  std::vector<uint8_t> RawBytesVector;
  if (auto* BI = Block.getByteInterval();
      Block.getOffset() + Block.getSize() <= BI->getInitializedSize()) {
    RawBytes = Block.rawBytes<uint8_t>();
  } else {
    std::copy(Block.bytes_begin<uint8_t>(), Block.bytes_end<uint8_t>(),
              std::back_inserter(RawBytesVector));
    RawBytes = RawBytesVector.data();
  }

  NumInstructions = cs_disasm(Stamper.Capstone, RawBytes, Block.getSize(),
                              static_cast<uint64_t>(A), 0, &Instructions);
}

gtirb_stack_stamp::CapstoneExecution::~CapstoneExecution() {
  if (Instructions) {
    cs_free(Instructions, NumInstructions);
  }
}

gtirb_stack_stamp::KeystoneExecution::KeystoneExecution(
    const gtirb_stack_stamp::StackStamper& Stamper, const std::string& Asm,
    gtirb::Addr Addr) {
  size_t StatCount;
  [[maybe_unused]] int KSRes =
      ks_asm(Stamper.Keystone, Asm.c_str(), static_cast<uint64_t>(Addr), &Bytes,
             &NumBytes, &StatCount);
  assert(KSRes == KS_ERR_OK);
}

gtirb_stack_stamp::KeystoneExecution::~KeystoneExecution() {
  if (Bytes) {
    ks_free(Bytes);
  }
}

void gtirb_stack_stamp::StackStamper::insertInstructions(
    gtirb::ByteInterval& BI, uint64_t Offset,
    const std::string& InsnsStr) const {
  assert(BI.getSection() && BI.getSection()->getModule() &&
         "BI must belong to a section and a module");

  gtirb::Addr Addr{0};
  if (auto BiAddr = BI.getAddress()) {
    Addr = *BiAddr + Offset;
  }

  KeystoneExecution Asm{*this, InsnsStr, Addr};
  const unsigned char* Bytes = Asm.getBytes();
  size_t BytesLen = Asm.getNumBytes();

  // Modify contents.
  BI.insertBytes<unsigned char>(BI.bytes_begin<unsigned char>() + Offset, Bytes,
                                Bytes + BytesLen);

  // Modify blocks.
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

  // Modify symbolic expressions.
  std::vector<std::tuple<uint64_t, gtirb::SymbolicExpression>> SEEs;
  for (const auto SEE : BI.symbolic_expressions()) {
    if (SEE.getOffset() >= Offset) {
      SEEs.emplace_back(SEE.getOffset(), SEE.getSymbolicExpression());
    }
  }
  for (const auto& SEE : SEEs) {
    BI.removeSymbolicExpression(std::get<0>(SEE));
  }
  for (const auto& SEE : SEEs) {
    BI.addSymbolicExpression(std::get<0>(SEE) + BytesLen, std::get<1>(SEE));
  }

  // Modify any affected aux data.
  if (const auto* CFIs = BI.getSection()
                             ->getModule()
                             ->getAuxData<gtirb::schema::CfiDirectives>()) {
    gtirb::schema::CfiDirectives::Type NewCFIs;
    for (const auto& [BlockOffset, Directive] : *CFIs) {
      const auto* CB = dyn_cast_or_null<gtirb::CodeBlock>(
          gtirb::Node::getByUUID(Ctx, BlockOffset.ElementId));
      if (!CB || CB->getByteInterval() != &BI ||
          CB->getOffset() + BlockOffset.Displacement < Offset ||
          CB->getOffset() > Offset ||
          CB->getOffset() + CB->getSize() <= Offset) {
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
  assert(Block.getByteInterval() && "Block must belong to a byte interval");
  insertInstructions(*Block.getByteInterval(), Block.getOffset(),
                     getStampAssembly(FunctionId));
}

void gtirb_stack_stamp::StackStamper::stampExitBlock(
    const gtirb::UUID& FunctionId, gtirb::CodeBlock& Block) const {
  CapstoneExecution Disasm{*this, Block};

  uint64_t Offset = Block.getOffset();
  for (size_t I = 0; I < Disasm.getNumInstructions(); I++) {
    const cs_insn& Insn = Disasm.getInstructions()[I];
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
  assert(Block.getByteInterval() && "Block must belong to a byte interval");

  CapstoneExecution Disasm{*this, Block};
  size_t NumInstrcutions = Disasm.getNumInstructions();
  return NumInstrcutions != 0 &&
         Disasm.getInstructions()[NumInstrcutions - 1].id == X86_INS_RET;
}

void gtirb_stack_stamp::StackStamper::stampFunction(
    gtirb::Module& M, const gtirb::UUID& FunctionId) const {
  // Get the aux data.
  const auto* AllBlocks = M.getAuxData<gtirb::schema::FunctionBlocks>();
  const auto* AllEntries = M.getAuxData<gtirb::schema::FunctionEntries>();

  if (!AllBlocks || !AllEntries) {
    return;
  }

  // If there are no entrance or exit blocks, don't add either.
  if (AllEntries->at(FunctionId).empty()) {
    return;
  }

  std::vector<gtirb::CodeBlock*> ExitBlocks;
  for (const auto& BlockId : AllBlocks->at(FunctionId)) {
    if (auto* Block = dyn_cast_or_null<gtirb::CodeBlock>(
            gtirb::Node::getByUUID(Ctx, BlockId));
        Block && isExitBlock(*Block)) {
      ExitBlocks.push_back(Block);
    }
  }
  if (ExitBlocks.empty()) {
    return;
  }

  // Handle entrance blocks.
  for (const auto& BlockId : AllEntries->at(FunctionId)) {
    if (auto* Block = dyn_cast_or_null<gtirb::CodeBlock>(
            gtirb::Node::getByUUID(Ctx, BlockId))) {
      stampEntranceBlock(FunctionId, *Block);
    }
  }

  // Handle exit blocks.
  for (auto* Block : ExitBlocks) {
    stampExitBlock(FunctionId, *Block);
  }
}

void gtirb_stack_stamp::stamp(gtirb::Context& Ctx, gtirb::Module& M) {
  gtirb_stack_stamp::StackStamper SS{Ctx};
  if (const auto* Functions = M.getAuxData<gtirb::schema::FunctionBlocks>()) {
    for (const auto& [FnId, _] : *Functions) {
      (void)_; // This line is necesary so GCC compilers <= 7 don't complain
               // about unused variables.
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
