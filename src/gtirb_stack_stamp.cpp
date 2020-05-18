#include <gtirb_stack_stamp/gtirb_stack_stamp.hpp>

template <typename BlockType>
static void modifyBlock(BlockType& Block, uint64_t Offset, uint64_t Size) {
  auto BlockOff = Block.getOffset();
  auto BlockSize = Block.getSize();

  if (BlockOff <= Offset && BlockOff + BlockSize < Offset) {
    // increase in size any blocks that intersect with the new bytes
    Block.setSize(BlockSize + Size);
  } else if (BlockOff >= Offset) {
    // move any blocks over that occur after the inserted bytes
    Block.getByteInterval()->addBlock<BlockType>(BlockOff + Size, &Block);
  }
}

void gtirb_stack_stamp::StackStamper::insertInstructions(
    gtirb::ByteInterval& BI, uint64_t Offset, const std::string& InsnsStr) {
  gtirb::Addr Addr{0};
  if (auto BiAddr = BI.getAddress()) {
    Addr = *BiAddr + Offset;
  }

  unsigned char* Bytes;
  size_t BytesLen, StatCount;
  auto KSRes = ks_asm(Keystone, InsnsStr.c_str(), static_cast<uint64_t>(Addr),
                      &Bytes, &BytesLen, &StatCount);
  assert(KSRes == 0);

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
  for (auto& SEE : SEEs {
    if (SEE.getOffset() >= Offset) {
      BI.removeSymbolicExpression(Offset);
      BI.addSymbolicExpression(Offset + BytesLen, SEE.getSymbolicExpression());
    }
  }
}

void gtirb_stack_stamp::StackStamper::stackStampEntranceBlock(
    gtirb::CodeBlock& Block) {}

void gtirb_stack_stamp::StackStamper::stackStampExitBlock(
    gtirb::CodeBlock& Block) {}

void gtirb_stack_stamp::StackStamper::stackStampFunction(
    gtirb::Module& M, const gtirb::UUID& FunctionId) {}

void gtirb_stack_stamp::stackStamp(gtirb::Module& M) {}

void gtirb_stack_stamp::registerAuxDataSchema() {}
