#include <gtest/gtest.h>
#include <gtirb_stack_stamp/gtirb_stack_stamp.hpp>

static bool alreadySetUp = false;

class GtirbStackStampFixture : public ::testing::Test {
protected:
  virtual void SetUp() override {
    if (!alreadySetUp) {
      alreadySetUp = true;
      gtirb_stack_stamp::registerAuxDataSchema();
    }
  }
};

TEST_F(GtirbStackStampFixture, TestInsertInstructions) {
  ks_engine* Keystone;
  auto KSRet =
      ks_open(KS_ARCH_X86, KS_MODE_LITTLE_ENDIAN | KS_MODE_64, &Keystone);
  ASSERT_EQ(KSRet, KS_ERR_OK);
  ks_option(Keystone, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);

  std::string InstructionsToInsert = "ret;";

  unsigned char* Bytes;
  size_t BytesLen, StatCount;
  [[maybe_unused]] auto KSRes = ks_asm(Keystone, InstructionsToInsert.c_str(),
                                       0, &Bytes, &BytesLen, &StatCount);
  ASSERT_EQ(KSRes, KS_ERR_OK);

  std::string BIContents = "\x01\x02\x03\x04\x05\x06\x07\x08";
  gtirb::Context Ctx;
  auto* IR = gtirb::IR::Create(Ctx);
  auto* M = IR->addModule(Ctx);
  auto* S = M->addSection(Ctx, ".text");
  auto* BI = S->addByteInterval(Ctx, BIContents.begin(), BIContents.end());
  auto* B1 = BI->addBlock<gtirb::CodeBlock>(Ctx, 0, 3);
  auto* B2 = BI->addBlock<gtirb::CodeBlock>(Ctx, 2, 4);
  auto* B3 = BI->addBlock<gtirb::CodeBlock>(Ctx, 4, 2);
  auto* B4 = BI->addBlock<gtirb::CodeBlock>(Ctx, 6, 1);

  gtirb_stack_stamp::StackStamper SS{Ctx};
  SS.insertInstructions(*BI, 4, InstructionsToInsert);

  ASSERT_EQ(std::string(BI->bytes_begin<char>(), BI->bytes_end<char>()),
            BIContents.substr(0, 4) + std::string(Bytes, Bytes + BytesLen) +
                BIContents.substr(4, 4));

  ASSERT_EQ(B1->getOffset(), 0);
  ASSERT_EQ(B1->getSize(), 3);
  ASSERT_EQ(B2->getOffset(), 2);
  ASSERT_EQ(B2->getSize(), 4 + BytesLen);
  ASSERT_EQ(B3->getOffset(), 4);
  ASSERT_EQ(B3->getSize(), 2 + BytesLen);
  ASSERT_EQ(B4->getOffset(), 6 + BytesLen);
  ASSERT_EQ(B4->getSize(), 1);
}