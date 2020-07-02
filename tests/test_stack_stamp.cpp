//===- test_stack_stamp.cpp -------------------------------------*- C++ -*-===//
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

#include <boost/filesystem.hpp>
#include <cstdlib>
#include <gtest/gtest.h>

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
  ks_err KSRet =
      ks_open(KS_ARCH_X86, KS_MODE_LITTLE_ENDIAN | KS_MODE_64, &Keystone);
  ASSERT_EQ(KSRet, KS_ERR_OK);
  ks_option(Keystone, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);

  std::string InstructionsToInsert = "ret;";

  unsigned char* Bytes;
  size_t BytesLen, StatCount;
  [[maybe_unused]] int KSRes = ks_asm(Keystone, InstructionsToInsert.c_str(), 0,
                                      &Bytes, &BytesLen, &StatCount);
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
  BI->addSymbolicExpression<gtirb::SymAddrConst>(2, 0, nullptr);
  BI->addSymbolicExpression<gtirb::SymAddrConst>(4, 0, nullptr);
  BI->addSymbolicExpression<gtirb::SymAddrConst>(6, 0, nullptr);

  gtirb_stack_stamp::StackStamper SS{Ctx};
  SS.insertInstructions(*BI, 4, InstructionsToInsert);

  EXPECT_EQ(std::string(BI->bytes_begin<char>(), BI->bytes_end<char>()),
            BIContents.substr(0, 4) + std::string(Bytes, Bytes + BytesLen) +
                BIContents.substr(4, 4));
  EXPECT_EQ(std::distance(BI->blocks_begin(), BI->blocks_end()), 4);

  EXPECT_EQ(B1->getOffset(), 0);
  EXPECT_EQ(B1->getSize(), 3);
  EXPECT_EQ(B2->getOffset(), 2);
  EXPECT_EQ(B2->getSize(), 4 + BytesLen);
  EXPECT_EQ(B3->getOffset(), 4);
  EXPECT_EQ(B3->getSize(), 2 + BytesLen);
  EXPECT_EQ(B4->getOffset(), 6 + BytesLen);
  EXPECT_EQ(B4->getSize(), 1);

  EXPECT_EQ(std::distance(BI->symbolic_expressions_begin(),
                          BI->symbolic_expressions_end()),
            3);
  std::set<uint64_t> Offsets{{2, 4 + BytesLen, 6 + BytesLen}};
  const auto Pred = [&Offsets](uint64_t Off) { return Offsets.count(Off); };

  for (auto SEE : BI->symbolic_expressions()) {
    EXPECT_PRED1(Pred, SEE.getOffset());
    Offsets.erase(SEE.getOffset());
  }
}

TEST_F(GtirbStackStampFixture, TestStackStamp) {
  boost::filesystem::current_path("tests");
  std::remove("factorial.gtirb.stamp");
  std::remove("factorial.stamp");

  ASSERT_EQ(std::system("make factorial -B"), EXIT_SUCCESS);
  ASSERT_EQ(std::system("ddisasm factorial --ir factorial.gtirb"),
            EXIT_SUCCESS);

  gtirb::Context Ctx;
  gtirb::IR* Ir;
  {
    std::ifstream File{"factorial.gtirb"};
    auto ErrorOrIr = gtirb::IR::load(Ctx, File);
    ASSERT_TRUE(ErrorOrIr);
    Ir = *ErrorOrIr;
  }

  for (auto& M : Ir->modules()) {
    gtirb_stack_stamp::stamp(Ctx, M);
  }

  {
    std::ofstream File{"factorial.gtirb.stamp"};
    Ir->save(File);
    ASSERT_TRUE(File);
  }

  ASSERT_EQ(std::system("gtirb-pprinter factorial.gtirb.stamp --binary "
                        "factorial.stamp"),
            EXIT_SUCCESS);
  ASSERT_TRUE(boost::filesystem::exists("factorial.stamp"));

  auto* TempFile = std::tmpnam(nullptr);
  int ReturnCode =
      std::system(("./factorial.stamp 10 > " + std::string{TempFile}).c_str());
  std::string Output;
  {
    std::ifstream File{TempFile};
    std::noskipws(File);
    File >> Output;
  }
  std::remove(TempFile);

  ASSERT_EQ(ReturnCode, EXIT_SUCCESS);
  EXPECT_EQ(Output, "Factorial(10)=3628800");
}
