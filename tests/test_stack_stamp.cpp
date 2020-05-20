
#include "gtest/gtest.h"
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

TEST_F(GtirbStackStampFixture, TestName) {}
