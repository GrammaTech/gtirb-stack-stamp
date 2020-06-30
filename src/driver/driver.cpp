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

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <fstream>
#include <iostream>

namespace po = boost::program_options;

int main(int ArgC, char** ArgV) {
  po::options_description Desc("gtirb-stack-stamp - modifies binaries with a "
                               "simple ROP-protection tool.\n\n"
                               "Allowed options");
  Desc.add_options()("help,h", "Produce this help message.");
  Desc.add_options()("in,i", po::value<std::string>()->required(),
                     "Input GTIRB file.");
  Desc.add_options()("out,o", po::value<std::string>()->required(),
                     "Output GTIRB file.");

  po::positional_options_description PD;
  PD.add("in", 1);
  PD.add("out", 1);

  po::variables_map VM;
  try {
    po::store(
        po::command_line_parser(ArgC, ArgV).options(Desc).positional(PD).run(),
        VM);
    if (VM.count("help") != 0) {
      std::cerr << Desc << std::endl;
      return EXIT_FAILURE;
    }
    po::notify(VM);
  } catch (std::exception& E) {
    std::cerr << "error: " << E.what() << ". Try '" << ArgV[0]
              << " --help' for more information." << std::endl;
    return EXIT_FAILURE;
  }

  gtirb_stack_stamp::registerAuxDataSchema();
  gtirb::Context Ctx;
  gtirb::IR* Ir;

  boost::filesystem::path InputPath = VM["in"].as<std::string>();
  std::cerr << "Reading GTIRB file: " << InputPath << std::endl;
  std::ifstream InputStream(InputPath.string(),
                            std::ios::in | std::ios::binary);
  if (auto ErrorOrIR = gtirb::IR::load(Ctx, InputStream)) {
    Ir = *ErrorOrIR;
  } else {
    std::cerr << "error: " << ErrorOrIR.getError().message() << std::endl;
    return EXIT_FAILURE;
  }

  for (auto& M : Ir->modules()) {
    std::cerr << "Stack stamping module '" << M.getBinaryPath() << "'..."
              << std::endl;
    gtirb_stack_stamp::stamp(Ctx, M);
  }

  boost::filesystem::path OutputPath = VM["out"].as<std::string>();
  std::cerr << "Writing to GTIRB file: " << OutputPath << std::endl;
  std::ofstream OutputStream(OutputPath.string(),
                             std::ios::out | std::ios::binary);
  Ir->save(OutputStream);

  std::cerr << "Output written successfully. " << std::endl;
  return EXIT_SUCCESS;
}
