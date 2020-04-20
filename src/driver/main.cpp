
#include <gtirb/gtirb.hpp>
#include <gtirb/Context.hpp>
#include <gtirb/IR.hpp>
#include <gtirb/version.h>

#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <boost/program_options.hpp>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <cstdint>
#include "Logger.h"

void register_aux_data_types() {
  using namespace gtirb::schema;
  gtirb::AuxDataContainer::registerAuxDataType<FunctionEntries>();
  gtirb::AuxDataContainer::registerAuxDataType<FunctionBlocks>();
}

/* class Function */
/* { */

/* protected: */
/*     uuid */
/*     entry_blocks */
/*     exit_blocks */
/*     blocks */
/*     name_symbols */



/* }; */

int build_functions(const gtirb::IR* ir, const gtirb::Module &m )
{
  return 0;
}

int main(int argc, char** argv)
{
    boost::program_options::options_description desc("Allowed options");
    desc.add_options()("help", "Produce help message.");
    desc.add_options()("in,i",
                       boost::program_options::value<std::string>(),
                       "Input GTIRB file");
    desc.add_options()("out,o",
                       boost::program_options::value<std::string>()->
                           default_value("<in>.ss"),
                       "Output GTIRB file");
    /* desc.add_options()("debug,D", */
    /*                    boost::program_options::value<bool>()-> */
    /*                        default_value(false), */
    /*                    "Turn on debugging (will break hint-generator)"); */

    boost::program_options::variables_map vm;
    boost::program_options::store(
             boost::program_options::parse_command_line(argc, argv, desc), vm);

    if(vm.count("help") != 0 || argc == 1)
    {
        std::cout << desc << "\n";
        return 1;
    }

    boost::program_options::notify(vm);

    boost::filesystem::path irPath = vm["in"].as<std::string>();

    if(boost::filesystem::exists(irPath) == true)
    {
         gtirb::Context ctx;

         LOG_INFO << std::setw(24) << std::left << "Reading IR: "
                  << irPath << std::endl;
         std::ifstream in(irPath.string());
         gtirb::IR* ir = gtirb::IR::load(ctx, in);
         in.close();

         for ( auto m = ir->modules_begin(); m != ir->modules_end(); m++)
         {
             build_functions( ir, *m );
         }

         // Perform the Pretty Printing step.
         LOG_INFO << std::setw(24) << std::left << "Pretty-printing hints..."
                  << std::endl;
    }
    else {
         LOG_ERROR << "IR not found: \"" << irPath << "\".";
         return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

