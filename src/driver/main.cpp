#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <boost/program_options.hpp>
#include <iomanip>
#include <iostream>
#include <fstream>
#include "Logger.h"
/* #include "GTIRBToSwyxHints.h" */

int main(int argc, char** argv)
{
    boost::program_options::options_description desc("Allowed options");
    desc.add_options()("help", "Produce help message.");
    desc.add_options()("decode,c",
                       boost::program_options::value<std::string>(),
                       "Decode a binary and call disasm.");
    desc.add_options()("dir,d",
                       boost::program_options::value<std::string>(),
                       "Set a datalog output directory to parse. "
                       "Automatically set (or overwtitten) by the "
                       "--decode optoin.");
    desc.add_options()("out,o",
                       boost::program_options::value<std::string>()->
                           default_value("out.hint"),
                       "The name of the hint output file.");
    desc.add_options()("debug,D",
                       boost::program_options::value<bool>()->
                           default_value(false),
                       "Turn on debugging (will break hint-generator)");

    boost::program_options::variables_map vm;
    boost::program_options::store(
             boost::program_options::parse_command_line(argc, argv, desc), vm);

    if(vm.count("help") != 0 || argc == 1)
    {
        std::cout << desc << "\n";
        return 1;
    }

    boost::program_options::notify(vm);

    boost::filesystem::path irPath;
    boost::filesystem::path disasmPath;

    if(vm.count("dir") != 0)
    {
        disasmPath = vm["dir"].as<std::string>();
    }

    if(vm.count("decode") != 0)
    {
        boost::filesystem::path exe = vm["decode"].as<std::string>();

        if(boost::filesystem::is_regular_file(exe) == true)
        {
            if (disasmPath.empty()) {
                const auto exePath = exe.parent_path();
                disasmPath = exePath / "dl_files/";
            }
            irPath = disasmPath / "gtirb";

            if(boost::filesystem::is_directory(disasmPath) == false)
            {
                if(boost::filesystem::create_directory(disasmPath) == false)
                {
                    LOG_ERROR << "Could not create directory "
                              << disasmPath << "." << std::endl;
                    return EXIT_FAILURE;
                }
                else
                {
                    LOG_INFO << "Created directory "
                             << disasmPath << std::endl;
                }
            }

            // Call ddisasm
            {
                std::stringstream cmd;
                cmd << "ddisasm " << exe << " --ir " << irPath;

                LOG_DEBUG << cmd.str() << std::endl;
                LOG_DEBUG << std::endl;

                try
                {
                    const auto datalogDecoderResult =
                                             boost::process::system(cmd.str());

                    if(datalogDecoderResult == 0)
                    {
                        LOG_INFO << "DDisasm Success." << std::endl;
                    }
                    else
                    {
                        LOG_ERROR << "DDisasm Failure." << std::endl
                                  << "\tCMD: \"" << cmd.str() << "\""
                                  << std::endl;
                        return EXIT_FAILURE;
                    }
                }
                catch(const std::exception& e)
                {
                    LOG_ERROR << e.what() << std::endl;
                    LOG_ERROR << "Make sure that \"disasm\" is in your PATH."
                              << std::endl;
                    return EXIT_FAILURE;
                }
            }
        }
        else
        {
            LOG_ERROR << "The parameter " << exe << " is not a file."
                      << std::endl;
            return EXIT_FAILURE;
        }
    }

    if(boost::filesystem::exists(irPath) == true)
    {
         gtirb::Context ctx;

         LOG_INFO << std::setw(24) << std::left << "Reading IR: "
                  << irPath << std::endl;
         std::ifstream in(irPath.string());
         gtirb::IR* ir = gtirb::IR::load(ctx, in);
         in.close();

         // Perform the Pretty Printing step.
         LOG_INFO << std::setw(24) << std::left << "Pretty-printing hints..."
                  << std::endl;
         /* GTIRBToSwyxHints pp(ctx, *ir); */
         /* pp.setDebug(vm["debug"].as<bool>()); */
         /* const auto hints = pp.prettyPrint(); */
    
         // Do we write it to a file?
         if (vm.count("out") != 0) {
             const auto outPath =
                          boost::filesystem::path(vm["out"].as<std::string>());
             std::ofstream ofs;
             ofs.open(outPath.string());
    
             if (ofs.is_open() == true) {
                 ofs << hints;
                 ofs.close();
                 LOG_INFO << "Hints written to: " << outPath << "\n";
             }
             else {
                 LOG_ERROR << "Could not output hint output file: "
                           << outPath << "\n";
                 return EXIT_FAILURE;
             }
         }
         else {
             std::cout << hints << std::endl;
         }
    }
    else {
         LOG_ERROR << "IR not found: \"" << irPath << "\".";
         return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

