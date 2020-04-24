
#include <gtirb/gtirb.hpp>
#include <gtirb/Context.hpp>
#include <gtirb/IR.hpp>
#include <gtirb/version.h>

#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <boost/program_options.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <cstdint>
#include "Logger.h"

using namespace gtirb;

void register_aux_data_types() {
    using namespace gtirb::schema;
    gtirb::AuxDataContainer::registerAuxDataType<FunctionEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionBlocks>();
}

class Function
{
public:
    Function(gtirb::UUID uuid) : fn_uuid(uuid) { } 

    std::set<gtirb::UUID> entry_blocks;
    std::set<gtirb::UUID> exit_blocks;
    std::set<gtirb::UUID> blocks;
    std::set<const gtirb::Symbol*> name_symbols;

    void dump() {
        std::cout << "Function " << get_name() << std::endl;
        std::cout << "\t" << "Total/Entry/Exit blocks: " 
            << blocks.size() << "/"
            << entry_blocks.size() << "/"
            << exit_blocks.size()
            << std::endl;
    }

    std::string get_name() {
        std::string primary, aka;

        for (auto& s : name_symbols) {
            if (primary.empty())
                primary = s->getName();
            else if (aka.empty())
                aka = s->getName();
            else {
                aka += ",";
                aka += s->getName();
            }
        }
        if (primary.empty())
            return "<unknown>";
        else if (aka.empty())
            return primary;
        else
            return primary + "(" + aka + ")";
    }

protected:
    gtirb::UUID fn_uuid;

};

class FunctionList : public std::list<Function*>
{
public:
    ~FunctionList() {
        for (auto& f : *this)
            delete f;
    }

    static FunctionList* build_functions(
            const IR* ir, Context &ctx, const Module &m )
    {
        FunctionList *functions = new FunctionList();
        auto cfg = ir->getCFG();

        const auto& fn_entries = *(m.getAuxData<schema::FunctionEntries>());
        const auto& fn_blocks = *(m.getAuxData<schema::FunctionBlocks>());
        for (auto& [fn_uuid, entries] : fn_entries) {
            Function *function = new Function(fn_uuid);
            functions->push_back(function);

            // Entry blocks and entry symbols
            for (auto& e : entries ) {
                function->entry_blocks.insert(e);
                Node *n = Node::getByUUID(ctx, e);
                for (auto& s : m.findSymbols(*n)) {
                    function->name_symbols.insert(&s);
                }
            }

            // All blocks
            auto found = fn_blocks.find(fn_uuid);
            if (found != fn_blocks.end()) {
                for (auto& b : found->second) {
                    function->blocks.insert(b);
                }
            }

            // Exit blocks
            using Vertex = CFG::vertex_descriptor;
            for (auto& b : function->blocks) {
                Node* n = Node::getByUUID(ctx,b);
                if (n->getKind() == Node::Kind::CodeBlock) {
                    CfgNode* cfg_node = static_cast<CfgNode*>(n);
                    auto vtx = getVertex( cfg_node, cfg);
                    bool bool_var;
                    // Check all outgoing edges from this vertex
                    auto [begin, end] = out_edges(*vtx, cfg);

                    for (auto& it = begin; it != end; it++) {
                        // If edge target has not been visited, do so now
                        if (std::get<EdgeType>(*cfg[*it]) == EdgeType::Return) {
                            function->exit_blocks.insert(b);
                        }
                    }
                }
            }
        }
        return functions;
    }
};

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
        std::cout << desc << std::endl;
        return 1;
    }

    boost::program_options::notify(vm);

    boost::filesystem::path irPath = vm["in"].as<std::string>();

    if(boost::filesystem::exists(irPath) == true)
    {
        register_aux_data_types();
        gtirb::Context ctx;

        LOG_INFO << std::setw(24) << std::left << "Reading IR: "
            << irPath << std::endl;
        std::ifstream in(irPath.string());
        gtirb::IR* ir = gtirb::IR::load(ctx, in);
        in.close();

        for ( auto m = ir->modules_begin(); m != ir->modules_end(); m++)
        {

            FunctionList *functions = FunctionList::build_functions( ir, ctx, *m );
            for (auto& f : *functions) {
                f->dump();
            }
        }

        /* // Perform the Pretty Printing step. */
        /* LOG_INFO << std::setw(24) << std::left << "Pretty-printing hints..." */
        /*          << std::endl; */
    }
    else {
        LOG_ERROR << "IR not found: \"" << irPath << "\".";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

