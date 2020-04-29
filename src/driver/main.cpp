
#include <gtirb/gtirb.hpp>
#include <gtirb/Context.hpp>
#include <gtirb/IR.hpp>
#include <gtirb/version.h>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <boost/program_options.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <sstream>
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

class RewritingContext
{
public:
    typedef unsigned char encoding_t;

    RewritingContext(csh cph = 0, ks_engine* ksh = NULL)
    {
        if ( cph == 0) {
              [[maybe_unused]] int Ret = cs_open(CS_ARCH_X86, CS_MODE_64,
                  &cs_handle_);
              assert(Ret == CS_ERR_OK);
              cs_option(cs_handle_, CS_OPT_DETAIL, CS_OPT_ON);
        }
        else
            cs_handle_ = cph;

        if ( ksh == 0 ) {
            auto err = ks_open(KS_ARCH_X86, KS_MODE_LITTLE_ENDIAN | KS_MODE_64,
                &ks_handle_);
            std::cout << "err: " << err << std::endl;
            assert (err == KS_ERR_OK);
            ks_option(ks_handle_, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
        }
        else
            ks_handle_ = ksh;
    }

    ~RewritingContext() {
        for ( auto& p : encoding_mem ) {
            ks_free(p);
        }
    }

    void show_asm(CodeBlock *node)
    {
    cs_insn* instructions;

        size_t count = cs_disasm(cs_handle_, node->rawBytes<uint8_t>(),
            node->getSize(),
            (uint64_t)node->getAddress().value_or(Addr(0)), 0, &instructions);

        for (size_t i = 0; i < count; i++) {
            const auto& instruction = instructions[i];
            std::cout << std::setbase(16) << std::setfill('0') << std::setw(8)
                << std::right
                << instruction.address << ": " 
                << instruction.mnemonic << " "
                << instruction.op_str << std::endl;
        }
    }

    std::string to_hex(unsigned char *bytes, size_t nbytes) {
        std::stringstream res;
            for (int i ; i < nbytes ; i++)
                res << std::setw(2) << std::setfill ('0') << 
                  std::hex << static_cast<int>(bytes[i]);
       return std::string(res.str().c_str());
    }

    encoding_t* make_asm(IR *ir, const char* inst_stmts) {
        encoding_t *encoding;
        size_t encoding_nbytes, stmt_cnt;

        int res = ks_asm(ks_handle_, "xorl $0x85,(%rsp);xorl $0xaa,4(%rsp);\n",
            0, &encoding, &encoding_nbytes, &stmt_cnt);
        if (res != 0){
            std::cout << "err: " << ks_strerror(ks_errno(ks_handle_)) << std::endl;
            return NULL;
        }
        else {
            std::cout << "stmts: " << stmt_cnt << " nbytes: " << encoding_nbytes
                << std::endl;
            std::string my_encoding = to_hex(encoding, encoding_nbytes);
            std::cout << "My encoding: " << my_encoding << std::endl;
            encoding_mem.push_back(encoding);
            return encoding;
        }
    }

    void prepare_for_rewriting(Context &ctx, IR *ir)
    {
        // for m in modules
        std::cout << "Preparing IR for rewriting ";
        for ( auto &m : ir->modules() ) {
            std::list<CodeBlock*> my_blocks;
            for ( auto &cb : m.code_blocks() )
                my_blocks.push_back(&cb);
            
            for ( auto &cb : my_blocks ) {
                if (cb->getOffset() != 0 || 
                        cb->getSize() != cb->getByteInterval()->getSize()) {
                    std::cout << ".";
                    isolate_bi(ctx, m, cb);
                }
            }
        }
        std::cout << std::endl;
        //
        // remove cfiDirectives aux_data
    }

    void isolate_bi(Context &ctx, Module &module, CodeBlock *cb)
    {
        
        std::cout << "Code Block: " << cb->getOffset() << std::endl;
        show_asm(cb);
        uint64_t old_offset = cb->getOffset();
        ByteInterval *old_bi = cb->getByteInterval();
        ByteInterval *new_bi =
            ByteInterval::Create(ctx,
                    cb->bytes_begin<uint8_t>(),
                    cb->bytes_end<uint8_t>());

        auto sym_expr_range = old_bi->findSymbolicExpressionsAtOffset(
                old_offset,old_offset + cb->getSize());
        while ( !sym_expr_range.empty() )
        {
            std::cout << "symex" << std::endl;
            auto s = sym_expr_range.begin();
            auto old_se_offset = s->getOffset();
            new_bi->addSymbolicExpression(
                    old_se_offset-old_offset,
                    s->getSymbolicExpression());
            old_bi->removeSymbolicExpression(old_se_offset);
            sym_expr_range = old_bi->findSymbolicExpressionsAtOffset(
                    old_offset,old_offset + cb->getSize());
        }

        new_bi->addBlock(0, cb);
        old_bi->removeBlock(cb);
    }

protected:
    std::list<encoding_t*> encoding_mem;
    csh cs_handle_;
    ks_engine *ks_handle_; 

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
        RewritingContext rw_ctx = RewritingContext();

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
                for (auto& block_uuid : f->entry_blocks) {
                    auto block =
                        static_cast<gtirb::CodeBlock*>(Node::getByUUID(ctx,
                                    block_uuid));
                    rw_ctx.show_asm(block);
                }
            }
        }

        /* rw_ctx.make_asm(ir, NULL); */
        rw_ctx.prepare_for_rewriting(ctx, ir);

        std::ofstream out_gtirb(irPath.string()+".gtirb");
        ir->save(out_gtirb);
        out_gtirb.close();

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

