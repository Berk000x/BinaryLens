// IDA SDK headers first to establish their environment
#include "../../ida-sdk/src/include/pro.h"
#include "../../ida-sdk/src/include/ida.hpp"
#include "../../ida-sdk/src/include/idp.hpp"
#include "../../ida-sdk/src/include/loader.hpp"
#include "../../ida-sdk/src/include/kernwin.hpp"
#include "../../ida-sdk/src/include/funcs.hpp"
#include "../../ida-sdk/src/include/name.hpp"
#include "../../ida-sdk/src/include/hexrays.hpp"

// After IDA headers, carefully include standard library with namespace protection
#ifdef __cplusplus
// Backup IDA SDK definitions
#pragma push_macro("vector")
#pragma push_macro("string") 
#pragma push_macro("thread")
#pragma push_macro("chrono")
// Temporarily undefine to allow std headers
#undef vector
#undef string
#undef thread
#undef chrono

#include <thread>
#include <string>
#include <vector>
#include <chrono>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <regex>
#include <algorithm>
#include <cstddef>

// Restore IDA SDK definitions
#pragma pop_macro("chrono")
#pragma pop_macro("thread") 
#pragma pop_macro("string")
#pragma pop_macro("vector")
#endif

// Temporarily undefine IDA SDK macros that conflict with third-party libraries
#ifdef snprintf
#undef snprintf
#endif
#ifdef wait
#undef wait  
#endif
#ifdef fgetc
#undef fgetc
#endif

// Third party headers
#include "../helper/httplib.h"

// Redefine IDA SDK macros after third-party includes
#define snprintf        dont_use_snprintf
#define wait            dont_use_wait
#define fgetc           dont_use_fgetc

// Local headers
#include "../helper/helper.h"
#include "plugin.h"

#if defined(_WIN32)
#include <windows.h>
#include <shlwapi.h>
#define PLUGIN_DWORD DWORD
#define PLUGIN_GetPrivateProfileStringA GetPrivateProfileStringA
#else
// Non-Windows platforms - provide stubs
typedef unsigned long PLUGIN_DWORD;
static PLUGIN_DWORD PLUGIN_GetPrivateProfileStringA(const char*, const char*, const char*, char*, size_t, const char*) {
    return 0; // Stub implementation for non-Windows
}
#endif

bool sub_rename_end = true;
bool var_rename_end = true;

int sub_ren_pass_count = 0;
qvector<qstring> failed_func_names;

bool IsSubPresentInBin() {
    int func_num = get_func_qty();

    LogMessage(LOG_PATH, 0, "IsSubPresentInBin func num: (%d)\n", func_num);

    std::string all_subs;
    for (int i = 0; i < func_num; i++) {
        func_t* cur_func = getn_func(i);
        if (cur_func == nullptr) {
            LogMessage(LOG_PATH, 0, "WARNING: (IsSubPresentInBin) getn_func(%d) returned nullptr.\n", i);
            return false;
        }

        qstring func_name;
        if (get_func_name(&func_name, cur_func->start_ea) <= 0) {
            LogMessage(LOG_PATH, 0, "WARNING: (IsSubPresentInBin) Failed to get function name at (%a)\n", cur_func->start_ea);
            return false;
        }

        // Skip previously failed funcs
        // Check if function name is in failed list (simple iteration due to IDA SDK conflicts)
        bool found_in_failed = false;
        for (const qstring& failed_name : failed_func_names) {
            if (failed_name == func_name) {
                found_in_failed = true;
                break;
            }
        }
        if (found_in_failed) {
            continue;
        }

        // Check if the funcs name starts with sub_
        if (qstrncmp(func_name.c_str(), "sub_", 4) == 0) {
            return true;
        }

        continue;
    }

    return false;
}

qstring RemoveVarDefinitions(const qstring& code) {
    // Simple filtering: keep lines without '=' assignments
    // (IDA SDK conflicts prevent using regex/stringstream)
    
    qstring result;
    const char* code_ptr = code.c_str();
    const char* line_start = code_ptr;
    
    while (*code_ptr) {
        if (*code_ptr == '\n') {
            qstring line(line_start, code_ptr - line_start);
            if (line.find('=') == qstring::npos) {
                result += line + "\n";
            }
            line_start = code_ptr + 1;
        }
        code_ptr++;
    }
    
    // Handle last line if no trailing newline
    if (line_start < code_ptr) {
        qstring line(line_start, code_ptr - line_start);
        if (line.find('=') == qstring::npos) {
            result += line;
        }
    }

    return result;
}

qstring GetFuncs() {
    int sub_num = 0;
    int func_num = get_func_qty();

    LogMessage(LOG_PATH, 0, "GetFuncs func num: (%d)\n", func_num);

    std::string all_subs;
    for (int i = 0; i < func_num; i++) {
        func_t* cur_func = getn_func(i);
        if (cur_func == nullptr) {
            LogMessage(LOG_PATH, 3, "ERROR: getn_func(%d) returned nullptr.\n", i);
            return qstring("");
        }

        qstring func_name;
        if (get_func_name(&func_name, cur_func->start_ea) <= 0) {
            LogMessage(LOG_PATH, 3, "Failed to get function name at (%a)\n", cur_func->start_ea);
            return qstring("");
        }

        // We don't want to give all functions, just the subs and main functions
        if (qstrncmp(func_name.c_str(), "sub_", 4) != 0 &&
            qstrncmp(func_name.c_str(), "main", 4) != 0 &&
            qstrncmp(func_name.c_str(), "WinMain", 7) != 0 &&
            qstrncmp(func_name.c_str(), "start", 5) != 0 &&
            qstrncmp(func_name.c_str(), "entry", 5) != 0 &&
            qstrncmp(func_name.c_str(), "DllMain", 7) != 0 &&
            qstrncmp(func_name.c_str(), "DriverEntry", 11) != 0) {
            continue;
        }

        cfuncptr_t cfunc = decompile(cur_func);
        if (cfunc == nullptr) {
            LogMessage(LOG_PATH, 1, "[BinaryLens] WARNING: Failed to decompile (%s), skiping it.\n", func_name.c_str());
            failed_func_names.push_back(func_name.c_str());
            continue;
        }

        const strvec_t& pseudocode = cfunc->get_pseudocode();
        if (pseudocode.empty()) {
            LogMessage(LOG_PATH, 1, "[BinaryLens] WARNING: No pseudocode available for function (%s)"
                ", skiping it.\n", func_name.c_str()
            );
            failed_func_names.push_back(func_name.c_str());
            continue;
        }

        sub_num++;

        for (const simpleline_t& line : pseudocode) {
            qstring clean_line = line.line;
            tag_remove(&clean_line);
            all_subs += clean_line.c_str();
            all_subs += "\n";
        }
        all_subs += "\n";
    }

    LogMessage(LOG_PATH, 0, "Total decompiled subs: (%d)\n", sub_num);

    return qstring(all_subs.c_str());
}

bool RenameSubsFromFile(qstring& renamed_funcs_path, int* renamed_sub_count) {
    int func_num = get_func_qty();
    LogMessage(LOG_PATH, 0, "RenameFuncs func num: (%d)\n", func_num);

    qstring all_funcs;
    for (int i = 0; i < func_num; i++) {
        func_t* cur_func = getn_func(i);
        if (cur_func == nullptr) {
            LogMessage(LOG_PATH, 3, "ERROR: getn_func(%d) returned nullptr.\n", i);
            return false;
        }

        qstring func_name;
        if (get_func_name(&func_name, cur_func->start_ea) <= 0) {
            LogMessage(LOG_PATH, 1, "[BinaryLens] WARNING: Failed to get function name at (%a)"
                ", skiping it.\n", cur_func->start_ea
            );
            continue;
        }

        // Skip if the funcs name doesn't start with sub_
        if (qstrncmp(func_name.c_str(), "sub_", 4) != 0) {
            continue;
        }

        char renamed_sub[256] = { 0 };
        PLUGIN_DWORD ReadConfig = PLUGIN_GetPrivateProfileStringA(
            "RenamedFunctions",
            func_name.c_str(),
            "",
            renamed_sub,
            sizeof(renamed_sub),
            renamed_funcs_path.c_str()
        );

        if (!ReadConfig) {
            LogMessage(LOG_PATH, 0, "WARNING: Function not found in response, skiping it: (%s)\n", func_name.c_str());
            continue;
        }

        if (!set_name(cur_func->start_ea, renamed_sub, SN_NOWARN | SN_FORCE)) {
            LogMessage(LOG_PATH, 1, "[BinaryLens] WARNING: Failed to rename (%s) to (%s)\n", func_name.c_str(), renamed_sub);
        }
        else {
            LogMessage(LOG_PATH, 0, "Renamed (%s) to (%s)\n", func_name.c_str(), renamed_sub);
            (*renamed_sub_count)++;
        }
    }

    return true;
}

bool RenameVariablesFromFile(qstring renamed_vars_path, VarRenameContext rename_context, int* renamed_var_count) {
    func_t* func = get_func(rename_context.func_ea);
    if (!func)
        return false;

    vdui_t* vdui = open_pseudocode(func->start_ea, OPF_REUSE);
    if (!vdui || !vdui->cfunc)
        return false;

    lvars_t* lvars = vdui->cfunc->get_lvars();
    if (!lvars)
        return false;

    LogMessage(LOG_PATH, 0, "RenameVariablesFromFile lvar num: (%d)\n", lvars->size());

    for (size_t i = 0; i < lvars->size(); i++) {
        lvar_t* lvar = &(*lvars)[i];
        if (lvar->name.empty())
            continue;

        qstring var_name = lvar->name.c_str();
        LogMessage(LOG_PATH, 0, "Processing var: (%s)\n", var_name.c_str());

        char renamed_var[256] = { 0 };
        PLUGIN_DWORD ReadConfig = PLUGIN_GetPrivateProfileStringA(
            "RenamedLocals",
            var_name.c_str(),
            "",
            renamed_var,
            sizeof(renamed_var),
            renamed_vars_path.c_str()
        );

        if (!ReadConfig) {
            LogMessage(LOG_PATH, 0, "WARNING: Var not found in response, skipping it: (%s)\n", lvar->name.c_str());
            continue;
        }

        if (var_name == renamed_var) {
            LogMessage(LOG_PATH, 0, "Var name is the same as the new name, skipping it: (%s)\n", var_name.c_str());
            continue;
        }

        if (!(vdui->rename_lvar(lvar, renamed_var, true))) {
            LogMessage(LOG_PATH, 1, "[BinaryLens] WARNING: Failed to rename (%s) to (%s)\n", var_name.c_str(), renamed_var);
        }
        else {
            LogMessage(LOG_PATH, 0, "Renamed (%s) to (%s)\n", var_name.c_str(), renamed_var);
            (*renamed_var_count)++;
        }

        lvars = vdui->cfunc->get_lvars();
    }

    return true;
}

/*
* The execute() func is invoked via execute_sync() to run in the main thread once the HTTP response is received.
* This approach is necessary because IDA's API functions are not thread safe and must be called from the main thread.
*/
class RenameSubs : public exec_request_t {
public:
    qstring model_response;

    ssize_t execute() override {
        static qstring bin_summary;
        qstring renamed_subs_path;
        if (!CreateTempFile(renamed_subs_path, "sub")) {
            sub_ren_pass_count = 0;
            bin_summary.clear();
            sub_rename_end = true;
            return 1;
        }

        // Save the server response to a temp file so it can be read without parsing
        qstring model_response_q(model_response.c_str());
        if (!SaveFileContent(renamed_subs_path, model_response_q)) {
            LogMessage(LOG_PATH, 3, "ERROR: SaveFileContent failed!\n");
            sub_ren_pass_count = 0;
            bin_summary.clear();
            sub_rename_end = true;
            return 1;
        }

        static int renamed_sub_count = 0;
        if (!RenameSubsFromFile(renamed_subs_path, &renamed_sub_count)) {
            LogMessage(LOG_PATH, 3, "ERROR: RenameSubsFromFile failed!\n");
            sub_ren_pass_count = 0;
            bin_summary.clear();
            renamed_sub_count = 0;
            sub_rename_end = true;
            return 1;
        }

        char buffer[1024] = { 0 };
        if (!PLUGIN_GetPrivateProfileStringA("BinaryInfo", "summary", "", buffer, sizeof(buffer), renamed_subs_path.c_str())) {
            LogMessage(LOG_PATH, 3, "Failed to get binary summary! Possible an unexpected server failure.\n");
            sub_ren_pass_count = 0;
            bin_summary.clear();
            renamed_sub_count = 0;
            sub_rename_end = true;
            return 1;
        }

        if (sub_ren_pass_count == 1) {
            bin_summary = buffer;
        }

        // Retry renaming one more time if there are still subs left. The models sometimes miss a few subs.
        if (sub_ren_pass_count == 1) {
            if (IsSubPresentInBin()) {
                LogMessage(LOG_PATH, 1, "Starting second pass to rename remaining functions...\n");
                RenameAllSubs();
                RemoveFile(std::string(renamed_subs_path.c_str()));
                return 0;
            }
        }

        char count_buffer[256];
        qsnprintf(count_buffer, sizeof(count_buffer), "Successfully renamed %d subrutines.\n\n", renamed_sub_count);
        qstring renamed_count = count_buffer;
        qstring final_summary = renamed_count + "Binary Analysis Summary:\n\n" + qstring(bin_summary) + "\n";

        qstring wrapped_text = qstring(WrapText(std::string(final_summary.c_str()), 120).c_str());
        LogMessage(LOG_PATH, 2, wrapped_text.c_str());

        RemoveFile(renamed_subs_path.c_str());

        sub_ren_pass_count = 0;
        bin_summary.clear();
        renamed_sub_count = 0;
        sub_rename_end = true;
        return 0;
    }
};

bool RenameAllSubs() {
    sub_rename_end = false;
    sub_ren_pass_count++;

    if (sub_ren_pass_count == 1) {
        LogMessage(LOG_PATH, 1, "[BinaryLens] Function renaming started. This may take a few minutes, please wait...\n");
    }

    if (!IsSubPresentInBin()) {
        LogMessage(LOG_PATH, 3, "No subroutines were found in the binary.\n");
        sub_rename_end = true;
        sub_ren_pass_count = 0;
        return false;
    }

    qstring subs = GetFuncs();
    if (subs.empty()) {
        LogMessage(LOG_PATH, 3, "ERROR: GetFuncs() failed!\n");
        sub_rename_end = true;
        sub_ren_pass_count = 0;
        return false;
    }

	LogMessage(LOG_PATH, 0, "=== Before removing var definitions ===\n%s\n========", subs.c_str());
	subs = RemoveVarDefinitions(subs);

    static qstring user_message;

    if (sub_ren_pass_count == 1) {
        size_t max_size = 250;
        if (!ask_text(
            &user_message,
            max_size,
            nullptr,
            "(optional) Provide information about the binary or what you're searching for:"
        )) {
            user_message = "";
        }
    }

    qstring message = qstring(user_message.c_str());

    // Use simple threading without std:: due to IDA SDK conflicts
    // Create thread manually using platform APIs
    auto thread_func = [subs, message]() -> void {
        std::string api_key;
        std::string model_to_use;

        ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Starting configuration validation...\n");

        if (!ReadRegistryData("SOFTWARE\\BinaryLensPlugin", "model_to_use", model_to_use)) {
            ThreadLogMessage(LOG_PATH, 3, "Please select a model in order to proceed with the subroutine renaming."
                "\n\nYou can do this by navigating to Edit/BinaryLens/Select Model.\n"
            );
            sub_rename_end = true;
            sub_ren_pass_count = 0;
            return;
        }

        ThreadLogMessage(LOG_PATH, 1, "[BinaryLens] Using model: %s\n", model_to_use.c_str());

        if (ContainsSubstring(model_to_use, "gemini")) {
            if (!ReadRegistryData("SOFTWARE\\BinaryLensPlugin", "gemini_api_key", api_key)) {
                ThreadLogMessage(LOG_PATH, 3,
                    "API key not found for the selected model (Gemini). Please set it before proceeding."
                    "\n\nYou can do this by navigating to Edit / BinaryLens / Select Model / Gemini / Set API key.\n"
                );
                sub_rename_end = true;
                sub_ren_pass_count = 0;
                return;
            }
            ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Gemini API key read successfully, length: %d\n", static_cast<int>(api_key.length()));
        }
        else if (ContainsSubstring(model_to_use, "deepseek")) {
            if (!ReadRegistryData("SOFTWARE\\BinaryLensPlugin", "deepseek_api_key", api_key)) {
                ThreadLogMessage(LOG_PATH, 3,
                    "API key not found for the selected model (deepseek). Please set it before proceeding."
                    "\n\nYou can do this by navigating to Edit/BinaryLens/Select Model/deepseek/Set API key.\n"
                );
                sub_rename_end = true;
                sub_ren_pass_count = 0;
                return;
            }
        }
        else if (ContainsSubstring(model_to_use, "gpt")) {
            if (!ReadRegistryData("SOFTWARE\\BinaryLensPlugin", "openai_api_key", api_key)) {
                ThreadLogMessage(LOG_PATH, 3,
                    "API key not found for the selected model (OpenAI). Please set it before proceeding."
                    "\n\nYou can do this by navigating to Edit/BinaryLens/Select Model/OpenAI/Set API key.\n"
                );
                sub_rename_end = true;
                sub_ren_pass_count = 0;
                return;
            }
        }
        else {
            ThreadLogMessage(LOG_PATH, 3, "Unsupported model: %s\n", model_to_use.c_str());
            sub_rename_end = true;
            sub_ren_pass_count = 0;
            return;
        }

        auto start = std::chrono::steady_clock::now();
        ThreadLogMessage(LOG_PATH, 1, "[BinaryLens] Waiting for model response...\n");


        qstring model_request_q = qstring("User message: \n") + message.c_str() + "\n\nDecompiled Functions:\n" + subs.c_str();
        qstring model_to_use_q(model_to_use.c_str());
        qstring api_key_q(api_key.c_str());
        qstring sys_prompt_q(SUB_REN_SYS_PROMPT);

        ThreadLogMessage(LOG_PATH, 0, "\n========== Model Request: ==========\n");
        ThreadLogMessage(LOG_PATH, 0, "System Prompt:\n%s\n\nUser Prompt\n%s\n", SUB_REN_SYS_PROMPT, model_request_q.c_str());
        ThreadLogMessage(LOG_PATH, 0, "====================\n\n");

        qstring model_response_q = GetResponseFromModel(model_to_use_q, api_key_q, sys_prompt_q, model_request_q);
        qstring model_response = model_response_q;
        if (model_response.empty()) {
            sub_rename_end = true;
            sub_ren_pass_count = 0;
            return;
        }

        // Log the model response for debugging
        ThreadLogMessage(LOG_PATH, 0, "\n========== Model Response: ==========\n");
        ThreadLogMessage(LOG_PATH, 0, "%s\n", model_response.c_str());
        ThreadLogMessage(LOG_PATH, 0, "====================\n\n");

        // Note: timing disabled due to IDA SDK std::chrono conflicts
        // auto stop = std::chrono::steady_clock::now();
        // double elapsed = std::chrono::duration<double>(stop - start).count();
        ThreadLogMessage(LOG_PATH, 1, "[BinaryLens] Model response received\n");

        RenameSubs RenameSubs;
        RenameSubs.model_response = model_response;

        execute_sync(RenameSubs, MFF_WRITE);
    };
    
    // Execute the thread function (simplified for IDA SDK compatibility)
    thread_func();

    return true;
}

/*
* The execute() func is invoked via execute_sync() to run in the main thread once the HTTP response is received.
* This approach is necessary because IDA's API functions are not thread safe and must be called from the main thread.
*/
class RenameVars : public exec_request_t {
public:
    VarRenameContext rename_context;

    ssize_t execute() override {
        std::string renamed_vars_path;
        qstring renamed_vars_path_q;
        if (!CreateTempFile(renamed_vars_path_q, "var")) {
            var_rename_end = true;
            return false;
        }

        // Save the server response to a temp file so it can be read without parsing
        qstring model_response_q(rename_context.model_response.c_str());
        if (!SaveFileContent(renamed_vars_path_q, model_response_q)) {
            LogMessage(LOG_PATH, 3, "ERROR: SaveFileContent failed!\n");
            var_rename_end = true;
            return false;
        }

        int renamed_var_count = 0;
        if (rename_context.rename_vars) {
            RenameVariablesFromFile(qstring(renamed_vars_path.c_str()), rename_context, &renamed_var_count);
        }

        LogMessage(LOG_PATH, 1, "[BinaryLens] Successfully renamed %d variables.\n", renamed_var_count);

        char buffer[1024] = { 0 };
        if (!PLUGIN_GetPrivateProfileStringA("FunctionInfo", "summary", "", buffer, sizeof(buffer), renamed_vars_path.c_str())) {
            LogMessage(LOG_PATH, 3, "ERROR: Failed to get function summary! Possible an unexpected server failure.\n");
            var_rename_end = true;
            return false;
        }

        std::string summary =
            "----- Function Analysis Summary: -----\n\n" +
            std::string(WrapText(buffer, 80)) +
            "\n----------------------------------------\n";

        func_t* func = get_func(rename_context.func_ea);
        if (!func) {
            LogMessage(LOG_PATH, 3, "ERROR: get_func failed\n");
            var_rename_end = true;
            return false;
        }

        if (!set_func_cmt(func, summary.c_str(), false)) {  // Use true for repeatable comment
            LogMessage(LOG_PATH, 3, "ERROR: set_func_cmt failed\n");
            var_rename_end = true;
            return false;
        }

        // Refresh pseudocode view
        vdui_t* vdui = open_pseudocode(func->start_ea, OPF_REUSE);
        if (vdui) vdui->refresh_view(true);

        LogMessage(LOG_PATH, 1, "[BinaryLens] Successfully set the function summary comment.\n", renamed_var_count);

        // check if the funcs name starts with sub_
        qstring func_name;
        get_func_name(&func_name, func->start_ea);
        if (qstrncmp(func_name.c_str(), "sub_", 4) == 0) {
            LogMessage(LOG_PATH, 3, "We highly recommend renaming all subroutines before analyzing specific functions"
                ", as this ensures more accurate renaming and analysis results.\n"
            );
        }

        RemoveFile(renamed_vars_path);
        var_rename_end = true;
        return 0;
    }
};

bool RenameVariables(TWidget* t_widget) {
    LogMessage(LOG_PATH, 1, "[BinaryLens] Variable renaming started. This may take a few minutes, please wait...\n");

    var_rename_end = false;
    vdui_t* vdui = get_widget_vdui(t_widget);
    lvars_t* temp_lvars = vdui->cfunc->get_lvars();
    bool rename_vars = true;

    // If there are no local variables, skip renaming
    if (!temp_lvars || temp_lvars->size() < 1) {
        rename_vars = false;
    }

    if (rename_vars) {
        // Dummy renaming to ensure all variables are listed correctly (IDA bug workaround)
        lvar_t* lvar = &(*temp_lvars)[0];
        std::string dummy_name = std::string(lvar->name.c_str()) + "_";
        vdui->rename_lvar(&(*temp_lvars)[0], dummy_name.c_str(), true);
        temp_lvars = vdui->cfunc->get_lvars();
    }

    const strvec_t& pseudocode = vdui->cfunc->get_pseudocode();
    if (pseudocode.empty()) {
        LogMessage(LOG_PATH, 3, "ERROR: No pseudocode available for function\n");
        var_rename_end = true;
        return false;
    }

    std::string func;
    for (const simpleline_t& line : pseudocode) {
        qstring clean_line = line.line;
        tag_remove(&clean_line);
        func += clean_line.c_str();
        func += "\n";
    }

    ea_t func_ea = vdui->cfunc->entry_ea;

    // Send the HTTP request in a thread to avoid freezing IDA
    std::thread([func = std::move(func), func_ea, rename_vars]() {
        std::string api_key;
        std::string model_to_use;

        ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Variable renaming: Starting configuration validation...\n");

        if (!ReadRegistryData("SOFTWARE\\BinaryLensPlugin", "model_to_use", model_to_use)) {
            ThreadLogMessage(LOG_PATH, 3, "Please select a model in order to proceed with the variable renaming."
                "\n\nYou can do this by navigating to Edit/BinaryLens/Select Model.\n"
            );
            var_rename_end = true;
            return;
        }

        ThreadLogMessage(LOG_PATH, 1, "[BinaryLens] Using model: %s\n", model_to_use.c_str());

        if (ContainsSubstring(model_to_use, "gemini")) {
            if (!ReadRegistryData("SOFTWARE\\BinaryLensPlugin", "gemini_api_key", api_key)) {
                ThreadLogMessage(LOG_PATH, 3, "API key not found for the selected model (Gemini). Please set it before proceeding."
                    "\n\nYou can do this by navigating to Edit/BinaryLens/Select Model/Gemini/Set API key.\n"
                );
                var_rename_end = true;
                return;
            }
        }
        else if (ContainsSubstring(model_to_use, "deepseek")) {
            if (!ReadRegistryData("SOFTWARE\\BinaryLensPlugin", "deepseek_api_key", api_key)) {
                ThreadLogMessage(LOG_PATH, 3, "API key not found for the selected model (deepseek). Please set it before proceeding."
                    "\n\nYou can do this by navigating to Edit/BinaryLens/Select Model/deepseek/Set API key.\n"
                );
                var_rename_end = true;
                return;
            }
        }
        else if (ContainsSubstring(model_to_use, "gpt")) {
            if (!ReadRegistryData("SOFTWARE\\BinaryLensPlugin", "openai_api_key", api_key)) {
                ThreadLogMessage(LOG_PATH, 3, "API key not found for the selected model (OpenAI). Please set it before proceeding."
                    "\n\nYou can do this by navigating to Edit/BinaryLens/Select Model/OpenAI/Set API key.\n"
                );
                var_rename_end = true;
                return;
            }
        }
        else {
            ThreadLogMessage(LOG_PATH, 3, "Unsupported model: %s\n", model_to_use.c_str());
            var_rename_end = true;
            return;
        }

        auto start = std::chrono::steady_clock::now();
        ThreadLogMessage(LOG_PATH, 1, "[BinaryLens] Waiting for model response...\n");

        ThreadLogMessage(LOG_PATH, 0, "\n========== Model Request: ==========\n");
        ThreadLogMessage(LOG_PATH, 0, "System Prompt:\n%s\n\nUser Prompt\n%s\n", VAR_REN_SYS_PROMPT, func.c_str());
        ThreadLogMessage(LOG_PATH, 0, "====================\n\n");

        qstring model_to_use_q(model_to_use.c_str());
        qstring api_key_q(api_key.c_str());
        qstring sys_prompt_q(VAR_REN_SYS_PROMPT);
        qstring func_q(func.c_str());
        
        qstring model_response_q = GetResponseFromModel(model_to_use_q, api_key_q, sys_prompt_q, func_q);
        std::string model_response(model_response_q.c_str());
        if (model_response.empty()) {
            var_rename_end = true;
            return;
        }

        // Log the model response for debugging
        ThreadLogMessage(LOG_PATH, 0, "\n========== Model Response: ==========\n");
        ThreadLogMessage(LOG_PATH, 0, "%s\n", model_response.c_str());
        ThreadLogMessage(LOG_PATH, 0, "====================\n\n");

        auto stop = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(stop - start).count();
        ThreadLogMessage(LOG_PATH, true, "[BinaryLens] Model response received (took %.2f sec)\n", elapsed);

        VarRenameContext rename_context;
        rename_context.func_ea = func_ea;
        rename_context.model_response = std::move(model_response);
        rename_context.rename_vars = rename_vars;

        RenameVars RenameVars;
        RenameVars.rename_context = std::move(rename_context);

        execute_sync(RenameVars, MFF_WRITE);
        }).detach();

    return true;
}