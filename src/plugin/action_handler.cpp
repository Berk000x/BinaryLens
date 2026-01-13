#include <fstream>
#include <thread>
#include <string>
#include <iostream>
#include <sstream>
#include <cstring>

#include "../helper/httplib.h"
#include "../helper/helper.h"
#include "action_handler.h"
#include "plugin.h"

#include <idp.hpp>
#include <ida.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <hexrays.hpp>

#if defined(_WIN32)
#include <windows.h>
#endif

TWidget* widget;

bool HandleAnalysisActions(const char* action_name) {
    ThreadLogMessage(LOG_PATH, 0, "[DEBUG] HandleAnalysisActions called with action: %s\n", action_name);
    
    if (strcmp(action_name, "rename_subs") == 0) {
        ThreadLogMessage(LOG_PATH, 0, "[DEBUG] rename_subs action triggered, sub_rename_end = %s\n", 
                        sub_rename_end ? "true" : "false");
        if (sub_rename_end) {
            RenameAllSubs();
        } else {
            ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Subroutine renaming already in progress, skipping...\n");
        }
    }

    if (strcmp(action_name, "rename_vars") == 0) {
        ThreadLogMessage(LOG_PATH, 0, "[DEBUG] rename_vars action triggered, var_rename_end = %s\n", 
                        var_rename_end ? "true" : "false");
        if (var_rename_end) {
            RenameVariables(widget);
        } else {
            ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Variable renaming already in progress, skipping...\n");
        }
    }

    if (strcmp(action_name, "about") == 0) {
        info("BinaryLens - an IDA plugin that uses language models to speed up binary analysis."
            "\n\nFind more info at github.com/Berk000x/BinaryLens.\n\nv1.0.1\n"
        );
    }

    return true;
}

bool HandleModelActions(const char* action_name) {
    const char* sub_key = "SOFTWARE\\BinaryLensPlugin";
    WriteRegistryData(sub_key, "model_to_use", action_name);
    return true;
}

bool HandleApiKeyActions(const char* action_name) {
    qstring key;
    bool input = ask_str(&key, 0, "Enter your API key:");

    std::string key_str = key.c_str();

    if (!input || key_str.empty())
        return true;

    TrimStr(key_str);

    const char* sub_key = "SOFTWARE\\BinaryLensPlugin";
    WriteRegistryData(sub_key, action_name, key_str.c_str());

    return true;
}

class FunctionActionHandler : public action_handler_t {
public:
    bool (*func)(const char*);

    FunctionActionHandler(bool (*f)(const char*)) {
        func = f;
    }

    virtual int idaapi activate(action_activation_ctx_t* ctx) override {
        if (func) {
            std::string action_name = ctx->action;
            RemoveSubstring(action_name, "BinaryLens:");
            return func(action_name.c_str()) ? 1 : 0;
        }
        return 0;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

FunctionActionHandler analysis_handler(HandleAnalysisActions);
FunctionActionHandler model_handler(HandleModelActions);
FunctionActionHandler api_key_handler(HandleApiKeyActions);

// Action descriptors
const action_desc_t rename_subs_action = ACTION_DESC_LITERAL(
    "BinaryLens:rename_subs",
    "Rename all subroutines",
    &analysis_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t rename_vars_action = ACTION_DESC_LITERAL(
    "BinaryLens:rename_vars",
    "Rename variables",
    &analysis_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t gemini_25_pro_action = ACTION_DESC_LITERAL(
    "BinaryLens:gemini-2.5-pro",
    "Gemini-2.5-Pro",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t gemini_api_action = ACTION_DESC_LITERAL(
    "BinaryLens:gemini_api_key",
    "Set API key",
    &api_key_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t deepseek_chat_action = ACTION_DESC_LITERAL(
    "BinaryLens:deepseek-chat",
    "Deepseek-chat",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t deepseek_api_action = ACTION_DESC_LITERAL(
    "BinaryLens:deepseek_api_key",
    "Set API key",
    &api_key_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t gpt_5_action = ACTION_DESC_LITERAL(
    "BinaryLens:gpt-5",
    "GPT-5",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t openai_api_action = ACTION_DESC_LITERAL(
    "BinaryLens:openai_api_key",
    "Set API key",
    &api_key_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t about_action = ACTION_DESC_LITERAL(
    "BinaryLens:about",
    "About",
    &analysis_handler,
    nullptr,
    nullptr,
    -1
);

ssize_t idaapi WidgetPopupCallback(void* user_data, int notification_code, va_list va) {
    if (notification_code == ui_populating_widget_popup) {
        TWidget* t_widget = va_arg(va, TWidget*);
        TPopupMenu* popup = va_arg(va, TPopupMenu*);
        if (get_widget_type(t_widget) == BWN_PSEUDOCODE) {
            ea_t current_ea = get_widget_vdui(t_widget)->cfunc->entry_ea;

            widget = t_widget;

            attach_action_to_popup(t_widget, popup, "BinaryLens:rename_vars", "BinaryLens/", SETMENU_APP);
        }
    }
    return 0;
}

plugmod_t* idaapi init() {
    #if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
    #endif
    RemoveFile("BinaryLensLog.txt");

    if (!register_action(rename_subs_action)   ||
        !register_action(rename_vars_action)   ||
        !register_action(about_action)         ||
        !register_action(gemini_25_pro_action) ||
        !register_action(deepseek_chat_action) ||
        !register_action(gpt_5_action)         ||
        !register_action(gemini_api_action)    ||
        !register_action(deepseek_api_action)  ||
        !register_action(openai_api_action)) {

        LogMessage(LOG_PATH, true, "[BinaryLens] ERROR: Failed to register actions.\n");
        return PLUGIN_SKIP;
    }

    // Create submenu in Edit menu
    if (!create_menu(ACTION_NAME, "BinaryLens", "Edit/")) {
        LogMessage(LOG_PATH, true, "[BinaryLens] ERROR: Failed to create Edit menu container\n");
        return PLUGIN_SKIP;
    }

    // Attach options to edit menu
    attach_action_to_menu("Edit/" ACTION_NAME "/", "BinaryLens:rename_subs", SETMENU_APP);

    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Gemini/", "BinaryLens:gemini-2.5-pro", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Gemini/", "BinaryLens:gemini_api_key", SETMENU_APP);

    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Deepseek/", "BinaryLens:deepseek-chat", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Deepseek/", "BinaryLens:deepseek_api_key", SETMENU_APP);

    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/OpenAI/", "BinaryLens:gpt-5", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/OpenAI/", "BinaryLens:openai_api_key", SETMENU_APP);

    attach_action_to_menu("Edit/" ACTION_NAME "/", "BinaryLens:about", SETMENU_APP);

    // Hook for popup menus
    hook_to_notification_point(HT_UI, WidgetPopupCallback, nullptr);

    return PLUGIN_KEEP;
}

void idaapi term() {
    unhook_from_notification_point(HT_UI, WidgetPopupCallback, nullptr);

    unregister_action("BinaryLens:rename_subs");
    unregister_action("BinaryLens:rename_vars");
    unregister_action("BinaryLens:gemini-2.5-pro");
    unregister_action("BinaryLens:gemini_api_key");
    unregister_action("BinaryLens:deepseek-chat");
    unregister_action("BinaryLens:deepseek_api_key");
    unregister_action("BinaryLens:gpt-5");
    unregister_action("BinaryLens:openai_api_key");
    unregister_action("BinaryLens:about");
}

bool idaapi run(size_t) {
    return true;
}