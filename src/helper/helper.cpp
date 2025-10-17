#include <fstream>
#include <windows.h>
#include <thread>
#include <shlwapi.h>
#include <string>
#include <iostream>
#include <sstream>

#include "httplib.h"
#include "json.hpp"
#include "helper.h"

#include <idp.hpp>
#include <ida.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <hexrays.hpp>

#pragma comment(lib, "Advapi32.lib")

std::string GetResponseFromModel(
    std::string model,
    std::string api_key,
    std::string system_prompt,
    std::string user_prompt
) {
    std::string host;
    std::string chat_endpoint;
    int max_token_len;

    nlohmann::json body = {
        {"model", model},
        {"messages", {
            {{"role", "system"}, {"content", system_prompt}},
            {{"role", "user"}, {"content", user_prompt}}
        }}
    };

    if (ContainsSubstring(model, "gemini")) {
        host = "generativelanguage.googleapis.com";
        chat_endpoint = "/v1beta/openai/chat/completions";
        max_token_len = 950000;
    }
    else if (ContainsSubstring(model, "deepseek")) {
        host = "api.deepseek.com";
        chat_endpoint = "/v1/chat/completions";
        max_token_len = 127000;

        // Set the deepseek output token to max, as the default is 4k
        body["max_tokens"] = 8192;
    }
    else if (ContainsSubstring(model, "gpt")) {
        host = "api.openai.com";
        chat_endpoint = "/v1/chat/completions";
        max_token_len = 270000;
    }
    else {
        ThreadLogMessage(LOG_PATH, 3, "Unsupported model: %s\n", model.c_str());
        return std::string();
    }

    int estimated_token_len = static_cast<int>(user_prompt.length() / 2.31);
    ThreadLogMessage(LOG_PATH, 0, "Estimated token length of the request: %d\n", estimated_token_len);

    if (estimated_token_len > max_token_len) {
        ThreadLogMessage(LOG_PATH, 3, "The given request is too large for the selected model (%s). "
            "Please choose a smaller binary or function.\n", model.c_str()
        );
        return std::string();
    }

    httplib::SSLClient cli(host.c_str());
    cli.set_read_timeout(1200, 0);
    cli.set_write_timeout(600, 0);

    ThreadLogMessage(LOG_PATH, 0, "Client created for host: %s\n", host.c_str());

    cli.set_default_headers({
        {"Authorization", "Bearer " + api_key},
        {"Content-Type", "application/json"}
        });

    ThreadLogMessage(LOG_PATH, 0, "Default headers set\n");

    auto dumpped_body = body.dump();

    ThreadLogMessage(LOG_PATH, 0, "Body dumped successfully\n");

    auto res = cli.Post(chat_endpoint, dumpped_body, "application/json");

    ThreadLogMessage(LOG_PATH, 0, "Request sent to endpoint: %s\n", chat_endpoint.c_str());

    if (!res) {
        ThreadLogMessage(LOG_PATH, 3, "Failed to get a response from the model. "
            "Please check your internet connection and try again later.\n"
        );
        return std::string();
    }

    if (res->status != 200) {
        // Try to parse the error message from the response
        nlohmann::json error_data;
        try {
            error_data = nlohmann::json::parse(res->body);

            std::string error_message;
            if (error_data.is_array())
                error_message = error_data[0]["error"]["message"];
            else
                error_message = error_data["error"]["message"];

            ThreadLogMessage(LOG_PATH, 3, "Request to (%s) rejected, with error:"
                "\n\n%s\n", model.c_str(), error_message.c_str()
            );
        }
        catch (const std::exception& e) {
            // If parsing fails, just print the status code
            ThreadLogMessage(LOG_PATH, 3, "Failed to get a response from the model. "
                "Please try again later. Failed with status (%d).\n", res->status
            );
            ThreadLogMessage(LOG_PATH, 0, "Response JSON:\n%s\n", error_data.dump(4).c_str());
        }
        return std::string();
    }

    nlohmann::json data;
    std::string model_response;

    try {
        data = nlohmann::json::parse(res->body);
        model_response = data["choices"][0]["message"]["content"];
    }
    catch (const std::exception& e) {
        ThreadLogMessage(LOG_PATH, 3, "Failed to get a response from the model. "
            "Model request was rejected unexpectedly. Please try again later.\n"
        );
        ThreadLogMessage(LOG_PATH, 0, "Response JSON:\n%s\n", data.dump(4).c_str());
        return std::string();
    }

    return model_response;
}

bool LogMessage(const char* path, int display_type, const char* format, ...) {
    va_list args;
    va_start(args, format);

    va_list args_copy;
    va_copy(args_copy, args);
    int len = qvsnprintf(NULL, 0, format, args_copy);
    va_end(args_copy);

    if (len < 0) {
        msg("[BinaryLens] WARNING: Failed to format log string\n");
        va_end(args);
        return false;
    }

    char* buf = (char*)malloc(len + 1);
    if (!buf) {
        msg("[BinaryLens] WARNING: Memory allocation failed for log string\n");
        va_end(args);
        return false;
    }

    qvsnprintf(buf, len + 1, format, args);
    va_end(args);

    FILE* logfile = qfopen(path, "a");
    if (!logfile) {
        msg("[BinaryLens] WARNING: Failed to open log file\n");
        free(buf);
        return false;
    }

    qfprintf(logfile, "%s", buf);

    if (display_type == 1)
        msg("%s", buf);
    if (display_type == 2)
        info("%s", buf);
    if (display_type == 3)
        warning("%s", buf);

    qfclose(logfile);
    free(buf);

    return true;
}

class LogMsgInMain : public exec_request_t {
public:
    int display_type;
    char* msg;

    ssize_t execute() override {
        LogMessage(LOG_PATH, display_type, "%s", msg);
        free(msg);
        return 0;
    }
};

bool ThreadLogMessage(const char* path, int display_type, const char* format, ...) {
    va_list args;
    va_start(args, format);

    va_list args_copy;
    va_copy(args_copy, args);
    int len = qvsnprintf(NULL, 0, format, args_copy);
    va_end(args_copy);

    if (len < 0) {
        msg("[BinaryLens] WARNING: Failed to format log string\n");
        va_end(args);
        return false;
    }

    char* buf = (char*)malloc(len + 1);
    if (!buf) {
        msg("[BinaryLens] WARNING: Memory allocation failed for log string\n");
        va_end(args);
        return false;
    }

    qvsnprintf(buf, len + 1, format, args);
    va_end(args);

    LogMsgInMain LogMsgInMain;
    LogMsgInMain.display_type = display_type;
    LogMsgInMain.msg = buf;

    execute_sync(LogMsgInMain, MFF_WRITE);

    return true;
}

bool WriteRegistryData(const char* sub_key, const char* value_name, const char* data_to_write) {
    HKEY hKey;

    if (RegCreateKeyExA(
        HKEY_CURRENT_USER,
        sub_key,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        nullptr,
        &hKey,
        nullptr
    ) != ERROR_SUCCESS) {
        LogMessage(LOG_PATH, 3, "Failed to create or open registry key. Error code: %ld\n", GetLastError());
        return false;
    }

    if (RegSetValueExA(
        hKey,
        value_name,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(data_to_write),
        strlen(data_to_write) + 1
    ) != ERROR_SUCCESS) {
        LogMessage(LOG_PATH, 3, "Failed to write data to registry. Error code: %ld\n", GetLastError());
        return false;
    }

    RegCloseKey(hKey);
    return true;
}

bool ReadRegistryData(const char* sub_key, const char* value_name, std::string& read_data) {
    HKEY hKey;

    if (RegCreateKeyExA(
        HKEY_CURRENT_USER,
        sub_key,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        nullptr,
        &hKey,
        nullptr
    ) != ERROR_SUCCESS) {
        ThreadLogMessage(LOG_PATH, 3, "ERROR: Failed to create or open registry key. Error code: %ld\n", GetLastError());
        return false;
    }

    char buffer[256];
    DWORD buffer_size = sizeof(buffer);
    if (RegGetValueA(hKey, nullptr, value_name, RRF_RT_REG_SZ, nullptr, buffer, &buffer_size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    read_data = std::string(buffer);
    RegCloseKey(hKey);
    return true;
}

std::string WrapText(const std::string& text, size_t max_line_length) {
    std::istringstream input(text);
    std::ostringstream output;
    std::string line;

    while (std::getline(input, line)) {
        std::istringstream words(line);
        std::string word;
        std::string currentLine;

        while (words >> word) {
            if (currentLine.empty()) {
                currentLine = word;
            }
            else if (currentLine.size() + 1 + word.size() <= max_line_length) {
                currentLine += " " + word;
            }
            else {
                output << currentLine << "\n";
                currentLine = word;
            }
        }
        output << currentLine << "\n";
    }

    return output.str();
}

bool SaveFileContent(const std::string& filepath, const std::string& content) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        LogMessage(LOG_PATH, 3, "Failed to open file for writing: %s\n", filepath.c_str());
        return false;
    }

    file.write(content.data(), content.size());
    if (!file) {
        LogMessage(LOG_PATH, 3, "Failed to write to file: %s\n", filepath.c_str());
        return false;
    }

    return true;
}

std::string GetFileContent(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        LogMessage(LOG_PATH, 3, "Failed to open file: %s\n", filepath.c_str());
        return std::string();
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string file_content = buffer.str();

    if (file_content.empty()) {
        LogMessage(LOG_PATH, 3, "File is empty: %s\n", filepath.c_str());
        return std::string();
    }

    return file_content;
}

void ltrim(std::string& s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
        }));
}

void rtrim(std::string& s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
        }).base(), s.end());
}

void TrimStr(std::string& s) {
    ltrim(s);
    rtrim(s);
}

void RemoveSubstring(std::string& str, const std::string& target) {
    size_t pos;
    while ((pos = str.find(target)) != std::string::npos) {
        str.erase(pos, target.length());
    }
}

bool ContainsSubstring(const std::string& str, const std::string& target) {
    return str.find(target) != std::string::npos;
}