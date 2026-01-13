// IDA SDK headers first to establish their environment  
#include "../../ida-sdk/src/include/pro.h"
#include "../../ida-sdk/src/include/ida.hpp"
#include "../../ida-sdk/src/include/idp.hpp"
#include "../../ida-sdk/src/include/loader.hpp"
#include "../../ida-sdk/src/include/kernwin.hpp"
#include "../../ida-sdk/src/include/funcs.hpp"
#include "../../ida-sdk/src/include/name.hpp"
#include "../../ida-sdk/src/include/hexrays.hpp"
#include "../../ida-sdk/src/include/fpro.h"

// Standard library with explicit std:: usage after IDA headers
#ifdef __cplusplus
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <vector>
#include <string>
#include <exception>
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
#include "httplib.h"
#include "json.hpp"

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/x509_vfy.h>
#endif

// Redefine IDA SDK macros after third-party includes
#define snprintf        dont_use_snprintf
#define wait            dont_use_wait
#define fgetc           dont_use_fgetc

// Local headers
#include "helper.h"

#if defined(_WIN32)
#include <windows.h>
#include <shlwapi.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#include <shlwapi.h>
#endif

#if defined(_WIN32)
#pragma comment(lib, "Advapi32.lib")
#endif

namespace {

#if defined(_WIN32)
// Windows registry-based config remains for backward compatibility.
#else
// Cross-platform config stored as JSON under ~/.config/BinaryLens/config.json

qstring GetConfigPath() {
    qstring config_path;
    qstring home;
    if (qgetenv("HOME", &home)) {
        config_path = home;
        config_path += "/.config/BinaryLens";
        
        // Ensure directory exists using IDA SDK compatible method
#ifdef __APPLE__
        qmkdir(config_path.c_str(), 0755);
#endif
        config_path += "/config.json";
    } else {
        config_path = "/tmp/BinaryLens_config.json";
    }
    return config_path;
}
#endif

} // namespace

qstring GetResponseFromModel(
    const qstring& model,
    const qstring& api_key,
    const qstring& system_prompt,
    const qstring& user_prompt
) {
    // Log the API call attempt
    ThreadLogMessage(LOG_PATH, 0, "=== GetResponseFromModel called ===\n");
    ThreadLogMessage(LOG_PATH, 0, "Model: %s\n", model.c_str());
    ThreadLogMessage(LOG_PATH, 0, "API Key length: %d\n", static_cast<int>(api_key.length()));
    ThreadLogMessage(LOG_PATH, 0, "System prompt length: %d\n", static_cast<int>(system_prompt.length()));
    ThreadLogMessage(LOG_PATH, 0, "User prompt length: %d\n", static_cast<int>(user_prompt.length()));
    
    qstring host;
    qstring chat_endpoint;
    int max_token_len;

    nlohmann::json body = {
        {"model", model.c_str()},
        {"messages", {
            {{"role", "system"}, {"content", system_prompt.c_str()}},
            {{"role", "user"}, {"content", user_prompt.c_str()}}
        }}
    };

    if (model.find("gemini") != BADADDR) {
        host = "generativelanguage.googleapis.com";
        chat_endpoint = "/v1beta/openai/chat/completions?key=";
        chat_endpoint += api_key.c_str();
        max_token_len = 950000;
        ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Gemini endpoint constructed: %s\n", chat_endpoint.c_str());
        ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Gemini API key length: %d\n", static_cast<int>(api_key.length()));
    }
    else if (model.find("deepseek") != BADADDR) {
        host = "api.deepseek.com";
        chat_endpoint = "/v1/chat/completions";
        max_token_len = 127000;

        // Set the deepseek output token to max, as the default is 4k
        body["max_tokens"] = 8192;
    }
    else if (model.find("gpt") != BADADDR) {
        host = "api.openai.com";
        chat_endpoint = "/v1/chat/completions";
        max_token_len = 270000;
    }
    else {
        ThreadLogMessage(LOG_PATH, 3, "Unsupported model: %s\n", model.c_str());
        return qstring();
    }

    ThreadLogMessage(LOG_PATH, 0, "Using host: %s, endpoint: %s\n", host.c_str(), chat_endpoint.c_str());

    // Validate API key presence for selected provider
    if (model.find("gemini") != BADADDR) {
        if (api_key.length() == 0) {
            ThreadLogMessage(LOG_PATH, 3, "API key not provided for Gemini. Please set `gemini_api_key`.\n");
            return qstring();
        }
    } else {
        if (api_key.length() == 0) {
            ThreadLogMessage(LOG_PATH, 3, "API key not provided. Please set the API key for the selected provider.\n");
            return qstring();
        }
    }

    // DEBUG: Print API key to IDA console (temporary) to verify configuration
    /*if (model.find("gemini") != BADADDR) {
        ThreadLogMessage(LOG_PATH, 1, "DEBUG: Gemini API key: %s\n", api_key.c_str());
    } else {
        ThreadLogMessage(LOG_PATH, 1, "DEBUG: API key for provider (%s): %s\n", model.c_str(), api_key.c_str());
    }*/

    int estimated_token_len = static_cast<int>(user_prompt.length() / 2.31);
    ThreadLogMessage(LOG_PATH, 0, "Estimated token length of the request: %d\n", estimated_token_len);

    if (estimated_token_len > max_token_len) {
        ThreadLogMessage(LOG_PATH, 3, "The given request is too large for the selected model (%s). "
            "Please choose a smaller binary or function.\n", model.c_str()
        );
        return qstring();
    }

    ThreadLogMessage(LOG_PATH, 0, "Creating HTTPS client...\n");
    ThreadLogMessage(LOG_PATH, 0, "Host URL: %s\n", host.c_str());
    
    // Detect CA bundle and configure SSL paths
    std::vector<std::string> ca_candidates = {
        "/opt/homebrew/etc/openssl@3/cert.pem",
        "/opt/homebrew/etc/openssl/cert.pem",
        "/usr/local/etc/openssl/cert.pem",
        "/opt/local/etc/openssl3/cert.pem",
        "/opt/local/libexec/openssl3/cert.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem"
    };

    std::string found_ca;
    struct stat st;
    for (const auto &p : ca_candidates) {
        if (stat(p.c_str(), &st) == 0) {
            found_ca = p;
            break;
        }
    }

    if (!found_ca.empty()) {
        qsetenv("SSL_CERT_FILE", found_ca.c_str());
        qsetenv("CURL_CA_BUNDLE", found_ca.c_str());
        ThreadLogMessage(LOG_PATH, 0, "Using CA bundle: %s\n", found_ca.c_str());
    } else {
        // Fallback values (may work on some setups)
        qsetenv("SSL_CERT_FILE", "/usr/local/etc/openssl/cert.pem");
        qsetenv("SSL_CERT_DIR", "/System/Library/OpenSSL");
        qsetenv("CURL_CA_BUNDLE", "/usr/local/etc/openssl/cert.pem");
        ThreadLogMessage(LOG_PATH, 3, "[WARNING] No CA bundle found in common locations; HTTPS may fail.\n");
    }

#if defined(CPPHTTPLIB_OPENSSL_SUPPORT)
    httplib::SSLClient cli(host.c_str(), 443);
    if (!found_ca.empty()) {
        cli.set_ca_cert_path(found_ca, std::string());
    }
    cli.enable_server_certificate_verification(true);
    cli.enable_server_hostname_verification(true);
    if (!cli.is_valid()) {
        ThreadLogMessage(LOG_PATH, 3, "[SSL DEBUG] SSLClient created but invalid (no SSL context)\n");
    } else {
        long init_vr = cli.get_openssl_verify_result();
        ThreadLogMessage(LOG_PATH, 0, "[SSL DEBUG] Initial OpenSSL verify result: %ld\n", init_vr);
    }
#else
    httplib::Client cli(host.c_str());
    ThreadLogMessage(LOG_PATH, 3, "[WARNING] httplib built without OpenSSL support; HTTPS may fail.\n");
#endif
    
    // Configure timeouts
    cli.set_read_timeout(1200, 0);
    cli.set_write_timeout(600, 0);
    cli.set_connection_timeout(60, 0);  // Add connection timeout
    
    ThreadLogMessage(LOG_PATH, 0, "Client created and SSL paths configured for host: %s\n", host.c_str());

    // Set authentication based on provider
    if (model.find("gemini") != BADADDR) {
        // Some Gemini endpoints accept API key as URL param, but some require
        // an Authorization or x-goog-api-key header. Send both to be compatible.
        qstring auth_header = "Bearer ";
        auth_header += api_key;
        cli.set_default_headers({
            {"Content-Type", "application/json"},
            {"x-goog-api-key", api_key.c_str()},
            {"Authorization", auth_header.c_str()}
        });
        ThreadLogMessage(LOG_PATH, 0, "Headers set for Gemini (URL key + x-goog-api-key + Authorization)\n");
    } else {
        // Other providers use Bearer token in Authorization header
        if (api_key.length() == 0) {
            ThreadLogMessage(LOG_PATH, 3, "API key is empty; cannot set Authorization header.\n");
            return qstring();
        }
        qstring auth_header = "Bearer ";
        auth_header += api_key;
        cli.set_default_headers({
            {"Authorization", auth_header.c_str()},
            {"Content-Type", "application/json"}
        });
        ThreadLogMessage(LOG_PATH, 0, "Headers set with Bearer token\n");
    }

    auto dumpped_body = body.dump();
    ThreadLogMessage(LOG_PATH, 0, "Request body size: %d bytes\n", static_cast<int>(dumpped_body.length()));

    ThreadLogMessage(LOG_PATH, 0, "Body dumped successfully\n");

    ThreadLogMessage(LOG_PATH, 0, "Sending POST request...\n");
    ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Full URL: https://%s%s\n", host.c_str(), chat_endpoint.c_str());
    ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Request body preview: %.200s...\n", dumpped_body.c_str());
    
    auto res = cli.Post(chat_endpoint.c_str(), dumpped_body, "application/json");

    ThreadLogMessage(LOG_PATH, 0, "Request completed\n");

    if (!res) {
        ThreadLogMessage(LOG_PATH, 3, "[ERROR] HTTP request returned null response\n");
        ThreadLogMessage(LOG_PATH, 3, "[ERROR] This usually indicates SSL/TLS handshake failure\n");
        ThreadLogMessage(LOG_PATH, 3, "Failed to get a response from the model. "
            "Please check your internet connection and SSL configuration. "
            "Try again later.\n"
        );
        // Additional OpenSSL verification debug info
#if defined(CPPHTTPLIB_OPENSSL_SUPPORT)
        long vr = cli.get_openssl_verify_result();
        const char* vr_str = X509_verify_cert_error_string((int)vr);
        ThreadLogMessage(LOG_PATH, 3, "[SSL DEBUG] OpenSSL verify result after failure: %ld (%s)\n", vr, vr_str ? vr_str : "<null>");
#endif
        return qstring();
    }

    ThreadLogMessage(LOG_PATH, 0, "[DEBUG] HTTP response received\n");
    ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Response status: %d\n", res->status);
    ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Response headers count: %d\n", static_cast<int>(res->headers.size()));
    ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Response body length: %d\n", static_cast<int>(res->body.length()));
    ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Response body preview: %.200s...\n", res->body.c_str());

    if (res->status != 200) {
        // Try to parse the error message from the response
        nlohmann::json error_data;
        try {
            error_data = nlohmann::json::parse(res->body);

            qstring error_message;
            if (error_data.is_array())
                error_message = error_data[0]["error"]["message"].get<std::string>().c_str();
            else
                error_message = error_data["error"]["message"].get<std::string>().c_str();

            ThreadLogMessage(LOG_PATH, 3, "Request to (%s) rejected, with error:"
                "\n\n%s\n", model.c_str(), error_message.c_str()
            );
        }
        catch (const std::exception& e) {
            // If parsing fails, just print the status code
            ThreadLogMessage(LOG_PATH, 3, "Failed to get a response from the model. "
                "Please try again later. Failed with status (%d).\n", res->status
            );
            ThreadLogMessage(LOG_PATH, 0, "Response body:\n%s\n", res->body.c_str());
        }
        return qstring();
    }

    nlohmann::json data;
    qstring model_response;

    try {
        data = nlohmann::json::parse(res->body);
        auto content_str = data["choices"][0]["message"]["content"].get<std::string>();
        model_response = content_str.c_str();
        ThreadLogMessage(LOG_PATH, 0, "Successfully parsed response, length: %d\n", static_cast<int>(model_response.length()));
    }
    catch (...) {
        ThreadLogMessage(LOG_PATH, 3, "Failed to get a response from the model. "
            "Model request was rejected unexpectedly. Please try again later.\n"
        );
        ThreadLogMessage(LOG_PATH, 0, "Response body for debugging:\n%s\n", res->body.c_str());
        return qstring();
    }

    ThreadLogMessage(LOG_PATH, 0, "=== GetResponseFromModel completed successfully ===\n");
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

    char* buf = (char*)qalloc(len + 1);
    if (!buf) {
        msg("[BinaryLens] WARNING: Memory allocation failed for log string\n");
        va_end(args);
        return false;
    }

    qvsnprintf(buf, len + 1, format, args);
    va_end(args);

    FILE* logfile = qfopen(path, "a");
    if (logfile == NULL) {
        msg("[BinaryLens] WARNING: Failed to open log file\n");
        qfree(buf);
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
    qfree(buf);

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
#if defined(_WIN32)
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
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    return true;
#else
    (void)sub_key; // Unused on non-Windows; kept for API compatibility.

    const auto cfg_path = GetConfigPath();
    nlohmann::json j;

    // Try to read existing config
    auto in_file = qfopen(cfg_path.c_str(), "r");
    if (in_file) {
        qfseek(in_file, 0, SEEK_END);
        int64 size = qftell(in_file);
        qfseek(in_file, 0, SEEK_SET);
        
        char* content = (char*)qalloc(size + 1);
        if (content) {
            qfread(in_file, content, size);
            content[size] = 0;
            try {
                j = nlohmann::json::parse(content);
            } catch (...) {
                j = nlohmann::json::object();
            }
            qfree(content);
        }
        qfclose(in_file);
    }

    if (j.is_null()) {
        j = nlohmann::json::object();
    }

    j[value_name] = data_to_write;

    // Write config file
    auto out_file = qfopen(cfg_path.c_str(), "w");
    if (!out_file) {
        LogMessage(LOG_PATH, 3, "Failed to open config file for writing: %s\n", cfg_path.c_str());
        return false;
    }
    auto json_str = j.dump(2);
    qfwrite(out_file, json_str.c_str(), json_str.length());
    qfclose(out_file);
    return true;
#endif
}

bool ReadRegistryData(const char* sub_key, const char* value_name, std::string& read_data) {
    ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Reading config for key: %s, value: %s\n", sub_key, value_name);
    
#if defined(_WIN32)
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
#else
    (void)sub_key; // Unused on non-Windows; kept for API compatibility.

    const auto cfg_path = GetConfigPath();
    ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Config file path: %s\n", cfg_path.c_str());
    
    auto in_file = qfopen(cfg_path.c_str(), "r");
    if (!in_file) {
        ThreadLogMessage(LOG_PATH, 0, "[DEBUG] Config file not found: %s\n", cfg_path.c_str());
        return false;
    }

    qfseek(in_file, 0, SEEK_END);
    int64 size = qftell(in_file);
    qfseek(in_file, 0, SEEK_SET);
    
    char* content = (char*)qalloc(size + 1);
    if (!content) {
        qfclose(in_file);
        return false;
    }
    
    qfread(in_file, content, size);
    content[size] = 0;
    qfclose(in_file);
    
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(content);
    } catch (...) {
        qfree(content);
        return false;
    }
    qfree(content);
    
    if (!j.contains(value_name))
        return false;

    try {
        read_data = j.at(value_name).get<std::string>();
        ThreadLogMessage(LOG_PATH, 0, "Successfully read config value: %s = %s\n", value_name, read_data.c_str());
    }
    catch (...) {
        ThreadLogMessage(LOG_PATH, 0, "Config value not found: %s\n", value_name);
        return false;
    }

    return true;
#endif
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

bool SaveFileContent(const qstring& filepath, const qstring& content) {
    auto file = qfopen(filepath.c_str(), "wb");
    if (!file) {
        LogMessage(LOG_PATH, 3, "Failed to open file for writing: %s\n", filepath.c_str());
        return false;
    }

    qfwrite(file, content.c_str(), content.length());
    qfclose(file);

    return true;
}

qstring GetFileContent(const qstring& filepath) {
    auto file = qfopen(filepath.c_str(), "rb");
    if (!file) {
        LogMessage(LOG_PATH, 3, "Failed to open file: %s\n", filepath.c_str());
        return qstring();
    }

    // Get file size
    qfseek(file, 0, SEEK_END);
    int64 size = qftell(file);
    qfseek(file, 0, SEEK_SET);

    // Read entire file into buffer
    char* buffer = (char*)qalloc(size + 1);
    if (!buffer) {
        qfclose(file);
        return qstring();
    }

    qfread(file, buffer, size);
    buffer[size] = '\0';  // Null terminate
    qfclose(file);

    qstring result(buffer);
    qfree(buffer);
    return result;
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

bool CreateTempFile(qstring& out_path, const char* prefix) {
#if defined(_WIN32)
    char temp_dir[MAX_PATH];
    char temp_file_path[MAX_PATH];

    if (GetTempPathA(MAX_PATH, temp_dir) == 0) {
        LogMessage(LOG_PATH, 3, "ERROR: GetTempPathA failed: %ld\n", GetLastError());
        return false;
    }

    if (GetTempFileNameA(temp_dir, prefix, 0, temp_file_path) == 0) {
        LogMessage(LOG_PATH, 3, "ERROR: GetTempFileNameA failed: %ld\n", GetLastError());
        return false;
    }

    out_path = temp_file_path;
    return true;
#else
    // Create a unique temp file name manually
    static int counter = 0;
    qstring filename = qstring(prefix) + "-" + std::to_string(getpid()).c_str() + "-" + std::to_string(++counter).c_str();
    std::filesystem::path full = std::filesystem::temp_directory_path() / filename.c_str();

    std::error_code ec;
    std::filesystem::create_directories(full.parent_path(), ec);
    
    // Create temp file
    auto touch = qfopen(full.string().c_str(), "w");
    if (touch) {
        qfclose(touch);
    }
    
    if (!std::filesystem::exists(full)) {
        LogMessage(LOG_PATH, 3, "ERROR: Failed to create temp file: %s\n", full.string().c_str());
        return false;
    }

    out_path = full.string().c_str();
    return true;
#endif
}

void RemoveFile(const std::string& path) {
#if defined(_WIN32)
    DeleteFileA(path.c_str());
#else
    std::error_code ec;
    std::filesystem::remove(path, ec);
#endif
}