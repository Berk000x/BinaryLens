#pragma once

#ifndef __cplusplus
#error "This header requires C++"
#endif

// Forward declare qstring to avoid circular includes
template<class T> class _qstring;
using qstring = _qstring<char>;

#include <string>
#include <cstddef>

#define LOG_PATH "BinaryLensLog.txt"

bool LogMessage(const char* path, int display_type, const char* format, ...);
bool ThreadLogMessage(const char* path, int display_type, const char* format, ...);
bool ReadRegistryData(const char* sub_key, const char* value_name, std::string& read_data);
bool WriteRegistryData(const char* sub_key, const char* value_name, const char* data_to_write);
bool CreateTempFile(qstring& out_path, const char* prefix);
void RemoveFile(const std::string& path);
bool SaveFileContent(const qstring& filepath, const qstring& content);
qstring GetFileContent(const qstring& filepath);
std::string WrapText(const std::string& text, size_t max_line_length);

qstring GetResponseFromModel(
	const qstring& model,
	const qstring& api_key,
	const qstring& system_prompt,
	const qstring& user_prompt
);

void RemoveSubstring(std::string& str, const std::string& target);
bool ContainsSubstring(const std::string& str, const std::string& target);
void TrimStr(std::string& s);