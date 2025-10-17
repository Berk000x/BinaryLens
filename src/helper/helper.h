#include <windows.h>
#include <iostream>

#define REACTION_TIME(stop, start, freq) ((double)((stop).QuadPart - (start).QuadPart) / (freq).QuadPart)
#define LOG_PATH "BinaryLensLog.txt"

bool LogMessage(const char* path, int display_type, const char* format, ...);
bool ThreadLogMessage(const char* path, int display_type, const char* format, ...);
bool ReadRegistryData(const char* sub_key, const char* value_name, std::string& read_data);
bool WriteRegistryData(const char* sub_key, const char* value_name, const char* data_to_write);
bool SaveFileContent(const std::string& filepath, const std::string& content);
std::string GetFileContent(const std::string& filepath);
std::string WrapText(const std::string& text, size_t max_line_length);

std::string GetResponseFromModel(
	std::string model,
	std::string api_key,
	std::string system_prompt,
	std::string user_prompt
);

void RemoveSubstring(std::string& str, const std::string& target);
bool ContainsSubstring(const std::string& str, const std::string& target);
void TrimStr(std::string& s);