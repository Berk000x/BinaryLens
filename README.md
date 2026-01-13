# BinaryLens
BinaryLens is an IDA plugin that speeds up binary analysis by using language models to rename all functions in a binary, explain binaries, analyze individual functions, rename variables, and more. It’s blazing fast and accurate compared to other tools out there. 

We recommend using an IDA MCP server for smaller binaries, since this plugin is mainly meant for larger binaries, as it will finish in minutes what takes an MCP server hours.

Here’s a simple example of the results:

![](imgs/showcase.gif?raw=true)

## Setup
You just need to place the two OpenSSL DLLs (**libcrypto-3-x64.dll** and **libssl-3-x64.dll**) in the directory where ida.exe is located, and put the **BinaryLens** DLL into IDA’s plugins folder.

BinaryLens DLL goes into: `%ProgramFiles%/IDA Professional 9.1/plugins`.

OpenSSL DLLs go into: `%ProgramFiles%/IDA Professional 9.1`.

## Usage
To select a model or set up your API key, go to the **Edit** menu in IDA, then **BinaryLens** → **Select Model**.

You can start the binary analysis through the **Edit** menu (**BinaryLens** → **Rename all subroutines**). For function analysis, use the context menu of IDA’s **pseudocode** window (**BinaryLens** → **Rename Variables**).

## Supported models
[OpenAI](https://platform.openai.com/docs/models)
- GPT-5

[Google Gemini](https://ai.google.dev/gemini-api/docs)
- Gemini-2.5-pro (recommended)

[Deepseek](https://api-docs.deepseek.com/quick_start/pricing)
- Deepseek-chat

## Compatibility
The plugin requires access to the Hex-Rays decompiler to function.
Tested on Windows 10/11 with IDA 9.1 Pro. Mainly tested on x86 binaries but should also work with other architectures.

## Compiling the source code
You need to link **OpenSSL** and **IDA’s SDK** in Visual Studio’s project settings. The necessary paths are already included, you just need to replace them with your own paths. Also make sure to compile the project in x64.

## Build with CMake (Windows)
1. Install Visual Studio 2022 with the Desktop development with C++ workload.
2. Download the IDA 9.1 SDK and set an environment variable or cache entry `IDA_SDK_ROOT` that points to the SDK root (the folder containing `include/` and `lib/x64_win_vc_64/ida.lib`).
3. Install OpenSSL for Windows and set `OPENSSL_ROOT_DIR` to its root (the folder containing `include/` and `lib/`).
4. Configure and build (x64):
	 ```powershell
	 cmake -S . -B build -G "Visual Studio 17 2022" -A x64 ^
		 -DIDA_SDK_ROOT="C:/idasdk91/idasdk91" ^
		 -DOPENSSL_ROOT_DIR="C:/OpenSSL-Win64"
	 cmake --build build --config Release
	 ```
5. Copy `build/bin/BinaryLens.dll` into IDA’s `plugins` directory and keep the required OpenSSL DLLs next to `ida.exe` as described above.

## macOS
An experimental macOS build path now exists. Set `-DBINARYLENS_EXPERIMENTAL_MACOS=ON` when configuring CMake and point `IDA_SDK_ROOT` to your macOS IDA SDK. The source now uses a file-based config under `~/.config/BinaryLens/config.json` instead of the Windows registry and avoids Win32-only timing/temp APIs. Remaining gaps: the UI and IDA SDK interactions have been tested primarily on Windows; please treat macOS as experimental.

## FAQ
#### Why not add more model options?
We have tested many models, but only the currently supported ones passed our checks. Adding new models is simple, but not recommended.

#### Why not send the decompiled functions chunk by chunk?
The models cannot accurately rename functions without analyzing the entire binary at once.

## TODO
1. We already slightly compress the functions before sending, but better compression methods could be added.
2. Allow interactive chat with the model on a selected function.
