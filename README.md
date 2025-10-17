# BinaryLens
BinaryLens is an IDA plugin that speeds up binary analysis by using language models to rename all functions in a binary, explain binaries, analyze individual functions, rename variables, and more. It’s blazing fast and accurate compared to other tools out there. Here’s a simple example of the results:

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

## Compiling the source code
You need to link **OpenSSL** and **IDA’s SDK** in Visual Studio’s project settings. The necessary paths are already included, you just need to replace them with your own paths. Also make sure to compile the project in x64.

## Compatibility
The plugin requires access to the Hex-Rays decompiler to function.
Tested on Windows 10/11 with IDA 9.1 Pro. Mainly tested on x86 binaries but should also work with other architectures.

## FAQ
### Why not add more model options?
We have tested many models, but only the currently supported ones passed our checks. Adding new models is simple, but not recommended.

### Why not send the decompiled functions chunk by chunk?
The models cannot accurately rename functions without analyzing the entire binary at once.

## TODO
1. Compress decompiled subroutines before sending (remove local variable definitions, etc.).  
2. Allow interactive chat with the model on a selected function.
