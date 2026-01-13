#include <iostream>

#include "plugin/action_handler.h"

#include <hexrays.hpp>

#if defined(_WIN32)
#define BINARYLENS_EXPORT __declspec(dllexport)
#else
#define BINARYLENS_EXPORT __attribute__((visibility("default")))
#endif

BINARYLENS_EXPORT plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC,
    init,
    term,
    run,
    "",
    "",
    "BinaryLens",
    0
};