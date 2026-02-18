{
  "targets": [{
    "target_name": "scanner",
    "sources": [
      "src/scanner_engine.cpp",
      "src/threat_detector.cpp",
      "src/storage_manager.cpp",
      "src/logger.cpp",
      "src/bindings.cpp"
    ],
    "include_dirs": [
      "<!@(node -p \"require('node-addon-api').include\")",
      "include"
    ],
    "libraries": [
      "advapi32.lib"
    ],
    "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"],
    "cflags!": [ "-fno-exceptions" ],
    "cflags_cc!": [ "-fno-exceptions" ],
    "msvs_settings": {
      "VCCLCompilerTool": {
        "ExceptionHandling": 1,
        "AdditionalOptions": [ "/std:c++17" ]
      }
    },
    "defines": [ 
      "NAPI_DISABLE_CPP_EXCEPTIONS",
      "_WIN32_WINNT=0x0601"
    ]
  }]
}
