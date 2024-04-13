# WASMaker

# Getting Started
In order to generate and store AST, you need to first install [MongoDB](https://www.mongodb.com/docs/manual/installation/) and get Wasm binaries from [WasmBench](https://github.com/sola-st/WasmBench).

The script [corpus_preprocess.py](https://github.com/WASMAKER/WASMAKER/blob/main/WASMaker/corpus_preprocess.py) parses WasmBench binaries and stores ASTs in MongoDB. 
And the [binary_generator.py](https://github.com/WASMAKER/WASMAKER/blob/main/WASMaker/binary_generator.py) will generate Wasm binaries and feed them to each Wasm runtime for execution. 

Finally, the output of the runtime is stored in runtime_output.txt.



## Comfirmed Issues
- **wasmtime**
[#7558](https://github.com/bytecodealliance/wasmtime/issues/7558)
- **wamr**
[#2450](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2450)
[#2555](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2555)
[#2556](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2556)
[#2557](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2557)
[#2561](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2561)
[#2677](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2677)
[#2690](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2690)
[#2720](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2720)
[#2789](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2789)
[#2861](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2861)
[#2862](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2862)
- **WasmEdge**
[#2812](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2812)
[#2814](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2814)
[#2815](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2815)
[#2988](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2988)
[#2996](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2996)
[#2997](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2997)
[#2999](https://github.com/bytecodealliance/wasm-micro-runtime/issues/2999)
[#3018](https://github.com/bytecodealliance/wasm-micro-runtime/issues/3018)
[#3019](https://github.com/bytecodealliance/wasm-micro-runtime/issues/3019)
[#3057](https://github.com/bytecodealliance/wasm-micro-runtime/issues/3057)
[#3063](https://github.com/bytecodealliance/wasm-micro-runtime/issues/3063)
[#3068](https://github.com/bytecodealliance/wasm-micro-runtime/issues/3068)
[#3076](https://github.com/bytecodealliance/wasm-micro-runtime/issues/3076)

