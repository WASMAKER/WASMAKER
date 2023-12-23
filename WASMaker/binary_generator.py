import sys
from WASMaker.fuzzer.module_generator import *
import time
import subprocess

current_time = time.time()
sys.setrecursionlimit(1000)
duration = 86400
end_time = current_time + duration

valid_instrs = get_valid_instrs()
i = 0

output_file = open("runtime_output.txt", "a")

while time.time() < end_time:
    filename = f"simd/file{i + 1}.wasm"
    emit_wasm_bianry(filename, valid_instrs)
    print(f"file{i + 1}.wasm generated successfully")

    # invoke command line
    subprocess.run(["echo", "=================================================="], stdout=output_file,
                   stderr=subprocess.STDOUT)
    subprocess.run(["echo", filename], stdout=output_file, stderr=subprocess.STDOUT)

    try:
        subprocess.run(["echo", "-----------------wasmtime-----------------"], stdout=output_file,
                       stderr=subprocess.STDOUT)
        wasmtime_command = "wasmtime run " + filename + " --invoke main"
        process = subprocess.Popen(wasmtime_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, _ = process.communicate(timeout=5)
        wasmtime_output_string = output.decode("utf-8")

        subprocess.run(["echo", wasmtime_output_string], stdout=output_file, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        subprocess.run(["echo", "timeout 5s"], stdout=output_file, stderr=subprocess.STDOUT)
        process.terminate()
        wasmtime_output_string = "timeout 5s"
        command = ['sudo', 'pkill', '-9', 'wasmtime']
        subprocess.run(command, stdout=subprocess.PIPE, text=True)

    try:
        subprocess.run(["echo", "-----------------wasmer-----------------"], stdout=output_file,
                       stderr=subprocess.STDOUT)
        wasmer_command = "wasmer run " + filename + " -i main"
        process = subprocess.Popen(wasmer_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, _ = process.communicate(timeout=5)
        wasmer_output_string = output.decode("utf-8")

        subprocess.run(["echo", wasmer_output_string], stdout=output_file, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        subprocess.run(["echo", "timeout 5s"], stdout=output_file, stderr=subprocess.STDOUT)
        process.terminate()
        wasmer_output_string = "timeout 5s"
        command = ['sudo', 'pkill', '-9', 'wasmer']
        subprocess.run(command, stdout=subprocess.PIPE, text=True)

    try:
        subprocess.run(["echo", "-----------------wamr-----------------"], stdout=output_file, stderr=subprocess.STDOUT)
        wamr_command = "iwasm -f main " + filename
        process = subprocess.Popen(wamr_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, _ = process.communicate(timeout=5)
        wamr_output_string = output.decode("utf-8")

        subprocess.run(["echo", wamr_output_string], stdout=output_file, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        subprocess.run(["echo", "timeout 5s"], stdout=output_file, stderr=subprocess.STDOUT)
        process.terminate()
        wamr_output_string = "timeout 5s"
        command = ['sudo', 'pkill', '-9', 'iwasm']
        subprocess.run(command, stdout=subprocess.PIPE, text=True)
        command = ['sudo', 'pkill', '-9', 'wamrc']
        subprocess.run(command, stdout=subprocess.PIPE, text=True)

    try:
        subprocess.run(["echo", "-----------------wasmedge-----------------"], stdout=output_file,
                       stderr=subprocess.STDOUT)
        wasmedge_command = "wasmedge --reactor " + filename + " main"
        process = subprocess.Popen(wasmedge_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, _ = process.communicate(timeout=5)
        wasmedge_output_string = output.decode("utf-8")

        subprocess.run(["echo", wasmedge_output_string], stdout=output_file, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        subprocess.run(["echo", "timeout 5s"], stdout=output_file, stderr=subprocess.STDOUT)
        process.terminate()
        wasmedge_output_string = "timeout 5s"
        command = ['sudo', 'pkill', '-9', 'wasmedge']
        subprocess.run(command, stdout=subprocess.PIPE, text=True)

    i += 1
