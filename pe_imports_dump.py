import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
import queue
import threading
import hashlib

def get_imported_functions(file_path):
    try:
        result = subprocess.run(['dumpbin.exe', '/nologo', '/imports', file_path], capture_output=True, text=True, shell=True)
        output = result.stdout
        return output
    except Exception as e:
        return ""

def calculate_file_hash(file_path):
    hash_object = hashlib.sha256()  # 使用SHA-256哈希算法
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_object.update(chunk)
    return hash_object.hexdigest()

def worker(file_path, target_function, output_queue):
    imported_functions = get_imported_functions(file_path)
    if target_function in imported_functions:
        file_hash = calculate_file_hash(file_path)
        output_queue.put((file_path, file_hash))

def main():
    root_directory = 'd:\\'
    target_function = 'MiniDumpWriteDump'

    file_paths = []
    for foldername, _, filenames in os.walk(root_directory):
        for filename in filenames:
            if filename.lower().endswith('.exe'):
                file_path = os.path.join(foldername, filename)
                file_paths.append(file_path)

    output_queue = queue.Queue()

    with ThreadPoolExecutor(max_workers=50) as executor:  # 调整线程数
        for file_path in file_paths:
            executor.submit(worker, file_path, target_function, output_queue)

    print("Files with imported function '{}' found:".format(target_function))
    while not output_queue.empty():
        file_path, file_hash = output_queue.get()
        print("File:", file_path)
        print("Hash:", file_hash)
        print("-" * 50)

if __name__ == "__main__":
    main()
