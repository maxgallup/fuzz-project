# Python script: run_frida.py

import frida
import sys

def on_message(message, data):
    print(message["payload"])
    with open("frida_trace.log", "a") as log_file:
        log_file.write(message["payload"])

def main(target_process):
    session = frida.get_usb_device().attach(target_process)
    with open("./hook_andromeda.js") as f:
        script = session.create_script(f.read())
    
    script.on("message", on_message)
    script.load()
    
    sys.stdin.read()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python run_frida.py <process_name>")
        sys.exit(1)

    main(sys.argv[1])

