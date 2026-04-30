import os
import subprocess
import sys

def find_process_by_port(port):
    """find pid of process using the specified port"""
    try:
        if os.name == 'nt':  # Windows
            result = subprocess.check_output(f'netstat -ano | findstr :{port}', shell=True).decode()
            if result:
                lines = result.strip().split('\n')
                for line in lines:
                    if f':{port}' in line:
                        parts = line.strip().split()
                        # last part is PID
                        return parts[-1]
        else:  # Linux/Mac
            result = subprocess.check_output(f'lsof -i :{port}', shell=True).decode()
            if result:
                lines = result.strip().split('\n')
                if len(lines) > 1:
                    return lines[1].split()[1]
    except subprocess.CalledProcessError:
        pass
    return None

def kill_process(pid):
    """terminate the process with the specified PID"""
    try:
        if os.name == 'nt':  # Windows
            subprocess.check_output(f'taskkill /F /PID {pid}', shell=True)
        else:  # Linux/Mac
            subprocess.check_output(f'kill -9 {pid}', shell=True)
        print(f"Terminated process PID: {pid}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to terminate process: {e}")
        return False

def clean_appium_port(port):
    """clean the specified Appium port"""
    pid = find_process_by_port(port)
    if pid:
        print(f"Found process {pid} using port {port}")
        if kill_process(pid):
            print(f"Successfully released port {port}")
        else:
            print(f"Failed to release port {port}")
    else:
        print(f"Port {port} is not in use")

if __name__ == "__main__":
    port = 4728  # default Appium port
    
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("Please provide a valid port number")
            sys.exit(1)
    
    print(f"Cleaning Appium port {port}...")
    clean_appium_port(port)

    # check for other possible Appium/Node.js processes
    print("\nChecking for other possible Appium/Node.js processes...")
    try:
        if os.name == 'nt':  # Windows
            os.system('tasklist | findstr "node.exe"')
        else:  # Linux/Mac
            os.system('ps aux | grep appium')
    except:
        pass 