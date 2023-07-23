import socket
import sys
import time
from multiprocessing import Pool, freeze_support
from types import FunctionType

'''
Creates a thread poll and runs the multi-processing
'''
def run_multiprocessing(func: FunctionType, res: list[any], n_processors: int) -> list[str]:
    with Pool(processes=n_processors) as pool:
        return [str(x) for x in pool.map(func, res) if x is not None]


'''
Scans all the ports based on the start and end port range
'''
def port_scan(args: tuple[str, int, int, bool]) -> int:
    target, start_port, end_port, verbose = args
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            socket.setdefaulttimeout(1)

            for port in range(start_port, end_port):
                result = s.connect_ex((target, port)) # return an error indicator
                if result == 0:
                    if verbose:
                        print(f"Port {port} is open")
                    return port        
                else:
                    if verbose:
                        print(f"Port {port} is closed")

    except KeyboardInterrupt:
        print("\nExiting program")
        sys.exit()
    except socket.gaierror:
        print("Hostname culd not be resolved")
        sys.exit()
    except socket.error:
        print("Couldn't connect to the server")
        sys.exit()

'''
Scans the input from the user.
'''
def scan_input() -> tuple[str, int, int]:
    if len(sys.argv) == 2:
        target = socket.gethostbyname(sys.argv[1]) # translate hostname to IPv4
    else:
        print("Invalid amount of arguements")
        print("Syntax: python scanner.py <ip>")
        sys.exit()
    
    try:
        start_port = int(input("Enter the starting range to scan ports. Eg- 50: "))
        end_port = int(input("Enter the ending range to scan ports. Eg- 500: "))

        if start_port > end_port:
            print("Start port is greater than end port.")
    except Exception:
        start_port = 50
        end_port = 500
        print(f"Due to an error, using {start_port} & {end_port} as start and end range.")
    
    return target, start_port, end_port

'''
Main function to start the scanner.
'''
def main(verbose: bool = False):
    start = time.perf_counter()

    '''
    set up parameters required by the task
    '''
    n_processors = 4
    target, start_port, end_port = scan_input()

    port_range = end_port - start_port
    chunk_size = port_range // n_processors

    input_ports = []

    for cur in range(start_port, end_port + 1, chunk_size):
        input_ports.append((target, cur, min(cur + chunk_size, end_port), verbose))

    out = run_multiprocessing(port_scan, input_ports, n_processors)

    if verbose:
        print(f"Open ports found: {out}")
    
    filename = f'ports-{target.replace(".", "_")}.csv'

    try:
        with open(filename, "w+") as f:
            f.write(','.join(out))

        print(f"Saved the ports to file: {filename}")
    except Exception as error:
        print("Unable to save ports to file.", end="")
        if not verbose:
            print("Hence printing it in the console:")
            print(out)

    print(f"\nMutiprocessing time: {time.perf_counter() - start} secs.")


if __name__ == "__main__":
    freeze_support()   # required to use multiprocessing
    main(True)