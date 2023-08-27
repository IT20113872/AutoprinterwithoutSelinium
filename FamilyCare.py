import subprocess
import sys
import os
import unicodedata
from scapy.all import sniff
import requests


# import win32gui
# import win32con

# # Get the window handle for the current console window
# console_window = win32gui.GetForegroundWindow()

# # Set the window style to remove the window from the taskbar
# win32gui.ShowWindow(console_window, win32con.SW_HIDE)


pdf_save_path = "simple.pdf"

visited_urls = set()

# Set the console encoding to utf-8
if sys.stdout.encoding != 'utf-8':
    os.environ["PYTHONIOENCODING"] = "utf-8"
    sys.stdout.reconfigure(encoding='utf-8')


def remove_non_ascii(text):
    return ''.join(char for char in text if unicodedata.category(char)[0] != 'C')


def download_pdf_from_link(url, save_path):
    try:
        response = requests.get(url, stream=True)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            with open(save_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)
            print(f"PDF downloaded and saved to: {save_path}")
        else:
            print(
                f"Failed to download PDF. Status code: {response.status_code}")

    except Exception as e:
        print("Error occurred while downloading the PDF:", e)


def packet_callback(packet):
    # Check if the packet contains the desired layers
    if packet.haslayer("TCP") and packet.haslayer("Raw"):
        # Get the fields of interest from the packet
        sport = packet["TCP"].sport
        dport = packet["TCP"].dport
        load = packet["Raw"].load.decode("utf-8", errors="ignore")

        # Extract the URL from the 'load' field
        url_start = load.find("GET ") + 4
        url_end = load.find(" HTTP/1.1")
        url = load[url_start:url_end]

        # Remove non-ASCII characters from the URL
        url = remove_non_ascii(url)

        # print("Source Port:", sport)
        # print("Destination Port:", dport)
        # print("URL:", url)

        base_url = "/Downloads"
        #     print(url)
        if url and url.startswith(base_url):
            if url not in visited_urls:
                visited_urls.add(url)
                # print(url)
                base = "http://familycare.apps.cipherlabz.com"
                # base = "http://osurapharmacy.apps.cipherlabz.com"
                combine = base + url
                print(combine)

                download_pdf_from_link(combine, pdf_save_path)
                os.startfile(pdf_save_path, 'print')


def get_interface_details():
    try:
        # Run the netsh command to get interface details
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"], capture_output=True, text=True)

        # Check if the command executed successfully
        if result.returncode == 0:
            return result.stdout
        else:
            print("Error executing netsh command:")
            print(result.stderr)
            return None

    except Exception as e:
        print("Error:", e)
        return None


def parse_interface_details(interface_output):
    interface_name = None
    lines = interface_output.splitlines()

    for line in lines:
        # Look for the line containing "Connected" and extract the Interface Name
        if "Connected" in line:
            interface_name = line.split()[-1]
            break

    return interface_name


interface_details = get_interface_details()
if interface_details:
    interface_name = parse_interface_details(interface_details)
    if interface_name:
        print(interface_name)
    else:
        print("No Interface Name found.")


interface = interface_name
# interface = "Wi-Fi"

# Filter TCP packets with destination port 80 (HTTP)
filter_expression = "tcp"

sniff(iface=interface, filter=filter_expression, prn=packet_callback)
