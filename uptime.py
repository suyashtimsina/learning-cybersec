import urllib.request
import time

# List of website URLs to monitor
websites = [
    "https://www.google.com",
    "https://www.github.com",
    "https://www.youtube.com",
    "https://httpstat.us/404"  # A test page designed to fail (404 Not Found)
]

def check_status():
    print("--- Checking Websites ---")
    for url in websites:
        try:
            # 1. Send a quick connection request (times out after 5 seconds)
            response = urllib.request.urlopen(url, timeout=5)
            
            # 2. HTTP code 200 means "OK / Success"
            if response.getcode() == 200:
                print(f"[ONLINE]  {url}")
                
        except Exception as error:
            # 3. If the connection fails or returns an error code
            print(f"[OFFLINE] {url} -> Details: {error}")

# Run the monitor on a loop
while True:
    check_status()
    print("\nWaiting 10 seconds before next check...\n")
    time.sleep(10)  # Pause for 10 seconds