import datetime

LOG_FILE = "audit.log"

def write_log(user, action):
    with open(LOG_FILE, "a") as log:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"[{timestamp}] USER={user} ACTION={action}\n")
