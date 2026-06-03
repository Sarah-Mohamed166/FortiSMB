import win32evtlog
import requests
import time
import clickhouse_connect

SERVER = "http://127.0.0.1:8000/predict"

client = clickhouse_connect.get_client(
    host="localhost",
    port=8123,
    username="default",
    password="FortiSMB"
)

server = "localhost"
logtype = "Microsoft-Windows-Sysmon/Operational"

hand = win32evtlog.OpenEventLog(server, logtype)

flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

print("Listening to Sysmon events...")

while True:
    events = win32evtlog.ReadEventLog(hand, flags, 0)

    if events:
        for event in events:
            event_id = event.EventID

            if event_id == 1:
                action = "device"
            elif event_id == 11:
                action = "file"
            elif event_id == 3:
                action = "logon"
            else:
                action = "file"

            payload = {
                "ai_query": f"Sysmon Event ID {event_id}",
                "action": action,
                "fortismb_role": "Administrative Employee",
                "file_op": "copy",
                "is_usb": False,
                "hour": 14,
                "off_hours": False,
                "date": "2026-04-26"
            }

            try:
                response = requests.post(SERVER, json=payload)
                result = response.json()

                client.insert(
                    "fortismb.sysmon_predictions",
                    [[
                        payload["ai_query"],
                        payload["action"],
                        payload["fortismb_role"],
                        payload["file_op"],
                        int(payload["is_usb"]),
                        float(payload["hour"]),
                        int(payload["off_hours"]),
                        result.get("final_risk", ""),
                        result.get("system_action", ""),
                        result.get("ai_explanation", "")
                    ]],
                    column_names=[
                        "ai_query",
                        "action",
                        "role",
                        "file_op",
                        "is_usb",
                        "hour",
                        "off_hours",
                        "final_risk",
                        "system_action",
                        "explanation"
                    ]
                )

                print("Sent Event:", payload)
                print("Prediction:", result)
                print("Saved to ClickHouse")

            except Exception as e:
                print("API/ClickHouse Error:", e)

    time.sleep(3)