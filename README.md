
# 🔥 MLS Firewall Simulator

A GUI-based firewall simulation tool developed using **Python** and **PyQt5** for educational purposes. This project mimics a basic firewall with functionalities such as IP rate limiting, manual blacklisting/unblocking, multi-level security enforcement, and simulated network traffic analysis.

## 🚀 Features

* **IP Rate Limiting**: Automatically blocks IPs that exceed the request threshold.
* **Manual Blacklisting**: Admins can manually block or unblock specific IPs.
* **Multi-Level Security (MLS)**: Enforces access control based on IP trust and requested security level.
* **Admin Login**: Secure access to firewall features via a login dialog.
* **Traffic Simulation**: Simulates incoming IP traffic using threading and randomization.
* **Real-Time Monitoring**: Displays live updates of traffic and firewall actions in a GUI table.
* **Event Logging**: Logs firewall activity with timestamps in a log file.

## 🖥️ Technologies Used

* Python 3.x
* PyQt5
* Threading
* File Handling
* Basic Network Security Concepts

## 📂 Project Structure

```
firewall_simulator/
├── firewall_simulator.py     # Main application script
├── firewall_logs.txt         # Auto-generated log file for tracking events
├── README.md                 # Project documentation
```

## 🔧 How to Run

1. **Install dependencies** (PyQt5):

   ```bash
   pip install pyqt5
   ```

2. **Run the application**:

   ```bash
   python firewall_simulator.py
   ```

3. **Login with admin credentials**:

   ```
   Admin ID: admin
   Password: 123
   ```

## 🛡️ Security Logic

* **Rate Limiting**: Max 5 requests per IP per minute.
* **Blacklisting**: Automatically or manually block IPs.
* **Multi-Level Security**:

  * Only trusted IPs can access higher security levels (e.g., `high`).
  * Unknown IPs are restricted based on MLS policies.

## 📝 Notes

* This simulator is meant for educational/demo purposes and not for deployment in real environments.
* Logs are saved to `firewall_logs.txt` in the project directory.

## 👨‍💻 Author

Developed as part of the *Information Security Fundamentals* course.

