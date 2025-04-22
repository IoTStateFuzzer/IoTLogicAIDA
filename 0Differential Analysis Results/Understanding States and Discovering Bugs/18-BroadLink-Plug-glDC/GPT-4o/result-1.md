# State Semantic Mapping Table

| State | Semantic Description |
|-------|----------------------|
| 0 | Indicates the initial state where no device is added, and user2 has no permissions. |
| 1 | User1 has added a device, and user2 has no permissions. User1 can manage devices and invite user2. |
| 2 | User1 has full control of devices, and user2 has no permissions to perform any actions. |
| 3 | User1 has full control of devices. User1 has invited user2 to the home, but user2 has not accepted the invitation yet. |
| 4 | User1 has invited user2 to the home, and user2 has accepted the invitation. User2 has temporary control over devices. |
| 5 | User1 has full control of devices, and user2 has control permissions on the device after accepting the invitation. |
| 6 | User1 has full control of devices. User2 can control the devices but cannot add or remove devices. |
| 7 | User1 has full control of devices, and user2 has control of devices, including limited permissions to interact with them. |
| 8 | User1 has control over devices, and user2 is actively trying to scan a QR code. |
| 9 | User1 has control over devices, and user2 has the ability to scan a QR code. |
| 10 | User1 can manage devices, and user2 has temporarily accepted an invitation but cannot perform certain actions. |
| 11 | User1 can manage devices, and user2 has been invited but has yet to respond. |
| 12 | User1 is attempting to remove a device, and user2 has no permission to perform actions. |
| 13 | User1 can manage devices, and user2 has been invited and accepted, but user2 is attempting to scan a QR code. |
| 14 | User1 has full control over devices, and user2 is interacting with the devices after being invited. |
| 15 | User1 has full control of devices, and user2 has successfully accepted the invitation but still faces limited interactions. |
| 16 | User1 has full control, and user2 is facing limitations or errors during interaction with devices. |
| 17 | User1 can manage devices, and user2 is interacting, but some errors exist in interaction. |
| 18 | User1 has full control, and user2 can attempt actions but faces frequent errors. |
| 19 | User1 has full control over devices, and user2 is trying to perform actions, but it fails. |
| 20 | User1 can manage devices, and user2 interacts but faces no further issues after accepting the invitation. |
| 21 | User1 has full control, and user2 interacts successfully after being invited. |
| 22 | User1 can manage devices, and user2 interacts successfully with devices after being invited. |
| 23 | User1 can manage devices, and user2 is interacting, but some errors or failures in the interaction happen. |
| 24 | User1 has full control over devices, and user2 can interact but has limited interaction rights. |
| 25 | User1 has control of devices, and user2's interactions are progressing successfully after the invitation. |
| 26 | User1 has full control over devices, and user2 can interact but faces some operation failures. |
| 27 | User1 manages devices, and user2 attempts to control devices but faces frequent errors. |
| 28 | User1 manages devices, and user2 interacts but encounters significant failures. |
| 29 | User1 has control over devices, and user2 can interact but encounters regular errors and failures. |
| 30 | User1 can manage devices, and user2 is able to control devices but with significant limitations. |
| 31 | User1 manages devices, and user2 can interact but faces multiple operational failures. |
| 32 | User1 can manage devices, and user2 is performing operations but encounters frequent errors or failures. |

---

# Vulnerability Report

## Critical Vulnerability Report

### Vulnerability 1: Potential Information Leakage
**Threat Level**: High Risk

**Attack Path**:
1. Attacker (user2) has been temporarily invited by user1 into the home and has access to certain device control functionalities.
2. The attacker (user2) may still retain partial knowledge or access to device data even after being removed from the home group.
3. Information about user1's device configurations and current statuses can be leaked, allowing unauthorized access to potentially sensitive data.

**Repeat Steps**:
1. Starting from state s0, user1 adds a device and invites user2 into the family.
2. After accepting the invitation in state 4, user2 is granted limited permissions to control devices.
3. If user2 is removed (state s2), and then re-invited (state s5), the attacker could still access certain details about the device and the home configuration, potentially leading to information leakage. 

