# Base Model
| State | Semantic Description |
|-------|----------------------|
| S0    | Initial state. |
| S1    | user1 added the device; user2 has no permissions. |
| S2    | Error state. |
| S3    | user1 added the device and invited user2 to home (family member invitation pending manual acceptance via QR code scan). |
| S4    | user1 invited user2 to home (family member invitation pending manual acceptance via QR code scan); no device added yet. |
| S5    | user1 added the device and invited user2 to home; user2 scanned QR code but hasn't manually accepted invitation yet. |
| S6    | user1 added the device and invited user2 to home; user2 manually accepted invitation and is now family member with automatic control permissions. |
| S7    | user1 added device and double-invited user2 to home; user2 manually accepted one invitation and is family member with automatic control permissions. |
| S8    | user1 invited user2 to home; user2 manually accepted invitation and is family member (no device control yet). |
| S9    | user1 double-invited user2 to home; user2 manually accepted one invitation and is family member (no device control yet). |
| S10   | user1 invited user2 to home; user2 scanned QR code but hasn't manually accepted yet (no device added). |
| S11   | user1 added device and completed family setup with user2; user2 later quit home (family membership and permissions revoked). |
| S12   | user1 invited user2 to home and completed setup; user2 later quit home (family membership revoked, no device was added). |
| S13   | user1 double-invited user2 to home; user2 scanned QR code but hasn't manually accepted yet (no device added). |
| S14   | user1 added device and double-invited user2 to home; user2 scanned QR code but hasn't manually accepted yet. |

# Divergent Model
| State | Final Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device. |
| 2     | Error state. |
| 3     | user1 invited user2 to become a family member (pending manual acceptance). |
| 4     | user1 invited user2, and user2 scanned the QR code (pending manual acceptance). |
| 5     | user1 invited user2, user2 scanned and manually accepted the invitation; user2 is now a family member with automatic control permissions over all user1 devices. |
| 6     | user1 invited user2 twice, user2 scanned and manually accepted the second invitation; user2 is a family member with automatic control permissions over all user1 devices. |
| 7     | user1 added the device, invited user2 twice, user2 scanned and manually accepted the second invitation; user2 is a family member with automatic control permissions over all user1 devices. |
| 8     | user1 added the device, invited user2, user2 scanned and manually accepted; user2 is a family member with automatic control permissions over all user1 devices. |
| 9     | user1 invited user2, user2 scanned, manually accepted, then quit the home; user2's family membership and device permissions are revoked. |
| 10    | user1 added the device, invited user2, and user2 scanned the QR code (pending manual acceptance). |
| 11    | user1 added the device and invited user2 (pending manual acceptance). |
| 12    | user1 added the device, invited user2, user2 scanned, manually accepted, then quit the home; user2's family membership and device permissions are revoked. |
| 13    | user1 added the device, invited user2 twice, user2 scanned the QR code (pending manual acceptance). |
| 14    | user1 invited user2 twice, user2 scanned the QR code (pending manual acceptance). |
| 15    | user1 added the device, invited user2 twice, user2 scanned and manually accepted, gaining automatic control permissions as family member over all user1 devices. |
| 16    | user1 added the device, invited user2 twice, user2 scanned, manually accepted, gained control, then user1 removed the device; user2 retains family permissions but no device to control. |
| 17    | user1 added the device, invited user2 twice, user2 scanned, manually accepted, gained control, user1 removed the device, then user2 quit the home; user2's family membership and device permissions are revoked. |
| 18    | user1 added the device, invited user2 twice, user2 scanned, manually accepted, gained control, user1 removed and re-added the device, then user2 quit the home; user2's family membership and device permissions are revoked. |
| 19    | user1 added the device, invited user2 twice, user2 scanned, manually accepted, gained control, then quit the home; user2's family membership and device permissions are revoked. |
| 20    | user1 added the device, invited user2 twice, user2 scanned, manually accepted, gained control, quit the home, then scanned the QR code again (pending new acceptance). |
| 21    | user1 added the device, invited user2 twice, user2 scanned, manually accepted, gained control, user1 removed and re-added the device, user2 quit the home, then scanned the QR code again (pending new acceptance). |
| 22    | user1 added the device, invited user2 twice, user2 scanned, manually accepted, gained control, user1 removed the device, user2 quit the home, then scanned the QR code again (pending new acceptance). |
| 23    | user1 added the device, invited user2 twice, user2 scanned, manually accepted, gained control, user1 removed the device, user2 quit the home, scanned the QR code, and was re-invited by user1 (pending new acceptance). |
| 24    | user1 added the device, invited user2 twice, user2 scanned, manually accepted, gained control, user1 removed and re-added the device, user2 quit the home, scanned the QR code, and was re-invited by user1 (pending new acceptance). |
| 25    | user1 added the device, invited user2 twice, user2 scanned, manually accepted, gained control, quit the home, scanned the QR code, and was re-invited by user1 (pending new acceptance). |
| 26    | user1 added the device, invited user2, user2 scanned, manually accepted, gained control, then user1 removed the device; user2 retains family permissions but no device to control. |
| 27    | user1 added the device, invited user2, user2 scanned, manually accepted, gained control, user1 removed the device, then user2 quit the home; user2's family membership and device permissions are revoked. |
| 28    | user1 added the device, invited user2, user2 scanned, manually accepted, gained control, user1 removed and re-added the device, then user2 quit the home; user2's family membership and device permissions are revoked. |
| 29    | user1 added the device, invited user2, user2 scanned, manually accepted, gained control, user1 removed and re-added the device; user2 maintains family permissions with automatic control over all user1 devices. |
| 30    | user1 added the device, invited user2, user2 scanned and manually accepted, gaining automatic control permissions as family member over all user1 devices. |
| 31    | user1 added the device, invited user2, user2 scanned, manually accepted, gained control, then quit the home; user2's family membership and device permissions are revoked. |
| 32    | user1 added the device, invited user2 twice, user2 scanned, manually accepted, gained control, user1 removed and re-added the device; user2 maintains family permissions with automatic control over all user1 devices. |

