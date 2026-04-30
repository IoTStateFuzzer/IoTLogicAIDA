# Base Model
| State | Semantic Description |
|-------|----------------------|
| S0    | Initial state. |
| S1    | user1 added the device; user2 has no permissions. |
| S2    | Error state. |
| S3    | user1 added the device and invited user2 to home (family member); user2 has not accepted yet. |
| S4    | user1 invited user2 to home (family member); no device added yet. |
| S5    | user1 added the device and invited user2 to home; user2 scanned QR code but has not accepted. |
| S6    | user1 added the device and invited user2 to home; user2 accepted the invite and is now a family member with control permissions. |
| S7    | user1 added the device and invited user2 to home twice; user2 accepted the second invite and is now a family member with control permissions. |
| S8    | user1 invited user2 to home; user2 accepted the invite and is now a family member with control permissions (no device added yet). |
| S9    | user1 invited user2 to home twice; user2 accepted the second invite and is now a family member with control permissions (no device added yet). |
| S10   | user1 invited user2 to home; user2 scanned QR code but has not accepted (no device added yet). |
| S11   | user1 added the device and invited user2 to home; user2 accepted the invite but later quit the home, losing family member status. |
| S12   | user1 invited user2 to home; user2 accepted the invite but later quit the home, losing family member status (no device added). |
| S13   | user1 invited user2 to home twice; user2 has not accepted yet (no device added). |
| S14   | user1 added the device and invited user2 to home twice; user2 has not accepted yet. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device. |
| 2     | Error state. |
| 3     | user1 invited user2 to become a family member (pending QR scan). |
| 4     | user1 invited user2, user2 scanned QR code (pending acceptance). |
| 5     | user1 invited user2, user2 scanned and accepted; user2 is now a family member with control permissions. |
| 6     | user1 invited user2 twice, user2 scanned and accepted once; user2 is a family member with control permissions. |
| 7     | user1 added device, invited user2 twice, user2 scanned and accepted once; user2 is family member with control permissions. |
| 8     | user1 added device, invited user2, user2 scanned and accepted; user2 is family member with control permissions. |
| 9     | user1 invited user2, user2 scanned, accepted, then quit; user2 is no longer a family member. |
| 10    | user1 added device, invited user2, user2 scanned QR code (pending acceptance). |
| 11    | user1 added device and invited user2 (pending QR scan). |
| 12    | user1 added device, invited user2, user2 scanned, accepted, then quit; user2 is no longer a family member. |
| 13    | user1 added device, invited user2 twice, user2 scanned QR code (pending acceptance). |
| 14    | user1 invited user2 twice, user2 scanned QR code (pending acceptance). |
| 15    | user1 added device, invited user2 twice, user2 scanned and accepted, then controlled device; user2 is family member with active control. |
| 16    | user1 added device, invited user2 twice, user2 scanned and accepted, controlled device, then user1 removed device; user2 retains family permissions but no device access. |
| 17    | user1 added device, invited user2 twice, user2 scanned and accepted, controlled device, user1 removed device, then user2 quit; user2 is no longer a family member. |
| 18    | user1 added device, invited user2 twice, user2 scanned and accepted, controlled device, user1 removed and re-added device, then user2 quit; user2 is no longer a family member. |
| 19    | user1 added device, invited user2 twice, user2 scanned and accepted, controlled device, then quit; user2 is no longer a family member. |
| 20    | user1 added device, invited user2 twice, user2 scanned and accepted, controlled device, quit, then scanned QR code again; pending re-invitation. |
| 21    | user1 added device, invited user2 twice, user2 scanned and accepted, controlled device, user1 removed and re-added device, user2 quit, then scanned QR code again; pending re-invitation. |
| 22    | user1 added device, invited user2 twice, user2 scanned and accepted, controlled device, user1 removed device, user2 quit, then scanned QR code again; pending re-invitation. |
| 23    | user1 added device, invited user2 twice, user2 scanned and accepted, controlled device, user1 removed device, user2 quit, scanned QR code again, then user1 re-invited; pending acceptance. |
| 24    | user1 added device, invited user2 twice, user2 scanned and accepted, controlled device, user1 removed and re-added device, user2 quit, scanned QR code again, then user1 re-invited; pending acceptance. |
| 25    | user1 added device, invited user2 twice, user2 scanned and accepted, controlled device, quit, scanned QR code again, then user1 re-invited; pending acceptance. |
| 26    | user1 added device, invited user2, user2 scanned and accepted, controlled device, then user1 removed device; user2 retains family permissions but no device access. |
| 27    | user1 added device, invited user2, user2 scanned and accepted, controlled device, user1 removed device, then user2 quit; user2 is no longer a family member. |
| 28    | user1 added device, invited user2, user2 scanned and accepted, controlled device, user1 removed and re-added device, then user2 quit; user2 is no longer a family member. |
| 29    | user1 added device, invited user2, user2 scanned and accepted, controlled device, user1 removed and re-added device; user2 retains family permissions. |
| 30    | user1 added device, invited user2, user2 scanned and accepted, then controlled device; user2 is family member with active control. |
| 31    | user1 added device, invited user2, user2 scanned and accepted, controlled device, then quit; user2 is no longer a family member. |
| 32    | user1 added device, invited user2 twice, user2 scanned and accepted, controlled device, user1 removed and re-added device; user2 retains family permissions. |

