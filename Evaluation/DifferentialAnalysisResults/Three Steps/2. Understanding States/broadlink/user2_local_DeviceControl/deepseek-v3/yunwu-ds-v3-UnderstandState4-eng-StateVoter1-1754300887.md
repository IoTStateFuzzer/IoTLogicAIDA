# Base Model
| State | Semantic Description |
|-------|----------------------|
| S0    | Initial state. |
| S1    | user1 added the device; user2 has no permissions. |
| S2    | Error state. |
| S3    | user1 added the device and invited user2 to become family member; user2 has not yet accepted. |
| S4    | user1 invited user2 to become family member; no device added yet. |
| S5    | user1 added the device and invited user2 to become family member; user2 scanned QR code but has not accepted yet. |
| S6    | user1 added the device and invited user2 to become family member; user2 accepted and now has automatic control permissions over all user1 devices. |
| S7    | user1 added the device and invited user2 to become family member twice; user2 accepted second invitation and now has automatic control permissions over all user1 devices. |
| S8    | user1 invited user2 to become family member; user2 accepted and now has automatic control permissions (no device added yet). |
| S9    | user1 invited user2 to become family member twice; user2 accepted second invitation and now has automatic control permissions (no device added yet). |
| S10   | user1 invited user2 to become family member; user2 scanned QR code but has not accepted yet (no device added). |
| S11   | user1 added the device and invited user2 to become family member; user2 accepted but later quit home, losing family membership and all permissions. |
| S12   | user1 invited user2 to become family member; user2 accepted but later quit home, losing family membership and all permissions (no device added). |
| S13   | user1 invited user2 to become family member twice; user2 scanned QR code but has not accepted yet (no device added). |
| S14   | user1 added the device and invited user2 to become family member twice; user2 scanned QR code but has not accepted yet. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device. |
| 2     | Error state. |
| 3     | user1 invited user2 to become a family member (pending acceptance). |
| 4     | user1 invited user2, and user2 scanned the QR code (pending acceptance). |
| 5     | user1 invited user2, user2 scanned and accepted the invitation; user2 is now a family member with control permissions. |
| 6     | user1 invited user2 twice, user2 scanned and accepted the second invitation; user2 is a family member with control permissions. |
| 7     | user1 added the device, invited user2 twice, user2 scanned and accepted the second invitation; user2 is a family member with control permissions. |
| 8     | user1 added the device, invited user2, user2 scanned and accepted the invitation; user2 is a family member with control permissions. |
| 9     | user1 invited user2, user2 scanned, accepted, and then quit the home; user2 is no longer a family member. |
| 10    | user1 added the device and invited user2; user2 scanned the QR code (pending acceptance). |
| 11    | user1 added the device and invited user2 (pending acceptance). |
| 12    | user1 added the device, invited user2, user2 scanned, accepted, and then quit the home; user2 is no longer a family member. |
| 13    | user1 added the device, invited user2 twice, user2 scanned the QR code (pending acceptance). |
| 14    | user1 invited user2 twice, user2 scanned the QR code (pending acceptance). |
| 15    | user1 added the device, invited user2 twice, user2 scanned, accepted, and controlled the device; user2 is a family member with control permissions. |
| 16    | user1 added the device, invited user2 twice, user2 scanned, accepted, controlled the device, and user1 removed the device; user2 retains family membership but loses device control. |
| 17    | user1 added the device, invited user2 twice, user2 scanned, accepted, controlled the device, user1 removed the device, and user2 quit the home; user2 is no longer a family member. |
| 18    | user1 added the device, invited user2 twice, user2 scanned, accepted, controlled the device, user1 removed and re-added the device, and user2 quit the home; user2 is no longer a family member. |
| 19    | user1 added the device, invited user2 twice, user2 scanned, accepted, controlled the device, and quit the home; user2 is no longer a family member. |
| 20    | user1 added the device, invited user2 twice, user2 scanned, accepted, controlled the device, quit the home, and scanned again (pending acceptance). |
| 21    | user1 added the device, invited user2 twice, user2 scanned, accepted, controlled the device, user1 removed and re-added the device, user2 quit the home, and scanned again (pending acceptance). |
| 22    | user1 added the device, invited user2 twice, user2 scanned, accepted, controlled the device, user1 removed the device, user2 quit the home, and scanned again (pending acceptance). |
| 23    | user1 added the device, invited user2 twice, user2 scanned, accepted, controlled the device, user1 removed the device, user2 quit the home, scanned again, and user1 re-invited user2 (pending acceptance). |
| 24    | user1 added the device, invited user2 twice, user2 scanned, accepted, controlled the device, user1 removed and re-added the device, user2 quit the home, scanned again, and user1 re-invited user2 (pending acceptance). |
| 25    | user1 added the device, invited user2 twice, user2 scanned, accepted, controlled the device, quit the home, scanned again, and user1 re-invited user2 (pending acceptance). |
| 26    | user1 added the device, invited user2, user2 scanned, accepted, controlled the device, and user1 removed the device; user2 retains family membership but loses device control. |
| 27    | user1 added the device, invited user2, user2 scanned, accepted, controlled the device, user1 removed the device, and user2 quit the home; user2 is no longer a family member. |
| 28    | user1 added the device, invited user2, user2 scanned, accepted, controlled the device, user1 removed and re-added the device, and user2 quit the home; user2 is no longer a family member. |
| 29    | user1 added the device, invited user2, user2 scanned, accepted, controlled the device, user1 removed and re-added the device; user2 is a family member with control permissions. |
| 30    | user1 added the device, invited user2, user2 scanned, accepted, and controlled the device; user2 is a family member with control permissions. |
| 31    | user1 added the device, invited user2, user2 scanned, accepted, controlled the device, and quit the home; user2 is no longer a family member. |
| 32    | user1 added the device, invited user2 twice, user2 scanned, accepted, controlled the device, user1 removed and re-added the device; user2 is a family member with control permissions. |

