# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device; user2 has no permissions. |
| 2     | Error state. |
| 3     | user1 added the device and invited user2 to become a family member; invitation pending acceptance. |
| 4     | user1 invited user2 to become a family member; invitation pending acceptance (no device added). |
| 5     | user1 added the device and invited user2 to become a family member; user2 scanned QR code but hasn't accepted yet. |
| 6     | user1 added the device; user2 is a family member with automatic control permissions over all user1 devices. |
| 7     | user1 re-invited user2 while device is present; user2 remains a family member with control permissions. |
| 8     | user2 is a family member with control permissions (no device added yet). |
| 9     | user1 re-invited user2; user2 remains a family member with control permissions (no device added yet). |
| 10    | user1 invited user2 to become a family member; user2 scanned QR code but hasn't accepted yet (no device added). |
| 11    | user1 added the device; user2 was a family member but revoked status, losing all permissions. |
| 12    | user2 was a family member but revoked status, losing all permissions (no device added). |
| 13    | user1 re-invited user2 to become a family member; invitation pending acceptance (no device added). |
| 14    | user1 added the device and re-invited user2 to become a family member; invitation pending acceptance. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device. |
| 2     | Error state. |
| 3     | user1 invited user2 to become a family member (pending acceptance). |
| 4     | user1 invited user2, user2 scanned QR code (pending acceptance). |
| 5     | user1 invited user2, user2 accepted invitation; user2 is now a family member with automatic control permissions. |
| 6     | user1 invited user2 twice, user2 accepted second invitation; user2 is a family member with control permissions. |
| 7     | user1 added device and invited user2 twice, user2 accepted second invitation; user2 is a family member with control permissions. |
| 8     | user1 added device and invited user2, user2 accepted invitation; user2 is a family member with control permissions. |
| 9     | user1 invited user2, user2 accepted then quit home; user2 is no longer a family member. |
| 10    | user1 added device and invited user2, user2 scanned QR code (pending acceptance). |
| 11    | user1 added device and invited user2 (pending acceptance). |
| 12    | user1 added device and invited user2, user2 accepted then quit home; user2 is no longer a family member. |
| 13    | user1 added device and invited user2 twice, user2 scanned QR code (pending acceptance). |
| 14    | user1 invited user2 twice, user2 scanned QR code (pending acceptance). |
| 15    | user1 added device, invited user2 twice, user2 accepted; user2 is family member with active control permissions. |
| 16    | user1 added device, invited user2 twice, user2 accepted and controlled device, then user1 removed device; user2 retains family status but loses device access. |
| 17    | user1 added device, invited user2 twice, user2 accepted and controlled device, user1 removed device, user2 quit home; user2 is no longer a family member. |
| 18    | user1 added device, invited user2 twice, user2 accepted and controlled device, user1 removed/re-added device, user2 quit home; user2 is no longer a family member. |
| 19    | user1 added device, invited user2 twice, user2 accepted and controlled device, then quit home; user2 is no longer a family member. |
| 20    | user1 added device, invited user2 twice, user2 accepted and controlled device, quit home, then scanned QR code (pending acceptance). |
| 21    | user1 added device, invited user2 twice, user2 accepted and controlled device, user1 removed/re-added device, user2 quit home and scanned QR code (pending acceptance). |
| 22    | user1 added device, invited user2 twice, user2 accepted and controlled device, user1 removed device, user2 quit home and scanned QR code (pending acceptance). |
| 23    | user1 added device, invited user2 twice, user2 accepted and controlled device, user1 removed device, user2 quit home, scanned QR code, and user1 re-invited (pending acceptance). |
| 24    | user1 added device, invited user2 twice, user2 accepted and controlled device, user1 removed/re-added device, user2 quit home, scanned QR code, and user1 re-invited (pending acceptance). |
| 25    | user1 added device, invited user2 twice, user2 accepted and controlled device, quit home, scanned QR code, and user1 re-invited (pending acceptance). |
| 26    | user1 added device, invited user2, user2 accepted and controlled device, then user1 removed device; user2 retains family status but loses device access. |
| 27    | user1 added device, invited user2, user2 accepted and controlled device, user1 removed device, user2 quit home; user2 is no longer a family member. |
| 28    | user1 added device, invited user2, user2 accepted and controlled device, user1 removed/re-added device, user2 quit home; user2 is no longer a family member. |
| 29    | user1 added device, invited user2, user2 accepted and controlled device, user1 removed/re-added device; user2 remains family member with control permissions. |
| 30    | user1 added device, invited user2, user2 accepted invitation; user2 is family member with automatic control permissions. |
| 31    | user1 added device, invited user2, user2 accepted and controlled device, then quit home; user2 is no longer a family member. |
| 32    | user1 added device, invited user2 twice, user2 accepted and controlled device, user1 removed/re-added device; user2 remains family member with control permissions. |

