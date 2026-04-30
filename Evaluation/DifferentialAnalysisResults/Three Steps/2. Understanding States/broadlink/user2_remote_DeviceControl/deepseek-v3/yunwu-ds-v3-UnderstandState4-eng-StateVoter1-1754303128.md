# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device; user2 has no permissions. |
| 2     | Error state. |
| 3     | user1 added the device and invited user2 to become family member; invitation pending acceptance by user2. |
| 4     | user1 invited user2 to become family member; invitation pending acceptance by user2; no device added yet. |
| 5     | user1 added the device and invited user2 to become family member; user2 scanned QR code but hasn't completed acceptance. |
| 6     | user1 added the device; user2 accepted family membership and has full control permissions. |
| 7     | user1 added the device and re-invited user2; user2 maintains family membership with full control permissions. |
| 8     | user2 accepted family membership and has full control permissions; no device added by user1 yet. |
| 9     | user1 re-invited user2; user2 maintains family membership with full control permissions; no device added yet. |
| 10    | user1 invited user2 to become family member; user2 scanned QR code but hasn't completed acceptance; no device added yet. |
| 11    | user1 added the device; user2 was family member but revoked status (permissions revoked). |
| 12    | user2 was family member but revoked status (permissions revoked); no device added by user1. |
| 13    | user1 re-invited user2 to become family member; user2 hasn't completed acceptance; no device added yet. |
| 14    | user1 added the device and re-invited user2; user2 hasn't completed family membership acceptance. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device. |
| 2     | Error state. |
| 3     | user1 invited user2 to become a family member (pending manual acceptance). |
| 4     | user1 invited user2, and user2 scanned the QR code (pending manual acceptance). |
| 5     | user1 invited user2, user2 manually accepted; user2 is now a family member with automatic control rights over all user1 devices. |
| 6     | user1 invited user2 twice, user2 manually accepted the second invitation; user2 is a family member with automatic control rights. |
| 7     | user1 added the device, invited user2 twice, user2 manually accepted the second invitation; user2 is a family member with automatic control rights. |
| 8     | user1 added the device, invited user2, user2 manually accepted; user2 is a family member with automatic control rights. |
| 9     | user1 invited user2, user2 accepted then quit the home; user2 is no longer a family member and all permissions are revoked. |
| 10    | user1 added the device, invited user2, user2 scanned the QR code (pending manual acceptance). |
| 11    | user1 added the device and invited user2 (pending manual acceptance). |
| 12    | user1 added the device, invited user2, user2 accepted then quit the home; user2 is no longer a family member. |
| 13    | user1 added the device, invited user2 twice, user2 scanned the QR code (pending manual acceptance). |
| 14    | user1 invited user2 twice, user2 scanned the QR code (pending manual acceptance). |
| 15    | user1 added the device, invited user2 twice, user2 manually accepted; user2 is a family member with automatic control rights. |
| 16    | user1 added the device, invited user2 twice, user2 accepted and controlled it, then user1 removed the device; user2 retains family membership but device access is revoked. |
| 17    | user1 added the device, invited user2 twice, user2 accepted and controlled it, user1 removed the device, then user2 quit the home; user2 is no longer a family member. |
| 18    | user1 added the device, invited user2 twice, user2 accepted and controlled it, user1 removed and re-added the device, then user2 quit the home; user2 is no longer a family member. |
| 19    | user1 added the device, invited user2 twice, user2 accepted and controlled it, then quit the home; user2 is no longer a family member. |
| 20    | user1 added the device, invited user2 twice, user2 accepted and controlled it, quit the home, then scanned QR code again (pending acceptance). |
| 21    | user1 added the device, invited user2 twice, user2 accepted and controlled it, user1 removed and re-added the device, user2 quit the home, then scanned QR code again (pending acceptance). |
| 22    | user1 added the device, invited user2 twice, user2 accepted and controlled it, user1 removed the device, user2 quit the home, then scanned QR code again (pending acceptance). |
| 23    | user1 added the device, invited user2 twice, user2 accepted and controlled it, user1 removed the device, user2 quit the home, scanned QR code, then user1 re-invited (pending acceptance). |
| 24    | user1 added the device, invited user2 twice, user2 accepted and controlled it, user1 removed and re-added the device, user2 quit the home, scanned QR code, then user1 re-invited (pending acceptance). |
| 25    | user1 added the device, invited user2 twice, user2 accepted and controlled it, quit the home, scanned QR code, then user1 re-invited (pending acceptance). |
| 26    | user1 added the device, invited user2, user2 accepted and controlled it, then user1 removed the device; user2 retains family membership but device access is revoked. |
| 27    | user1 added the device, invited user2, user2 accepted and controlled it, user1 removed the device, then user2 quit the home; user2 is no longer a family member. |
| 28    | user1 added the device, invited user2, user2 accepted and controlled it, user1 removed and re-added the device, then user2 quit the home; user2 is no longer a family member. |
| 29    | user1 added the device, invited user2, user2 accepted and controlled it, user1 removed and re-added the device; user2 retains family membership with automatic control rights. |
| 30    | user1 added the device, invited user2, user2 manually accepted; user2 is a family member with automatic control rights. |
| 31    | user1 added the device, invited user2, user2 accepted and controlled it, then quit the home; user2 is no longer a family member. |
| 32    | user1 added the device, invited user2 twice, user2 accepted and controlled it, user1 removed and re-added the device; user2 retains family membership with automatic control rights. |

