# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device; user2 has no permissions. |
| 2     | Error state. |
| 3     | user1 added the device and invited user2 to home; user2 has not accepted yet. |
| 4     | user1 invited user2 to home; user2 has not accepted yet. |
| 5     | user1 added the device and invited user2 to home; user2 scanned QR code but has not accepted yet. |
| 6     | user1 added the device and invited user2 to home; user2 accepted and is now a family member with control permissions. |
| 7     | user1 added the device and invited user2 to home twice; user2 accepted and is now a family member with control permissions. |
| 8     | user1 invited user2 to home; user2 accepted and is now a family member with control permissions. |
| 9     | user1 invited user2 to home twice; user2 accepted and is now a family member with control permissions. |
| 10    | user1 invited user2 to home; user2 scanned QR code but has not accepted yet. |
| 11    | user1 added the device and invited user2 to home; user2 accepted and later quit home, losing family member status and permissions. |
| 12    | user1 invited user2 to home; user2 accepted and later quit home, losing family member status and permissions. |
| 13    | user1 invited user2 to home twice; user2 has not accepted yet. |
| 14    | user1 added the device and invited user2 to home twice; user2 has not accepted yet. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device; user2 has no permissions. |
| 2     | Error state. |
| 3     | user1 invited user2 to become a family member; user2 has not accepted yet. |
| 4     | user1 invited user2, and user2 scanned the QR code but has not accepted the invitation. |
| 5     | user1 invited user2, user2 accepted the invitation; user2 is now a family member with control permissions. |
| 6     | user1 re-invited user2 (already a family member); user2 retains control permissions. |
| 7     | user1 added the device and invited user2 (accepted); user2 is a family member with control permissions. |
| 8     | user1 added the device and user2 accepted family invitation; user2 is a family member with control permissions. |
| 9     | user2 quit the family after accepting; user2 no longer has control permissions. |
| 10    | user1 added the device and invited user2; user2 scanned QR code (pending acceptance). |
| 11    | user1 added the device and invited user2 (pending acceptance). |
| 12    | user2 quit the family after accepting; user2 no longer has control permissions. |
| 13    | user1 re-invited user2 (already invited); user2 scanned QR code (pending acceptance). |
| 14    | user1 re-invited user2 (already invited); user2 scanned QR code (pending acceptance). |
| 15    | user2 has control permissions as a family member and used device control. |
| 16    | user1 removed the device; user2 retains family permissions but no device access. |
| 17    | user1 removed the device and user2 quit the family; user2 has no permissions. |
| 18    | user1 re-added the device after removal; user2 quit the family (no permissions). |
| 19    | user2 quit the family after using device control; user2 no longer has permissions. |
| 20    | user2 scanned QR code again after quitting; pending re-invitation. |
| 21    | user2 scanned QR code after device re-addition and quitting; pending re-invitation. |
| 22    | user2 scanned QR code after quitting; pending re-invitation. |
| 23    | user1 re-invited user2 after quitting; pending acceptance. |
| 24    | user1 re-invited user2 after device re-addition and quitting; pending acceptance. |
| 25    | user1 re-invited user2 after quitting; pending acceptance. |
| 26    | user1 removed the device; user2 retains family permissions but no device access. |
| 27    | user2 quit the family after device removal; user2 has no permissions. |
| 28    | user1 re-added the device after removal; user2 quit the family (no permissions). |
| 29    | user1 re-added the device after removal; user2 retains family permissions. |
| 30    | user2 has control permissions as a family member and used device control. |
| 31    | user2 quit the family after using device control; user2 no longer has permissions. |
| 32    | user1 re-added the device after removal; user2 retains family permissions. |

