# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0 | Initial state: user1 has not added the device; user2 is not invited. |
| 1 | user1 added the device once; user2 is not invited. |
| 2 | Error state. |
| 3 | user1 added the device once and invited user2 to become a family member; user2 has not accepted the invitation and has no control permissions. |
| 4 | user1 has not added the device; user2 is invited to become a family member but has not accepted and has no control permissions. |
| 5 | user1 added the device once and invited user2 to become a family member; user2 scanned the QR code but has not accepted the invitation and has no control permissions. |
| 6 | user1 added the device once; user2 is a family member and has control permissions. |
| 7 | user1 added the device once and sent two invitations to user2; user2 is a family member and has control permissions. |
| 8 | user1 has not added the device; user2 is a family member and has control permissions (no device present). |
| 9 | user1 has not added the device and sent two invitations to user2; user2 is a family member and has control permissions (no device present). |
| 10 | user1 has not added the device; user2 was invited to become a family member, scanned the QR code, but has not accepted and has no control permissions. |
| 11 | user1 added the device once; user2 quit the family and lost all control permissions. |
| 12 | user1 has not added the device; user2 quit the family and lost all control permissions. |
| 13 | user1 has not added the device and sent two invitations to user2; user2 scanned the first invitation but has not accepted and has no control permissions. |
| 14 | user1 added the device once and sent two invitations to user2; user2 scanned the first invitation but has not accepted and has no control permissions. |

# Divergent Model

| State | Semantic Description |
|-------|----------------------|
| 0 | Initial state: user1 has not added the device (count=0, device absent); user2 is not invited and has no control permissions. |
| 1 | user1 added the device once (device present); user2 is not invited and has no control permissions. |
| 2 | Error state. |
| 3 | user1 has not added the device (count=0, device absent); user2 is invited to become a family member but has not accepted, so not a family member and has no control permissions. |
| 4 | user1 has not added the device (count=0, device absent); user2 is invited to become a family member but has not accepted, so not a family member and has no control permissions. |
| 5 | user1 has not added the device (count=0, device absent); user2 is a family member but has no control permissions due to device absence. |
| 6 | user1 has not added the device (count=0, device absent); user2 is a family member but has no control permissions due to device absence. |
| 7 | user1 added the device once (device present); user2 is a family member and has control permissions. |
| 8 | user1 added the device once (device present); user2 is a family member and has control permissions. |
| 9 | user1 has not added the device (count=0, device absent); user2 quit the family (not a family member) and has no control permissions. |
| 10 | user1 added the device once (device present); user2 is invited to become a family member but has not accepted, so not a family member and has no control permissions. |
| 11 | user1 added the device once (device present); user2 is invited to become a family member but has not accepted, so not a family member and has no control permissions. |
| 12 | user1 added the device once (device present); user2 quit the family (not a family member) and has no control permissions. |
| 13 | user1 added the device once (device present); user2 is invited to become a family member but has not accepted, so not a family member and has no control permissions. |
| 14 | user1 has not added the device (count=0, device absent); user2 is invited to become a family member but has not accepted, so not a family member and has no control permissions. |
| 15 | user1 added the device once (device present); user2 is a family member and has control permissions. |
| 16 | user1 added and then removed the device (count=1; device absent); user2 is a family member but has no control permissions due to device absence. |
| 17 | user1 added and then removed the device (count=1; device absent); user2 quit the family (not a family member) and has no control permissions. |
| 18 | user1 added the device twice (re-added after removal; device present); user2 quit the family and has no control permissions. |
| 19 | user1 added the device once (device present); user2 quit the family and has no control permissions. |
| 20 | user1 added the device once (device present); user2 quit the family and has no control permissions. |
| 21 | user1 added the device twice (device present); user2 quit the family and has no control permissions. |
| 22 | user1 added and then removed the device (count=1; device absent); user2 is not a family member and has no control permissions. |
| 23 | user1 added and then removed the device (count=1; device absent); user2 is invited to become a family member but has not accepted, so not a family member and has no control permissions. |
| 24 | user1 added the device twice (count=2; device absent); user2 is invited to become a family member but has not accepted, so not a family member and has no control permissions. |
| 25 | user1 added the device once (device present); user2 is invited to become a family member but has not accepted, so not a family member and has no control permissions. |
| 26 | user1 added and then removed the device (count=1; device absent); user2 is a family member but has no control permissions due to device absence. |
| 27 | user1 added and then removed the device (count=1; device absent); user2 quit the family and has no control permissions. |
| 28 | user1 added the device twice (device present); user2 quit the family and has no control permissions. |
| 29 | user1 added the device twice (re-added after removal; device present); user2 is a family member and has control permissions. |
| 30 | user1 added the device once (device present); user2 is a family member and has control permissions. |
| 31 | user1 added the device once (device present); user2 quit the family and has no control permissions. |
| 32 | user1 added the device twice (re-added after removal; device present); user2 is a family member and has control permissions. |

