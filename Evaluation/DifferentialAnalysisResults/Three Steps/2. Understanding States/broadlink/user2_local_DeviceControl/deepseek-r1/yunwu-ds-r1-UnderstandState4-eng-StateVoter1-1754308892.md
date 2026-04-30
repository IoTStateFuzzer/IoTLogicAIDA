# Base Model

| State | Semantic Description |
|-------|----------------------|
| 0 | user1 has not added any device; user2 is not invited. |
| 1 | user1 added the device once; user2 is not invited. |
| 2 | Error state. |
| 3 | user1 added the device once and invited user2 to become a family member; user2 has not accepted, so no control permissions. |
| 4 | user1 has not added any device and invited user2 to become a family member; user2 has not accepted, so no control permissions. |
| 5 | user1 added the device once and invited user2 to become a family member; user2 has not accepted, so no control permissions. |
| 6 | user1 added the device once; user2 is a family member and has control permissions. |
| 7 | user1 added the device once and sent two family invitations; user2 is a family member and has control permissions. |
| 8 | user1 has not added any device; user2 is a family member with control permissions for any future device. |
| 9 | user1 has not added any device and sent two family invitations; user2 is a family member with control permissions for any future device. |
| 10 | user1 has not added any device and invited user2 to become a family member; user2 has not accepted, so no control permissions. |
| 11 | user1 added the device once; user2 was a family member but quit, so no control permissions. |
| 12 | user1 has not added any device; user2 was a family member but quit, so no control permissions. |
| 13 | user1 has not added any device and sent two family invitations to user2; user2 has not accepted, so no control permissions. |
| 14 | user1 added the device once and sent two family invitations to user2; user2 has not accepted, so no control permissions. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0 | Device not present (added 0 times); user2 not invited. |
| 1 | Device present (1st addition); user2 not invited. |
| 2 | Error state. |
| 3 | Device not present (added 0 times); user2 invited but unaccepted. |
| 4 | Device not present (added 0 times); user2 invited but unaccepted. |
| 5 | Device not present (added 0 times); user2 is a family member with control permissions. |
| 6 | Device not present (added 0 times); user2 is a family member with control permissions. |
| 7 | Device present (1st addition); user2 is a family member with control permissions. |
| 8 | Device present (1st addition); user2 is a family member with control permissions. |
| 9 | Device not present (added 0 times); user2 not a family member. |
| 10 | Device present (1st addition); user2 invited but unaccepted. |
| 11 | Device present (1st addition); user2 invited but unaccepted. |
| 12 | Device present (1st addition); user2 not a family member. |
| 13 | Device present (1st addition); user2 invited but unaccepted. |
| 14 | Device not present (added 0 times); user2 invited but unaccepted. |
| 15 | Device present (1st addition); user2 is a family member with control permissions. |
| 16 | Device not present (added 1 time); user2 is a family member with control permissions. |
| 17 | Device not present (added 1 time); user2 not a family member. |
| 18 | Device present (2nd addition); user2 not a family member. |
| 19 | Device present (1st addition); user2 not a family member. |
| 20 | Device present (1st addition); user2 not a family member. |
| 21 | Device present (2nd addition); user2 not a family member. |
| 22 | Device not present (added 1 time); user2 not a family member. |
| 23 | Device not present (added 1 time); user2 invited but unaccepted. |
| 24 | Device present (2nd addition); user2 invited but unaccepted. |
| 25 | Device present (1st addition); user2 invited but unaccepted. |
| 26 | Device not present (added 1 time); user2 is a family member with control permissions. |
| 27 | Device not present (added 1 time); user2 not a family member. |
| 28 | Device present (2nd addition); user2 not a family member. |
| 29 | Device present (2nd addition); user2 is a family member with control permissions. |
| 30 | Device present (1st addition); user2 is a family member with control permissions. |
| 31 | Device present (1st addition); user2 not a family member. |
| 32 | Device present (2nd addition); user2 is a family member with control permissions. |

