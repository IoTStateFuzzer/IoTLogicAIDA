# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0  | Initial state. No device is added; user2 has no invitation or permissions. |
| 1  | user1 has added the device once; user2 is not invited and has no permissions. |
| 2  | Error state. |
| 3  | user1 has added the device once, invited user2, but user2 has not accepted and currently has no control. |
| 4  | No device is added; user2 is invited but has not accepted, and has no control. |
| 5  | user1 has added the device once, invited user2, and user2 scanned the code but has not fully accepted, so user2 has no control. |
| 6  | user1 has added the device once; user2 accepted the family invitation and now holds permanent control rights. |
| 7  | user1 has added the device once and repeatedly invited user2. user2 ultimately accepted and is a family member with permanent control rights. |
| 8  | No device is added; user2 has accepted the family invitation and is a family member with potential control over future devices. |
| 9  | No device is added; user2, after multiple invites, accepted and is now a family member with potential control over future devices. |
| 10 | No device is added; user2 scanned the invitation code but has not accepted, so user2 remains invited with no control. |
| 11 | user1 has added the device once; user2 joined as a family member but quit, losing all control. |
| 12 | No device is added; user2 briefly joined the family but quit, so user2 has no membership or control. |
| 13 | No device is added; user2 was invited multiple times and scanned the code yet never accepted, so user2 remains invited without control. |
| 14 | user1 has added the device once and invited user2 multiple times; user2 remains invited but has not accepted, so no control. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0  | Initial state. No device is added, and user2 has no invitation or membership. |
| 1  | user1 has added one device; user2 is not invited and has no permissions. |
| 2  | Error state. |
| 3  | No device is added; user2 is invited to become a family member but has not accepted. |
| 4  | No device is added; user2 scanned the family invitation code but has not accepted. |
| 5  | No device is added; user2 accepted the invitation and is now a family member with permanent control rights. |
| 6  | No device is added; user2 became a family member through repeated invites and now has permanent rights. |
| 7  | user1 has added one device; user2 is a family member with permanent control over it. |
| 8  | user1 has one device; user2 is a family member with permanent control rights. |
| 9  | No device is added; user2 joined as a family member, then quit, so user2 no longer has membership. |
| 10 | user1 has one device; user2 was invited, scanned, but has not accepted the invitation. |
| 11 | user1 has one device; user2 is invited but has not accepted membership. |
| 12 | user1 has one device; user2 joined as a family member, then quit, losing membership. |
| 13 | user1 has one device; user2 was re-invited but has not accepted membership. |
| 14 | No device is added; user2 received multiple invitations but has not accepted membership. |
| 15 | user1 has one device; user2 is a family member actively controlling it. |
| 16 | user1 removed the device. user2 remains a family member with no current device to control. |
| 17 | user1 removed the device, and user2 quit the family, losing membership. |
| 18 | user1 re-added the device; user2 quit and is no longer a family member. |
| 19 | user1 has one device; user2 had family control but quit, losing membership. |
| 20 | user1 has one device; user2 quit the family, scanned again, but did not re-accept and remains outside the family. |
| 21 | user1 re-added the device; user2 quit and scanning again did not restore membership, so user2 remains outside the family. |
| 22 | No device is present; user2 quit the family and scanning again did not restore membership. |
| 23 | No device is present; user2 quit, scanned again, was re-invited, but has not accepted. |
| 24 | user1 has one device re-added; user2 quit, scanned again, and was re-invited but has not accepted. |
| 25 | user1 has one device; user2 quit, scanned again, and is re-invited but has not accepted. |
| 26 | user1 removed the device after user2 used it; user2 is still a family member with no current device. |
| 27 | user1 removed the device; user2 then quit, losing family membership. |
| 28 | user1 re-added the device; user2 quit the family and is no longer a member. |
| 29 | user1 re-added the device; user2 remains a family member with automatic control. |
| 30 | user1 has one device; user2 is a family member actively controlling it. |
| 31 | user1 has one device; user2 quit the family, losing all control rights. |
| 32 | user1 removed and re-added the device; user2 remains a family member with control rights. |

