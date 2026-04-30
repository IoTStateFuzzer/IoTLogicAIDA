# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 has added the device once; user2 is not invited and has no control rights. |
| 2     | Error state. |
| 3     | user1 has added the device once and invited user2 to become a family member; user2 has not accepted yet, so no control. |
| 4     | No device has been added; user2 is invited but has not accepted yet, so no control. |
| 5     | user1 has added the device once and invited user2; user2 scanned the code but has not accepted, so no control. |
| 6     | user1 has added the device once; user2 accepted the family invite and now has permanent control rights. |
| 7     | user1 has added the device once (possibly after multiple invites); user2 ultimately accepted and is a family member with permanent control rights. |
| 8     | No device has been added; user2 is a family member with permanent control rights for any future devices. |
| 9     | No device has been added; user2 is a family member with permanent control rights. |
| 10    | No device has been added; user2 scanned the invitation but has not accepted, so no control. |
| 11    | user1 has added the device once; user2 was a family member but quit, losing all control rights. |
| 12    | No device has been added; user2 was a family member but quit, so has no control. |
| 13    | No device has been added; user2 was invited repeatedly but has not accepted, so no control. |
| 14    | user1 has added the device once; user2 was invited (possibly multiple times) but has not accepted, so no control. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0  | Initial state. No device is added; user2 is not invited. |
| s1  | user1 has added the device once; user2 is not invited and has no control. |
| s2  | Error state. |
| s3  | No device is added; user2 is invited but has not accepted family membership. |
| s4  | No device is added; user2 scanned the invitation but has not finished accepting. |
| s5  | No device is added; user2 accepted the invite and is now a family member (no device bound yet). |
| s6  | No device is added; user2 is a family member with permanent rights over any future device. |
| s7  | user1 has added one device; user2 is a family member with control rights. |
| s8  | user1 has added one device; user2 is a family member with control. |
| s9  | No device is added; user2 was a family member but quit, losing membership. |
| s10 | user1 has added one device; user2 is invited but has not accepted. |
| s11 | user1 has added one device; user2 is invited but has not fully accepted membership. |
| s12 | user1 has added one device; user2 was a family member but quit and is no longer a member. |
| s13 | user1 has added one device; user2 scanned a second invite but never accepted, remaining non-member. |
| s14 | No device is added; user2 was re-invited but has not accepted. |
| s15 | user1 has added one device; user2 is a family member actively controlling the device. |
| s16 | user1 removed the device; user2 remains a family member but no device is bound. |
| s17 | No device is bound; user2 quit the home and is no longer a family member. |
| s18 | user1 re-added the device; user2 quit the home and is no longer a member. |
| s19 | user1 has one device; user2 was a family member but quit and is no longer a member. |
| s20 | user1 has one device; user2 quit the home, then scanned a code without being re-invited or accepted. |
| s21 | user1 re-added the device; user2 quit the home, scanned again, but remains outside the family. |
| s22 | No device is bound; user2 quit home, scanned a code, but is not re-invited or accepted. |
| s23 | No device is bound; user1 re-invited user2 after a quit, but user2 hasn't accepted yet. |
| s24 | user1 has re-added the device; user2 was re-invited but hasn't accepted membership. |
| s25 | user1 has one device; user2 quit, was re-invited, but hasn't accepted membership. |
| s26 | user1 removed the device; user2 remains a family member with no device to control. |
| s27 | No device is bound; user2 quit the home and is not a family member. |
| s28 | user1 re-added the device; user2 quit and is not a family member. |
| s29 | user1 removed and re-added the device; user2 remains a family member with control. |
| s30 | user1 has one device; user2 is a family member actively controlling it. |
| s31 | user1 has one device; user2 quit home and is no longer a family member. |
| s32 | user1 removed and re-added the device; user2 remains a family member with control rights. |

