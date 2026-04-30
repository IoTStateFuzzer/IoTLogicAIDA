# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. No device is added; user2 is not invited. |
| 1     | user1 has added the device once; user2 is not invited and has no control. |
| 2     | Error state. |
| 3     | user1 has added the device once; user2 is invited to family but has not accepted. |
| 4     | No device is added; user2 is invited to family but has not accepted. |
| 5     | user1 has added the device once; user2 has scanned the invitation code but has not completed acceptance. |
| 6     | user1 has added the device once; user2 accepted the family invitation and now has permanent control. |
| 7     | user1 has added the device once; user2 accepted the family invitation (after multiple invites) and now has permanent control. |
| 8     | No device is added; user2 is a family member with permanent control over any future devices. |
| 9     | No device is added; user2 became a family member (after multiple invites) with permanent control for any future devices. |
| 10    | No device is added; user2 scanned the family invitation code but has not accepted. |
| 11    | user1 has added the device once; user2 was a family member but quit and no longer has any control. |
| 12    | No device is added; user2 had joined the family but quit, losing all control rights. |
| 13    | No device is added; user2 has been invited multiple times but has not accepted membership. |
| 14    | user1 has added the device once; user2 was invited multiple times, scanned the code, but has not accepted. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0    | Initial state (no device added and user2 has no membership or invitation). |
| s1    | user1 has added the device once; user2 is not invited. |
| s2    | Error state. |
| s3    | No device added; user2 is invited but has not accepted. |
| s4    | No device added; user2 scanned the invite but has not accepted. |
| s5    | No device added; user2 accepted the family invitation and is now a family member. |
| s6    | No device added; user2 remains a family member (repeated invites). |
| s7    | user1 has one device added; user2 is a family member with control rights. |
| s8    | user1 has one device; user2 is a family member with control rights. |
| s9    | No device added; user2 was a family member but quit and lost membership. |
| s10   | user1 has one device; user2 is invited and may have scanned but has not accepted. |
| s11   | user1 has one device; user2 is invited but has not accepted. |
| s12   | user1 has one device; user2 joined as a family member but then quit. |
| s13   | user1 has one device; user2 scanned at least once but never fully accepted repeated invitations. |
| s14   | No device added; user2 scanned the code multiple times but never accepted. |
| s15   | user1 has one device; user2 is a family member actively controlling it. |
| s16   | user1 removed the device; user2 remains a family member with no active device. |
| s17   | user1 removed the device; user2 quit the family, so no device remains and user2 is not a member. |
| s18   | user1 re-added the device; user2 quit the family, so user2 is not a member. |
| s19   | user1 has one device; user2 was family but quit and lost membership. |
| s20   | user1 has one device; user2 quit membership and has scanned a code but has no valid invitation or membership. |
| s21   | user1 re-added the device; user2 quit membership and scanned again without re-accepting. |
| s22   | No device present; user2 quit membership and scanned again without re-accepting. |
| s23   | No device added; user2 was re-invited after quitting but hasn't accepted. |
| s24   | user1 re-added one device; user2 was re-invited after quitting, but has not accepted. |
| s25   | user1 has one device; user2 quit membership, scanned again, and was re-invited but hasn't accepted. |
| s26   | user1 removed the device; user2 remains a family member with no active device. |
| s27   | No device remains; user2 quit the family and is no longer a member. |
| s28   | user1 re-added the device; user2 quit membership and is not a member. |
| s29   | user1 re-added the device; user2 remains a family member and automatically retains control. |
| s30   | user1 has one device; user2 is a family member with active control. |
| s31   | user1 has one device; user2 was a family member but quit and lost membership. |
| s32   | user1 re-added the device; user2 remains a family member with control rights. |

