# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0  | Initial state. |
| 1  | Error state. |
| 2  | user1 has added 1 device; user2 is not invited, so no membership or control. |
| 3  | user1 has added 1 device; user2 is invited but has not accepted. |
| 4  | No device added; user2 is invited but has not accepted. |
| 5  | user1 has added 1 device; user2 scanned the invitation code but has not accepted. |
| 6  | user1 has 1 device; user2 accepted the invitation and is now a family member with permanent control rights. |
| 7  | user1 has 1 device; user2 is a family member with permanent control rights (despite re-invitation). |
| 8  | No device added; user2 is a family member with permanent control rights (no devices to control). |
| 9  | No device added; user2 is a family member with permanent control rights (multiple invites had no effect). |
| 10 | No device added; user2 scanned the invitation code but has not accepted. |
| 11 | No device added; user2 was a family member but has been removed, so no membership now. |
| 12 | user1 has 1 device; user2 was a family member but membership was revoked, no control. |
| 13 | user1 has 1 device; user2 was removed from the family and no longer has control. |
| 14 | user1 has 1 device; user2 was removed from the family and lacks control. |
| 15 | No device remains; user2 was removed from the family and lacks control. |
| 16 | No device; user2 was removed from the family and lacks control. |
| 17 | user1 has 1 device; user2 was removed from the family, scanning again does not restore membership. |
| 18 | user1 has 1 device; user2 was removed from the family and scanning again does not restore membership. |
| 19 | No device; user2 was removed from the family, scanning again does not restore membership. |
| 20 | user1 has 1 device; user2 became a family member but quit, losing membership. |
| 21 | user1 re-added the device (second addition); user2’s membership was revoked and remains removed. |
| 22 | user1 re-added the device (second addition); user2’s membership was revoked and remains removed. |
| 23 | user1 re-added the device (second addition); user2’s membership remains revoked, scanning again does not restore membership. |
| 24 | user1 has 1 device; user2 was removed from the family and has no membership. |
| 25 | No device; user2 was a family member but quit, losing membership. |
| 26 | No device remains; user2’s membership was revoked. |
| 27 | No device remains; user2’s membership was revoked, scanning again does not restore membership. |
| 28 | user1 has 1 device; user2 was removed from the family, re-invited, but has not accepted. |
| 29 | No device; user2 was removed from the family, re-invited, but has not accepted. |
| 30 | user1 has 1 device; user2 was removed from the family, re-invited, but has not accepted. |
| 31 | No device remains; user2 was removed from the family, re-invited, but has not accepted. |
| 32 | user1 re-added the device (second addition); user2 was removed from the family, newly invited, but has not accepted. |
| 33 | No device; user2 is newly invited but has not accepted. |
| 34 | user1 has 1 device; user2 is newly invited but has not accepted. |

