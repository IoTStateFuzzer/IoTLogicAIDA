# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0 | Initial state: user1 has not added the device; user2 is not invited. |
| 1 | user1 added the device once; user2 is not invited. |
| 2 | Error state. |
| 3 | user1 added the device once; user2 is invited but not accepted. |
| 4 | user1 has not added the device; user2 is invited but not accepted. |
| 5 | user1 added the device once; user2 is invited but not accepted. |
| 6 | user1 added the device once; user2 is a family member with control permissions. |
| 7 | user1 added the device once; user2 is a family member with control permissions. |
| 8 | user1 has not added the device; user2 is a family member (with control rights for any future devices). |
| 9 | user1 has not added the device; user2 is a family member (with control rights for any future devices). |
| 10 | user1 has not added the device; user2 is invited but not accepted. |
| 11 | user1 added the device once; user2 is not a family member (having quit) and has no permissions. |
| 12 | user1 has not added the device; user2 is not a family member (having quit) and has no permissions. |
| 13 | user1 has not added the device; user2 is invited but not accepted. |
| 14 | user1 added the device once; user2 is invited but not accepted. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0 | Initial state: Device not added; user2 not invited and without permissions. |
| 1 | Device added once and present; user2 not invited and without permissions. |
| 2 | Error state. |
| 3 | Device not added; user2 invited to family (pending acceptance) without permissions. |
| 4 | Device not added; user2 invited to family (pending acceptance) without permissions. |
| 5 | Device not added; user2 is a family member with control permissions. |
| 6 | Device not added; user2 is a family member with control permissions. |
| 7 | Device added once and present; user2 is a family member with control permissions. |
| 8 | Device added once and present; user2 is a family member with control permissions. |
| 9 | Device not added; user2 quit family without permissions. |
| 10 | Device added once and present; user2 invited to family (pending acceptance) without permissions. |
| 11 | Device added once and present; user2 invited to family (pending acceptance) without permissions. |
| 12 | Device added once and present; user2 quit family without permissions. |
| 13 | Device added once and present; user2 invited to family (pending acceptance) without permissions. |
| 14 | Device not added; user2 invited to family (pending acceptance) without permissions. |
| 15 | Device added once and present; user2 is a family member with control permissions. |
| 16 | Device added once and removed; user2 is a family member with control permissions. |
| 17 | Device added once and removed; user2 quit family without permissions. |
| 18 | Device added twice and present; user2 quit family without permissions. |
| 19 | Device added once and present; user2 quit family without permissions. |
| 20 | Device added once and present; user2 not invited and without permissions. |
| 21 | Device added twice and present; user2 not invited and without permissions. |
| 22 | Device added once and removed; user2 not invited and without permissions. |
| 23 | Device added once and removed; user2 invited to family (pending acceptance) without permissions. |
| 24 | Device added twice and present; user2 invited to family (pending acceptance) without permissions. |
| 25 | Device added once and present; user2 invited to family (pending acceptance) without permissions. |
| 26 | Device added once and removed; user2 is a family member with control permissions. |
| 27 | Device added once and removed; user2 quit family without permissions. |
| 28 | Device added twice and present; user2 quit family without permissions. |
| 29 | Device added twice and present; user2 is a family member with control permissions. |
| 30 | Device added once and present; user2 is a family member with control permissions. |
| 31 | Device added once and present; user2 quit family without permissions. |
| 32 | Device added twice and present; user2 is a family member with control permissions. |

