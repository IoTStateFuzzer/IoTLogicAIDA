# Base Model
| State | Semantic Description |
|-------|----------------------|
| S0    | Initial state. |
| S1    | Error state. |
| S2    | user1 added the device; user2 has no permissions. |
| S3    | user1 added the device and invited user2 to home; user2 has not accepted yet. |
| S4    | user1 invited user2 to home; user2 has not accepted yet. |
| S5    | user1 added the device and invited user2 to home; user2 scanned QR code but has not accepted yet. |
| S6    | user1 added the device and invited user2 to home; user2 accepted the invite and is now a family member with control permissions. |
| S7    | user1 added the device and invited user2 to home twice; user2 accepted the second invite and is now a family member with control permissions. |
| S8    | user1 invited user2 to home; user2 accepted the invite and is now a family member with control permissions. |
| S9    | user1 invited user2 to home twice; user2 accepted the second invite and is now a family member with control permissions. |
| S10   | user1 invited user2 to home; user2 scanned QR code but has not accepted yet. |
| S11   | user1 invited user2 to home twice; user2 accepted the second invite and was later removed from home by user1. |
| S12   | user1 invited user2 to home twice; user2 accepted the second invite, was removed from home, and user1 re-added the device. |
| S13   | user1 added the device and invited user2 to home twice; user2 accepted the second invite and was later removed from home by user1. |
| S14   | user1 added the device and invited user2 to home; user2 accepted the invite and was later removed from home by user1. |
| S15   | user1 added the device and invited user2 to home; user2 accepted the invite, was removed from home, and user1 removed the device. |
| S16   | user1 invited user2 to home; user2 accepted the invite and was later removed from home by user1. |
| S17   | user1 invited user2 to home twice; user2 accepted the second invite, was removed from home, user1 re-added the device, and user2 scanned QR code. |
| S18   | user1 added the device and invited user2 to home twice; user2 accepted the second invite, was removed from home, and user2 scanned QR code again. |
| S19   | user1 invited user2 to home twice; user2 accepted the second invite, was removed from home, and user2 scanned QR code again. |
| S20   | user1 added the device and invited user2 to home; user2 accepted the invite and later quit the home. |
| S21   | user1 added the device and invited user2 to home; user2 accepted the invite, was removed from home, user1 removed and re-added the device. |
| S22   | user1 added the device and invited user2 to home twice; user2 accepted the second invite, was removed from home, user1 removed and re-added the device. |
| S23   | user1 added the device and invited user2 to home twice; user2 accepted the second invite, was removed from home, user1 removed and re-added the device, and user2 scanned QR code. |
| S24   | user1 invited user2 to home; user2 accepted the invite, was removed from home, and user1 re-added the device. |
| S25   | user1 invited user2 to home; user2 accepted the invite and later quit the home. |
| S26   | user1 added the device and invited user2 to home twice; user2 accepted the second invite, was removed from home, and user1 removed the device. |
| S27   | user1 added the device and invited user2 to home twice; user2 accepted the second invite, was removed from home, user1 removed the device, and user2 scanned QR code. |
| S28   | user1 invited user2 to home twice; user2 accepted the second invite, was removed from home, user1 re-added the device, user2 scanned QR code, and user1 invited again. |
| S29   | user1 invited user2 to home twice; user2 accepted the second invite, was removed from home, user2 scanned QR code, and user1 invited again. |
| S30   | user1 added the device and invited user2 to home twice; user2 accepted the second invite, was removed from home, user2 scanned QR code, and user1 invited again. |
| S31   | user1 added the device and invited user2 to home twice; user2 accepted the second invite, was removed from home, user1 removed the device, user2 scanned QR code, and user1 invited again. |
| S32   | user1 added the device and invited user2 to home twice; user2 accepted the second invite, was removed from home, user1 removed and re-added the device, user2 scanned QR code, and user1 invited again. |
| S33   | user1 invited user2 to home twice; user2 has not accepted yet. |
| S34   | user1 added the device and invited user2 to home twice; user2 has not accepted yet. |

