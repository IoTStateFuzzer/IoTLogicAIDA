# Base Model
| State | Semantic Description |
|-------|----------------------|
| S0    | Initial state. |
| S1    | Error state. |
| S2    | user1 added the device; user2 has no permissions. |
| S3    | user1 added the device and invited user2 to home; user2 has not scanned QR code yet. |
| S4    | user1 invited user2 to home; user2 has not scanned QR code yet. |
| S5    | user1 added the device and invited user2 to home; user2 scanned QR code but has not accepted invitation yet. |
| S6    | user1 added the device and invited user2 to home; user2 accepted invitation and is now a family member with control permissions. |
| S7    | user1 added the device and invited user2 to home twice; user2 accepted second invitation and is now a family member with control permissions. |
| S8    | user1 invited user2 to home; user2 accepted invitation and is now a family member with control permissions. |
| S9    | user1 invited user2 to home twice; user2 accepted second invitation and is now a family member with control permissions. |
| S10   | user1 invited user2 to home; user2 scanned QR code but has not accepted invitation yet. |
| S11   | user1 invited user2 to home twice; user2 accepted second invitation and was later removed from home by user1. |
| S12   | user1 invited user2 to home twice; user2 accepted second invitation, was removed from home, and user1 re-added the device. |
| S13   | user1 added the device and invited user2 to home twice; user2 accepted second invitation and was later removed from home by user1. |
| S14   | user1 added the device and invited user2 to home; user2 accepted invitation and was later removed from home by user1. |
| S15   | user1 added the device and invited user2 to home; user2 accepted invitation, was removed from home, and user1 removed the device. |
| S16   | user1 invited user2 to home; user2 accepted invitation and was later removed from home by user1. |
| S17   | user1 invited user2 to home twice; user2 accepted second invitation, was removed from home, user1 re-added the device, and user2 scanned QR code again. |
| S18   | user1 added the device and invited user2 to home twice; user2 accepted second invitation, was removed from home, and scanned QR code again. |
| S19   | user1 invited user2 to home twice; user2 accepted second invitation, was removed from home, and scanned QR code again. |
| S20   | user1 added the device and invited user2 to home; user2 accepted invitation and later quit home. |
| S21   | user1 added the device and invited user2 to home; user2 accepted invitation, was removed from home, user1 removed and re-added the device. |
| S22   | user1 added the device and invited user2 to home twice; user2 accepted second invitation, was removed from home, user1 removed and re-added the device. |
| S23   | user1 added the device and invited user2 to home twice; user2 accepted second invitation, was removed from home, user1 removed and re-added the device, and user2 scanned QR code again. |
| S24   | user1 invited user2 to home; user2 accepted invitation, was removed from home, and user1 re-added the device. |
| S25   | user1 invited user2 to home; user2 accepted invitation and later quit home. |
| S26   | user1 added the device and invited user2 to home twice; user2 accepted second invitation, was removed from home, and user1 removed the device. |
| S27   | user1 added the device and invited user2 to home twice; user2 accepted second invitation, was removed from home, user1 removed the device, and user2 scanned QR code again. |
| S28   | user1 invited user2 to home twice; user2 accepted second invitation, was removed from home, user1 re-added the device, user2 scanned QR code, and user1 invited again. |
| S29   | user1 invited user2 to home twice; user2 accepted second invitation, was removed from home, scanned QR code, and user1 invited again. |
| S30   | user1 added the device and invited user2 to home twice; user2 accepted second invitation, was removed from home, scanned QR code, and user1 invited again. |
| S31   | user1 added the device and invited user2 to home twice; user2 accepted second invitation, was removed from home, user1 removed the device, user2 scanned QR code, and user1 invited again. |
| S32   | user1 added the device and invited user2 to home twice; user2 accepted second invitation, was removed from home, user1 removed and re-added the device, user2 scanned QR code, and user1 invited again. |
| S33   | user1 invited user2 to home twice; user2 has not scanned QR code yet. |
| S34   | user1 added the device and invited user2 to home twice; user2 has not scanned QR code yet. |

