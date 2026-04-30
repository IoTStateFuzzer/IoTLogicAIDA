# Base Model
| State | Semantic Description |
|-------|----------------------|
| S0    | Initial state. |
| S1    | Error state. |
| S2    | user1 added the device; user2 has no permissions. |
| S3    | user1 added the device and invited user2 to home; user2 has not accepted yet. |
| S4    | user1 invited user2 to home; no device added yet. |
| S5    | user1 added the device and invited user2 to home; user2 scanned QR code but has not accepted yet. |
| S6    | user1 added the device and invited user2 to home; user2 accepted and is now a family member with control permissions. |
| S7    | user1 added the device and invited user2 to home twice; user2 accepted the second invitation and is now a family member. |
| S8    | user1 invited user2 to home; user2 accepted and is now a family member with control permissions; no device added yet. |
| S9    | user1 invited user2 to home twice; user2 accepted the second invitation and is now a family member; no device added yet. |
| S10   | user1 invited user2 to home; user2 scanned QR code but has not accepted yet; no device added. |
| S11   | user1 invited user2 to home twice; user2 accepted the second invitation; user1 later removed user2 from home. |
| S12   | user1 invited user2 to home twice; user2 accepted the second invitation; user1 removed and re-added the device; user2 retains family permissions. |
| S13   | user1 added the device and invited user2 to home twice; user2 accepted the second invitation; user1 later removed user2 from home. |
| S14   | user1 added the device and invited user2 to home; user2 accepted and was later removed from home by user1. |
| S15   | user1 added the device and invited user2 to home; user2 accepted; user1 removed user2 from home and then removed the device. |
| S16   | user1 invited user2 to home; user2 accepted and was later removed from home by user1. |
| S17   | user1 invited user2 to home twice; user2 accepted the second invitation; user1 removed user2, re-added the device, and user2 scanned QR code again. |
| S18   | user1 added the device and invited user2 to home twice; user2 accepted the second invitation; user1 removed user2, and user2 scanned QR code again. |
| S19   | user1 invited user2 to home twice; user2 accepted the second invitation; user1 removed user2, and user2 scanned QR code again. |
| S20   | user1 added the device and invited user2 to home; user2 accepted and later quit the home. |
| S21   | user1 added the device and invited user2 to home; user2 accepted; user1 removed user2 and the device, then re-added the device. |
| S22   | user1 added the device and invited user2 to home twice; user2 accepted the second invitation; user1 removed user2 and the device, then re-added the device. |
| S23   | user1 added the device and invited user2 to home twice; user2 accepted the second invitation; user1 removed user2 and the device, re-added the device, and user2 scanned QR code again. |
| S24   | user1 invited user2 to home; user2 accepted; user1 removed user2 and later added the device. |
| S25   | user1 invited user2 to home; user2 accepted and later quit the home. |
| S26   | user1 added the device and invited user2 to home twice; user2 accepted the second invitation; user1 removed user2 and the device. |
| S27   | user1 added the device and invited user2 to home twice; user2 accepted the second invitation; user1 removed user2 and the device, and user2 scanned QR code again. |
| S28   | user1 invited user2 to home twice; user2 accepted the second invitation; user1 removed user2, re-added the device, and invited user2 again. |
| S29   | user1 invited user2 to home twice; user2 accepted the second invitation; user1 removed user2 and invited again. |
| S30   | user1 added the device and invited user2 to home twice; user2 accepted the second invitation; user1 removed user2 and invited again. |
| S31   | user1 added the device and invited user2 to home twice; user2 accepted the second invitation; user1 removed user2 and the device, then invited again. |
| S32   | user1 added the device and invited user2 to home twice; user2 accepted the second invitation; user1 removed user2 and the device, re-added the device, and invited again. |
| S33   | user1 invited user2 to home twice; user2 has not accepted yet. |
| S34   | user1 added the device and invited user2 to home twice; user2 has not accepted yet. |

