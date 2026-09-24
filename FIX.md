This file has stuff that needs to be fixed:

1. Unlock with Touch ID
The Touch ID authentication mechanism is currently failing to function reliably. Additionally, the user interface lacks intelligent state detection. To resolve this, the app must dynamically check if a valid credential is saved in secure storage; when present, the UI should simplify to display solely a fingerprint icon button with a "Touch to Unlock" prompt, minimizing clutter and streamlining the login experience.
When user changes database, it shows normal login with two buttons unlock, and unlock and save touch id (rethink this)

2. Auto-Type Functionality
The Auto-Type feature fails to execute even though the toggle is enabled in the privacy settings. 

3. Keyboard accessability
Make it keyboard friendly

4. Fix popup menubar close when click outside, like other menubar apps do
