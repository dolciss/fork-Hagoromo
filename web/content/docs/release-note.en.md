---
title: Release note
weight: 9999
description: This is a multi-column Bluesky client.
---

# Release note

## 2024

### v0.30.0 - 2024/5/11

- Add
  - Add log reference function
- Update
  - Adjust link card layout
- Fix
  - Fix a bug that caused a post to be mistakenly displayed as a pinned post when the post was pinned in someone else's profile
  - Corrected layout of content filter dialog
  - Improved processing of reading link card information(OGP)

### v0.29.0 - 2024/5/2

- Add
  - Supports login with MFA (deprecated)
  - Display PDS belonging to user's profile
  - Display pinned a post in user's profile
- Fix
  - Fix display layout of handles, etc

### v0.28.0 - 2024/4/20

- Add
  - Support for aggregate display of notifications
  - Add per-column setting for whether notifications are displayed in the aggregate
  - Support for sequential posts with 4 or more images attached
  - Add progress indicator to post dialog
- Update
  - Adjusted post dialog layout

### v0.27.0 - 2024/4/6

- Add
  - Mute and Block Lists
  - Listing of muted and blocked lists
- Update
  - Content filter settings to support the new label system
  - Support switching from post URL to quote in post dialog
  - Change to allow reposting, etc. even while columns are loading

### v0.26.0 - 2024/3/21

- Add
  - Support muted word
  - Add list of blocked and muted accounts
- Update
  - Remove self-labels that should not be set from the selection candidates when posting
  - Internal updates to maintain compatibility with the new label system
  - Added aspect ratio to attached images
- Fix
  - Fixed a situation where the tab button in the profile was sticking out.

### v0.25.0 - 2024/3/2

- Add
  - Function to hide reposts (the following can be set individually)
    - Reposts of your posts
    - Reposts by you
  - Move columns with the cursor keys
- Update
  - Change to allow selection of search method when clicking on a hashtag
  - Change to add # when searching for hashtags
- Fix
  - Fix a bug that caused display corruption with unexpected facets

### v0.24.0 - 2024/2/23

- Add
  - Support for "from:me" in post search
  - Function to change reply limits later
  - Function to hide reposts (the following can be set individually)
    - Reposts by the user
    - Reposts of users followed
    - Reposts of users you do not follow
- Fix
  - Fixed a bug in reply restrictions that prevented the selection of combinations of mentions, etc.

### v0.23.0 - 2024/2/17

- Add
  - Function to adjust scroll velocity
  - Support for the list card (post and display)
- Update
  - Change the image layout to be able to choose from four different layouts
- Fix
  - Failure to play animated GIFs of a PDS different from the account
  - Failure to create a card when a handle was used in the feed URL

### v0.22.1 - 2024/2/14

- Update
  - Target item also displays busy indicator when adding/deleting listings
- Fix
  - Fixed a bug that caused the reply limit setting to be empty when adding a new account

### v0.22.0 - 2024/2/12

- Add
  - Display of registered lists in the profile view
  - Function to cache list entries
    - Display of loading and progress at the bottom right of the window at startup
  - Faster loading of the Add/Remove Lists dialog
  - Reload button in add/delete list dialog
  - Display account loading on startup at the bottom right corner of the window
  - Function to copy the official URL into the profile menu
- Update
  - Move the account icon in the post dialog into the combo box

### v0.21.0 - 2024/2/1

- Add
  - Post display and posting support for posts containing quotes and link cards
- Update
  - Changed to be able to close the display of Mention Candidates with Esc
- Fix
  - Support for posts that cannot be displayed in notifications
  - Fixed layout of settings dialog

### v0.20.0 - 2024/1/15

- Add
  - Add indication of character limit (list name, Alt text)
  - Adjust link card title and description with character limit
  - Display of candidate users to be mentions
  - Display of Likes on feeds in notifications
  - Support for multi-line layouts
- Update
  - Support for read notifications (can be turned on/off in settings)
  - Limit replies to 5 selectable replies.

## 2023

### v0.19.0 - 2023/12/31

- Add
  - Setting to hide the version information in the main window
  - Function to switch how posts are displayed when updating feed (one at a time or all at once)
  - Function to copy the official URL of a post
  - Function to save space in the profile
- Fix
  - Character encoding judgment when retrieving OGP

### v0.18.0 - 2023/12/24

- Add
  - Support for Reply Limitations
- Update
  - Update not to display `!no-unauthenticated` label in profile
- Fix
  - Fix to be able to create link cards with Youtube sharing URLs
  - Fixed to be able to create lists without icon images

### v0.17.0 - 2023/12/4

- Add
  - Function to update your profile
  - Function to update information in the listings

### v0.16.0 - 2023/11/25

- Add
  - Support for animated GIFs
- Update
  - Change search API to official one
- Fix
  - Bug in content filter settings Show was not reflected correctly
  - Bug in the registration process to the list

### v0.15.0 - 2023/11/11

- Add
  - Add font selection function
- Update
  - Change default font
  - Change to be able to add itself to the list
- Fix
  - Fix column cursor position
  - Fix the content of the message when an error occurs
  - Fix clipping process of icons to be registered in the list
  - Fix scrolling when post dialog is about to overflow

### v0.14.1 - 2023/11/2

- Fix
  - Fix clip process for avatar image in list

### v0.14.0 - 2023/11/1

- Add
  - Support for curation lists
  - Ability to display only the reps to users you follow.
- Update
  - Change display position when adding columns
- Fix
  - Fix to handle correctly when a slash is specified at the end of the URL of a service
  - Fix error log

### v0.13.0 - 2023/10/8

- Add
  - Display and post hashtags (in text)
  - Display post tags (post thread only)
- Update
  - Update to also show behind the base post in post threads
  - Display lines between posts in post threads
- Fix
  - Fixed a bug that may cause image sending to fail
  - Fixed error in profile feed list

### v0.12.0 - 2023/9/18

- Add
  - Add feed list to profile
  - Add labels set for accounts in follow list, etc.
  - Add support for "Open in Official", "Save", and "Drop" custom feeds in columns
  - Add ability to notify of communication related errors
- Update
  - Update authentication process at startup
  - Change list refresh to manual in add column dialog
- Fix
  - Fix handling of HTML escaping characters in post body
  - Fix failure to add root information when replying in notification and post threads
  - Fix OGP processing

### v0.11.0 - 2023/9/9

- Add
  - Continue loading support
  - ALT text support (display, post)
  - Post Likes and Reposted Account Listing support
  - Supports feed card post
- Update
  - Improved link card parsing process

### v0.10.0 - 2023/8/27

- Add
  - Add app icons (except for Linux version)
  - Add information on post thread based on post (label, language, date/time, via)
  - Add indication of whether a user is on mute in user information such as follow list
  - Add the ability to set the main target from multiple accounts
- Update
  - Change to display all posts at once when the column is empty
  - Change tab button in profile to an icon
  - Change moderation-related menu items in own profile to not selectable
  - Change font size adjustment to scale function for entire layout
- Fix
  - Fix disabled language and label buttons during post processing
  - Fix layout of columns when viewing post threads, etc.
  - Fix mode when searching again after user search
  - Fix unavailability of search button for custom feeds

### v0.9.0 - 2023/8/16

- Add
  - Function to add self-labeling to post
  - Display images within the quote
  - Warns when the post being quoted is muted or labeled
  - Support for labels that hide the entire content of the post and warn
- Fix
  - Fix to remove Exif when attaching image files less than 1Mbyte

### v0.8.0 - 2023/8/12

- Add
  - Support for content filters
    - Display posts according to labels
    - Display labels on profiles
    - Add per-label display settings
  - Added media tab to profile
- Fix
  - Changed so that posts cannot be posted when the post content exceeds 300 characters

### v0.7.0 - 2023/7/23

- Add
  - Shortcut to display the corresponding column by pressing a number key
  - Shortcut to display the leftmost and rightmost columns by pressing Ctrl+Left, Ctrl+Right
  - Posting quotations with images
  - Display quotations with images
- Fix
  - Fixes cases where post dialog layout is broken

### v0.6.0 - 2023/7/18

- Add
  - Display user's feed in a new column from profile
  - Display profile by clicking on icon in column header
  - Display URLs in profiles as hyperlinks
  - Collapsed display of muted user's posts
  - Display feed cards in post
  - Function to post link cards
  - Language settings when posting
  - Delete a post
  - Mute, block and report a user
  - Report a post
  - Display mute and block status on profile
  - Adjust scroll position when added column is off screen
- Fix
  - Fixed a bug where URLs could not include anchor links in the determination of URLs.

### v0.5.0 - 2023/7/2

- Add
  - Function to select to show/hide by type in notification column settings
  - Add "via" to post
- Fix
  - Fixed sort order for custom feeds in list of types in add column dialog
  - Fixed bug where token refresh was not propagated to columns properly

### v0.4.1 - 2023/6/25

- Fix
  - Fixed that the reply button did not work.

### v0.4.0 - 2023/6/25

- Add
  - Function to open in official
  - Function to copy post to clipboard
  - Function to adjust font size (post body only)
- Change
  - Optimization of column swapping process
- Fixe
  - Fixed a bug that the selection target is not displayed in the add column dialog immediately after adding an account
  - Forgot to add GUI translation data (Japanese)

### v0.3.0 - 2023/6/18

- Add
  - Custom feed support
  - Japanese translation data
- Fix
  - Display URL on link card hover in post thread

### v0.2.0 - 2023/6/11

- Add
  - Search function (post and user)
  - Mention function in post (implemented in `@handle`)
  - Mentioned handle in post to be a link
  - Display mentions in notifications
  - Display the URL that actually opens when you hover over the URL in the lower left corner of the window
- Change
  - Open Google Translate when the API key of DeepL is not set in the translation settings
  - Show more threads in post threads when clicking on a post other than the one that is the basis of the post.
- Fix
  - Retrieve icon and other information when adding an account

### v0.1.0 - 2023/6/2

- This is a trial release.
