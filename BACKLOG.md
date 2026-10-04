# PulseCheck backlog

Use this format for new entries:
- Menu function: <menu or route>
- Required future change: <description>
- Status: pending


## Current backlog

- Menu function: Import page
- Required future change: Add a blocking overlay while importing with an option to cancel the import.
- Status: completed


- Menu function: Import page
- Required future change: Show progress per service name, including entry x of n being imported and the port currently being tested for each service.
- Status: completed


- Menu function: Import page
- Required future change: Skip service names that are already in the database and continue importing the remaining entries without duplicating records.
- Status: completed


- Menu function: Import page
- Required future change: If a service is already in the database, do not rescan its ports during import.
- Status: completed


- Menu function: Services page
- Required future change: Add bulk port editing for pre-selected services using checkboxes, including adding or removing ports in one action.
- Status: completed


- Menu function: Services page
- Required future change: Show a confirmation prompt before deleting a service entry.
- Status: completed


- Menu function: Status page
- Required future change: Use a grid layout to shorten the page, place ports next to each other, and add a hover tooltip showing the last successful scan and response time.
- Status: completed


- Menu function: Settings page
- Required future change: Capture and maintain e-mail SMTP settings and a destination e-mail address to be used later in the system to send notifications.
- Status: completed


- Menu function: Background scanner
- Required future change: Send an e-mail notification after check_all_services completes with a list of all services whose state changed since the previous scan.
- Status: completed


- Menu function: Import page
- Required future change: Add CSV file export and import of services with Service, Match, URL path, Paused, and Ports, showing stats and skipping existing services.
- Status: completed


- Menu function: Notifications / Email
- Required future change: Improve the notification email body:
  - Resize the logo/header image (currently too large).
  - Color-code the status next to the service name (RED = OFFLINE, ORANGE = DEGRADED, GREEN = ONLINE).
- Status: completed


- Menu function: Web UI & Email notifications
- Required future change: Introduce and display an application version number:
  - On the webpage near the application name.
  - In the email body near the application name.
- Status: completed


- Menu function: Edit Service page
- Required future change: Add a live "Test" button on the service edit screen:
  - Test the probe calls to configured ports and display per-port diagnostics:
    - Resulting text response snippet or error code.
    - Highlight matching token in the response text if match succeeds.
    - Duration of the call, retry count, and timestamp.
    - Color-coded indicators for success or failure.
  - Redesign layout into two columns, utilizing the right-hand side of the edit card with tabs per port to avoid excessively wide input fields.
- Status: completed


- Menu function: Add Service page
- Required future change: Upgrade Add New Service to work like the Edit Service function:
  - Dedicated full-screen capture page utilizing the responsive 2-column layout.
  - Pre-fill ports with sensible defaults (`80, 443`) and allow testing probe connections live before saving.
  - Maximize code reuse by sharing form and diagnostic tab components with Edit Service.
  - Return to Services list with a confirmation flash message upon successful addition.
- Status: completed


- Menu function: Status page
- Required future change: Add header metadata on the Status screen right-aligned on the same line as the title [Service Status]:
  - Time of last scheduled check in local timezone format.
  - Overall status indicator in the respective color (GREEN = ALL ONLINE, ORANGE = SOME DEGRADED, OFFLINE = SOME OFFLINE services), ignoring services without ports listed.
  - Countdown to the next scheduled service check, updating the countdown every second.
  - Automatically refresh the status screen when the next scheduled run completes and the database is updated.
- Status: completed


- Menu function: Status page
- Required future change: Colorize the filter pills and counters for All, Online, Degraded, and Offline:
  - Respective dark outline color and two distinct shades of the color filling the name and count badge:
    - BLUE = ALL
    - GREEN = ONLINE
    - ORANGE = DEGRADED
    - RED = OFFLINE
- Status: completed


- Menu function: Services / Port Configuration
- Required future change: Allow each port to have its own protocol instead of treating all ports on a service to use the same protocol.
- Status: completed


- Menu function: Services
- Required future change:
  1. When deleting a port from selected services, preserve the protocols of the remaining ports on that service.
  2. When adding a new port, auto‑detect and assign the appropriate protocol.
- Status: completed


- Menu function: Import & Export
- Required future change:
  1. **Import CSV** – improve the “Supported Columns” example to reflect that protocols are now per‑port and ICMP has no port number.
  2. **Export CSV** – improve the export structure & preview example to show per‑port protocols and the ICMP case.
- Status: completed


- Menu function: Notifications / Email
- Required future change:
  - Color‑code port details in notification emails:
    - **Red** – offline / error
    - **Orange** – degraded / intermittent
    - **Green** – online / healthy
  - Treat ICMP entries (no port) as either red or green.
- Status: completed


- Menu function: not applicable – under‑hood change
- Required future change:
  - Remove the database migration code that was added when the `port_checks` and `services` tables were changed.
- Status: completed


- Menu function: import, export, services, status screens
- Required future change:
  1. Store a **match** string and **URL path** for each `port_protocol` (ASCII or hex).
  2. For each port‑protocol, default to the existing **match** string & **URL path** values when migrating to individual (**match** string and **URL path**).
  3. Allow capturing a **match** string and **URL path** for each `port_protocol` during service **add** and **edit**.
  4. Use the stored **match** string and **URL path** for each port_protocol in port diagnostics per port‑protocol.
  5. Remove the shared `[match]` and `[url path]` columns from the database.
  6. Update the Status and Services lists: remove the Match and URL Path columns.
     - The [match] and [url path] value per port:protocol must be added to the hover of the PORTS column.
     - On the status screen remove the MATCH column
     - On the status screen add to the STATUS hover the [url path] and [match] value per port:protocol.

  - Ask questions if there things that needs to be clarified and/or decisions to be taken?
    
- Status: completed

- Menu function: Impacts the entire system, from add/edit service and status screens
- Required future change:
1) Per [port_protocol] a [request] string which can be either ascii string or hex type string with multi line support.
2) It must be captured and stored during the add and edit of a services before the [match] value per port:protocol.
3) Must be used during port diagnostics per port:protocol.
4) Remove the shared hard coded HTML get.
5) Defaults to the current hard coded implementation for HTTP GET per port:protocol.
6) Do not add the [request] value to the Status and Services list screens
- Status: pending

OpenWrt/Linux SSH integration for list of DNS/Services
- Status: pending

Predefined [request] defintions to be selected from when adding or editing a service
- Status: pending
