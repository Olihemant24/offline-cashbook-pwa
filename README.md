# My Cashbook

An offline-first personal cashbook built as an installable Progressive Web App (PWA). It is designed for phone and desktop browsers, stores transactions on the current device first, and can sync them to a Google Sheet when online. The selected ISO 4217 currency is configurable, so the same project can be used in different countries.

## Features

- Record **Money Came In**, **Money Went Out**, and **Remarks** in the selected currency.
- Set a three-letter ISO 4217 currency code supported by the browser (for example NPR, USD, EUR, INR, JPY, or BHD). Amounts use the device's locale and the currency's standard decimal precision.
- Capture the original save date and time, including when the device is offline.
- Keep entries in the browser's IndexedDB storage and show separate income, expense, and balance totals.
- Retry pending uploads when connectivity returns, while the app is open and Google access is valid.
- Avoid duplicate rows on retry with an offline entry ID.
- Cache the app shell so it can open offline after the first online visit.

## Google Sheets connection

The app uses Google Identity Services and Google Picker with the per-file `drive.file` permission. It asks to use only the spreadsheet selected in Picker, instead of requesting access to every spreadsheet. See Google's [Drive scopes guide](https://developers.google.com/workspace/drive/api/guides/api-specific-auth) and [Google Picker guide](https://developers.google.com/workspace/drive/picker/guides/web-picker?hl=en).

Before connecting, configure an HTTPS origin and a Google Cloud project with the Google Sheets API and Google Picker API enabled. Create a web OAuth client, an API key restricted to the app's origin and Picker API, and note the project number. Enter those values in the app's local settings. They are not embedded in this repository.

The starter settings use NPR to match the original cashbook, but the app can be set to another supported currency before the first entry. Change the currency under **Cashbook settings and Google Sheets sync**. After entries exist on a device, the app locks that device to the saved currency to protect its totals; use a separate browser profile or clear the local records only after syncing them to start a different cashbook in another currency.

The app defaults to a response tab named `Form responses 1` and a dashboard tab named `Dashboard`. The response tab needs headers for Timestamp, Money Came In, Money Went Out, and Remarks. If the amount headers include a currency code such as `(USD)`, that code must match the app setting. Keep one currency per sheet so the totals remain meaningful. On first sync, after validating those headers, the app adds an `Offline Entry ID` header to the next empty column and appends cashbook rows there. It reads the starting balance from `Dashboard!B13` in the selected currency; if that cell is blank, the balance starts at zero. It does not set or change the starting balance.

Google access tokens stay in memory and are not saved on the device. After closing the app, switching devices, or token expiry, connect Google again. If the app was closed when the network returned, queued entries sync when the app is opened and connected again.

## Install and host

Serve the files in this folder from an HTTPS website. A service worker cannot install from a `file://` path. Open the hosted app once while online so it can cache the app shell, then install it from Chrome or another supported browser.

### Publish as a GitHub Pages project

1. Create a public GitHub repository, such as `my-cashbook`.
2. Unzip the source package and upload the contents of `cashbook-pwa` to the repository root, then commit them to the `main` branch.
3. Open **Settings → Pages**. Under **Build and deployment**, choose **Deploy from a branch**, select `main` and `/(root)`, then save.
4. Open the published address shown in the Pages settings once while online. Install it from the browser on each device.

GitHub Pages sites are public. This source package contains no transaction data or Google credentials; keep your cashbook entries and any private keys out of the repository.

Each device has its own local database until it syncs. Clear site data only after all entries have synced, or pending entries on that device may be lost.

## Project files

- `index.html` — cashbook screen
- `app.js` — local storage, totals, Google authorization, and Sheets sync
- `sw.js` — offline app-shell cache
- `manifest.webmanifest` and `icon.svg` — install metadata and app icon
- `styles.css` — responsive phone and desktop layout
