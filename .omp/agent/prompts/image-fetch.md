---
description: Download an image from a URL (e.g. Imgur) to /tmp and display it. Workaround for WebFetch blocking image hosts.
---

# image-fetch

Download an image from a URL to `/tmp` so it can be viewed with the Read tool. Useful when WebFetch blocks the host (Imgur, etc.).

## Required input

- **url** (string): the image URL. Can be a direct image link or an Imgur album/page URL.

## Steps

1. **Resolve the URL.** If the URL is an Imgur album/page (e.g. `imgur.com/a/XXX` or `imgur.com/XXX`), convert it to a direct image link by appending `.png` to the image ID, or use `curl -sI` to follow redirects and find the actual image URL. For `imgur.com/a/<id>`, fetch the page HTML with `curl -s` and extract the first `og:image` meta tag URL.
2. **Download.** `curl -sL -o /tmp/fetched_image.<ext> "<resolved_url>"`. Use `-L` to follow redirects. Infer the extension from the URL or Content-Type header. Default to `.png` if unclear.
3. **Verify.** `file /tmp/fetched_image.<ext>` to confirm it's actually an image and not an HTML error page.
4. **Display.** Use the Read tool to open `/tmp/fetched_image.<ext>` — the Read tool renders images natively.
5. **Clean up context.** After viewing, summarize what the image shows and proceed with whatever task the user needs.

## Tips

- If `file` says it's HTML, the download likely got a landing page instead of the image. Try extracting the direct image URL from the HTML.
- Imgur album URLs (`/a/XXX`) may contain multiple images. Fetch the first one unless the user specifies otherwise.
- For non-Imgur URLs, `curl -sL` usually works directly.
