---
description: Create a new blog post on blog.carter2099.com. Collaboratively draft and polish markdown content, preview it, then publish — triggering subscriber email notifications via the Rails app.
---

# blog-post

Create a new blog post on the blog. This is a collaborative workflow — help the user draft and polish their content before publishing. **Never publish without showing the user exactly what will be posted and getting explicit confirmation.**

## Required input

- **title** (string): the post title
- **content** (string): markdown body — may be provided as a rough draft, bullet points, stream of consciousness, or polished text

## Optional input

- **image_urls** (list of URLs): images to download and embed in the post

## Workflow

### 1. Draft and polish

The user may provide anything from a finished post to rough notes. Work with them to shape it:

- If the content is rough/draft-quality, help polish it while preserving their voice
- If they ask for edits, make them and show the result
- Go back and forth as many times as needed

### 2. Preview — MANDATORY before publishing

When the content feels ready, display the **exact markdown** that will be written to disk, formatted like this:

```
**Title:** <title>

**Filename:** <Title-With-Hyphens>.md

---

<full markdown content exactly as it will be written to the file>

---

**Images:** <list of images that will be downloaded, or "None">
```

Ask: "Ready to publish? This will notify all subscribers via email."

**Do not proceed without explicit confirmation** (e.g. "yes", "publish it", "send it", "go ahead"). If the user wants changes, make them and show the preview again.

### 3. Publish

Once confirmed, execute these steps in order:

#### 3a. Download images (if any)

For each image URL:

```bash
curl -fSL "<url>" -o /home/carter/blog/blog/app/assets/images/<filename>
```

Then copy all images to public:

```bash
docker exec blog-web-1 bin/rails runner "PostsHelper.load_post_images"
```

#### 3b. Write the markdown file

Write the markdown content to `/home/carter/blog/blog/app/posts/<Title-With-Hyphens>.md`.

- Replace spaces in filename with hyphens
- Convert any Obsidian image syntax `![[file.jpg]]` to `![file.jpg](/assets/file.jpg)`
- Image references in markdown should use the format `![alt text](/assets/filename.jpg)`

#### 3c. Create the database record

```bash
docker exec blog-web-1 bin/rails runner "Post.create!(title: '<title>', path: '/rails/app/posts/<Title-With-Hyphens>.md')"
```

This triggers `after_create_commit :notify_subscribers` which enqueues `NotifySubscribersJob` → sends emails to all confirmed subscribers via `SubscriberMailer`.

#### 3d. Verify

```bash
docker exec blog-web-1 bin/rails runner "p = Post.last; puts \"Created: #{p.title} (id: #{p.id})\"; puts \"Subscribers notified: #{Subscriber.confirmed.count}\""
```

Report the post ID, URL (`https://blog.carter2099.com/posts/<id>`), and number of subscribers who will be notified.

## Important notes

- The blog container is `blog-web-1`. If it's not running, tell the user — don't try to start it (use `/deploy-app blog` for that).
- The path stored in the database must be the **container path** (`/rails/app/posts/...`), not the host path.
- Escape single quotes in title and content when passing to `rails runner` (use heredoc syntax for content if needed).
- Posts have no frontmatter — just plain markdown content.
- If `rails runner` fails, the file has already been written but no DB record or emails were sent. Clean up the file and report the error.

## Markdown formatting rules

The blog uses Redcarpet with `hard_wrap: true`, which changes how the parser handles certain constructs. Follow these rules when writing markdown content:

- **Blank line before lists.** A list must have a blank line separating it from the preceding paragraph — otherwise Redcarpet won't parse it as `<ul>`/`<li>` and will instead render it as literal text with `<br>` line breaks.
  ```markdown
  ❌ Some intro text:
  - first item
  ✅ Some intro text:

  - first item
  ```
- **Blank line before headings** (`##`, `###`, etc.) — same rule as lists.
- **Spaces, not tabs, for nested list indentation.** Use 4 spaces for each nesting level. Tabs cause Redcarpet to treat the indented content as a code block.
- **Inline backtick code** (`` `code` ``) renders with a subtle background only (it's now `display: inline` as of 2025-06-19). Fenced code blocks (` ``` `) are for block-level code.
