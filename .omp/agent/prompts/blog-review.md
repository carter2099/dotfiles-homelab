---
description: Create a new review on blog.carter2099.com (Book, Movie, Show, Product, or Video Game). Collaboratively draft content, preview it, then publish — triggering subscriber email notifications via the Rails app.
---

# blog-review

Create a new review on the blog. This is a collaborative workflow — help the user draft and polish their review before publishing. **Never publish without showing the user exactly what will be posted and getting explicit confirmation.**

## Required input

- **title** (string): the title of the thing being reviewed
- **review_type** (string): one of `Book`, `Movie`, `Show`, `Product`, `Video Game`
- **rating** (float): 0 to 10 (decimals like 7.5 are fine)

**Rating scale invariant:** The blog stores and displays every rating out of 10. Never normalize a `/10` rating to `/5`. Preserve its numeric value exactly (for example, `7.75/10` must be stored as `7.75` and previewed as `7.75/10`). If the user supplies a rating out of 5, convert it to the equivalent rating out of 10 before previewing.

## Conditionally required

- **author** (string): required if review_type is `Book`

## Optional input

- **content** (string): markdown review body — may be rough draft, notes, or polished text. Reviews can also have no body text (just title + rating).
- **main_image_url** (URL): a primary/cover image for the review
- **image_urls** (list of URLs): additional images to embed in the review body

## Workflow

### 1. Draft and polish

The user may provide anything from a finished review to rough notes, or just a title and rating with no body. Work with them:

- By default, only correct unmistakable spelling, grammar, and punctuation errors. Preserve the user's wording, sentence structure, emphasis, numerals, punctuation style (including spaced hyphens), and voice.
- Before making any stylistic rewrite or changing phrasing, explain the proposed changes and get the user's explicit agreement.
- When presenting corrected content, list every correction made so the user can distinguish mechanical fixes from rewriting.
- If the user explicitly asks for broader polishing, preserve their voice and identify any non-mechanical changes.
- If they want a text-free review (just rating), that's fine — content is optional.
- Go back and forth as many times as needed.

### 2. Preview — MANDATORY before publishing

When ready, display the **exact content** that will be published:

```
**Title:** <title>
**Type:** <review_type>
**Rating:** <rating>/10
**Author:** <author, or omit line if not a book>
**Main image:** <filename if provided, or "None">
**Filename:** <Title-With-Hyphens>.md (or "No body text" if no content)

---

<full markdown content exactly as it will be written, or "(no body text)">

---

**Additional images:** <list, or "None">
```

Ask: "Ready to publish? This will notify all subscribers via email."

**Do not proceed without explicit confirmation.** If the user wants changes, make them and show the preview again.

### 3. Publish

Once confirmed, execute these steps in order:

#### 3a. Download images (if any)

For each image URL (main_image and additional images):

```bash
curl -fSL "<url>" -o /home/carter/blog/blog/app/assets/images/<filename>
```

Then copy all images to public:

```bash
docker exec blog-web-1 bin/rails runner "PostsHelper.load_post_images"
```

#### 3b. Write the markdown file (if content provided)

Write the markdown content to `/home/carter/blog/blog/app/reviews/<Title-With-Hyphens>.md`.

- Replace spaces in filename with hyphens
- Convert any Obsidian image syntax `![[file.jpg]]` to `![file.jpg](/assets/file.jpg)`
- Image references in markdown should use the format `![alt text](/assets/filename.jpg)`

#### 3c. Create the database record

Build the `rails runner` command with all required fields:

```bash
docker exec blog-web-1 bin/rails runner "Review.create!(title: '<title>', review_type: ReviewType.find_by!(name: '<review_type>'), rating: <rating>, author: <author_or_nil>, path: <path_or_nil>, main_image: <main_image_filename_or_nil>)"
```

This triggers `after_create_commit :notify_subscribers` which enqueues `NotifySubscribersJob` → sends emails to all confirmed subscribers.

#### 3d. Verify

```bash
docker exec blog-web-1 bin/rails runner "r = Review.last; puts \"Created: #{r.title} (id: #{r.id}, #{r.formatted_rating})\"; puts \"Subscribers notified: #{Subscriber.confirmed.count}\""
```

Report the review ID, URL (`https://blog.carter2099.com/reviews/<id>`), and number of subscribers who will be notified.

## Review types and their IDs

These are seeded in the `review_types` table:

| Name       | Notes                    |
|------------|--------------------------|
| Book       | `author` field required  |
| Movie      |                          |
| Show       |                          |
| Product    |                          |
| Video Game |                          |

Always use `ReviewType.find_by!(name: '<type>')` — never hardcode IDs.

## Important notes

- The blog container is `blog-web-1`. If it's not running, tell the user — don't try to start it (use `/deploy-app blog` for that).
- The path stored in the database must be the **container path** (`/rails/app/reviews/...`), not the host path.
- Escape single quotes in title, author, and content when passing to `rails runner`.
- Reviews have no frontmatter — just plain markdown content.
- `main_image` stores just the filename (e.g. `cover.jpg`), not a full path.
- If `rails runner` fails, clean up any written files and report the error.
- The `rating` field is a float from 0 to 10 — `8` and `8.0` both work, as does `7.5`.

## Markdown formatting rules

The blog uses Redcarpet with `hard_wrap: true`, which changes how the parser handles certain constructs. Follow these rules when writing markdown content:

- **Blank line before lists.** A list must have a blank line separating it from the preceding paragraph — otherwise Redcarpet won't parse it as `<ul>`/`<li>` and will instead render it as literal text with `<br>` line breaks.
- **Blank line before headings** (`##`, `###`, etc.) — same rule as lists.
- **Spaces, not tabs, for nested list indentation.** Use 4 spaces for each nesting level. Tabs cause Redcarpet to treat the indented content as a code block.
- **Inline backtick code** (`` `code` ``) renders with a subtle background only (it's now `display: inline` as of 2025-06-19). Fenced code blocks (` ``` `) are for block-level code.
