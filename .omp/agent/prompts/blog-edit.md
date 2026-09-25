---
description: Edit an existing blog post or review on blog.carter2099.com. Find by title/ID, show current content, collaboratively revise, preview changes, then update.
---

# blog-edit

Edit an existing blog post or review. This is collaborative — show the user what exists, help them revise it, preview the final result, and only commit changes after explicit confirmation.

## Finding the right post or review

The user may refer to content by title, partial title, topic, or ID. Use these to locate it:

### List recent posts

```bash
docker exec blog-web-1 bin/rails runner "Post.order(created_at: :desc).limit(10).each { |p| puts \"#{p.id}: #{p.title} (#{p.created_at.strftime('%Y-%m-%d')})\" }"
```

### List recent reviews

```bash
docker exec blog-web-1 bin/rails runner "Review.order(created_at: :desc).limit(10).each { |r| puts \"#{r.id}: #{r.title} [#{r.review_type.name}, #{r.formatted_rating}] (#{r.created_at.strftime('%Y-%m-%d')})\" }"
```

### Search by title

```bash
docker exec blog-web-1 bin/rails runner "Post.where('title LIKE ?', '%<query>%').each { |p| puts \"#{p.id}: #{p.title}\" }"
docker exec blog-web-1 bin/rails runner "Review.where('title LIKE ?', '%<query>%').each { |r| puts \"#{r.id}: #{r.title}\" }"
```

If the match is ambiguous, show the user the candidates and ask which one.

## Workflow

### 1. Show current content

Once the target is identified, display what currently exists:

**For a post:**
- Read the markdown file from `/home/carter/blog/blog/app/posts/<filename>.md`
- Show:
  ```
  **Post #<id>:** <title>
  **File:** <filename>.md
  **Created:** <date>
  
  ---
  
  <current markdown content>
  
  ---
  ```

**For a review:**
- Read the markdown file from `/home/carter/blog/blog/app/reviews/<filename>.md` (if it has one)
- Show:
  ```
  **Review #<id>:** <title>
  **Type:** <review_type> | **Rating:** <rating>/5
  **Author:** <author, if book>
  **Main image:** <main_image filename, or "None">
  **File:** <filename>.md (or "No body text")
  **Created:** <date>
  
  ---
  
  <current markdown content, or "(no body text)">
  
  ---
  ```

### 2. Collaborate on changes

Work with the user on what they want to change. This could be:
- Rewriting or tweaking the markdown body
- Changing the title
- Changing rating/type/author (reviews only)
- Adding or replacing images via URL
- Any combination of the above

### 3. Preview — MANDATORY before saving

Show the **complete final version** (not just the diff) so the user sees exactly what the post/review will look like after the edit:

**For a post:**
```
**Title:** <title> (unchanged / changed from "<old>")

---

<full markdown content as it will exist after the edit>

---

**Images to download:** <list, or "None">
```

**For a review:**
```
**Title:** <title> (unchanged / changed)
**Type:** <type> | **Rating:** <rating>/5 (unchanged / changed)
**Author:** <author> (if book)
**Main image:** <filename> (unchanged / changed / new)

---

<full markdown content, or "(no body text)">

---

**Images to download:** <list, or "None">
```

Ask: "Save these changes?" — **do not proceed without explicit confirmation.**

### 4. Apply changes

#### 4a. Download new images (if any)

```bash
curl -fSL "<url>" -o /home/carter/blog/blog/app/assets/images/<filename>
docker exec blog-web-1 bin/rails runner "PostsHelper.load_post_images"
```

#### 4b. Update the markdown file (if content changed)

Overwrite the file at its existing path on the host. If the title changed and the user wants the filename updated too, write to the new path and delete the old one.

#### 4c. Update the database record

**For a post:**
```bash
docker exec blog-web-1 bin/rails runner "p = Post.find(<id>); p.update!(title: '<title>', path: '<path>')"
```

**For a review:**
```bash
docker exec blog-web-1 bin/rails runner "r = Review.find(<id>); r.update!(title: '<title>', review_type: ReviewType.find_by!(name: '<type>'), rating: <rating>, author: <author_or_nil>, path: <path_or_nil>, main_image: <main_image_or_nil>)"
```

#### 4d. Verify

```bash
docker exec blog-web-1 bin/rails runner "p = Post.find(<id>); puts \"Updated: #{p.title}\""
```

Report success with the URL (`https://blog.carter2099.com/posts/<id>` or `/reviews/<id>`).

## Important notes

- **Editing does NOT send subscriber emails.** The `after_create_commit` callback only fires on create, not update. This is correct behavior — subscribers shouldn't get re-notified for edits.
- The path in the DB is the **container path** (`/rails/app/posts/...`), but files are read/written on the **host path** (`/home/carter/blog/blog/app/posts/...`) since the directory is bind-mounted.
- Escape single quotes in all values passed to `rails runner`.
- If the user wants to change the filename (e.g. because the title changed), update both the file on disk and the `path` in the DB. Delete the old file after confirming the new one exists.

## Markdown formatting rules

The blog uses Redcarpet with `hard_wrap: true`, which changes how the parser handles certain constructs. Follow these rules when editing markdown content:

- **Blank line before lists.** A list must have a blank line separating it from the preceding paragraph — otherwise Redcarpet won't parse it as `<ul>`/`<li>` and will instead render it as literal text with `<br>` line breaks.
- **Blank line before headings** (`##`, `###`, etc.) — same rule as lists.
- **Spaces, not tabs, for nested list indentation.** Use 4 spaces for each nesting level. Tabs cause Redcarpet to treat the indented content as a code block.
- **Inline backtick code** (`` `code` ``) renders with a subtle background only (it's now `display: inline` as of 2025-06-19). Fenced code blocks (` ``` `) are for block-level code.
