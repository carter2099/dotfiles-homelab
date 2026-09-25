---
description: Delete a blog post or review from blog.carter2099.com. Soft-deletes the markdown file (moved to deleted/ directory) and destroys the database record.
---

# blog-delete

Delete a blog post or review. Files are **soft-deleted** (moved to a `deleted/` subdirectory) so they can be recovered if needed. The database record is permanently destroyed.

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

If the match is ambiguous, show the candidates and ask which one.

## Workflow

### 1. Show what will be deleted

Once the target is identified, display it fully so the user knows exactly what they're removing:

**For a post:**
- Read the markdown file from `/home/carter/blog/blog/app/posts/<filename>.md`
- Show:
  ```
  **Post #<id>:** <title>
  **Created:** <date>
  **File:** <filename>.md
  **URL:** https://blog.carter2099.com/posts/<id>
  
  ---
  
  <full markdown content>
  
  ---
  ```

**For a review:**
- Show:
  ```
  **Review #<id>:** <title>
  **Type:** <review_type> | **Rating:** <rating>/5
  **Author:** <author, if book>
  **Created:** <date>
  **File:** <filename>.md (or "No body text")
  **URL:** https://blog.carter2099.com/reviews/<id>
  
  ---
  
  <full markdown content, or "(no body text)">
  
  ---
  ```

### 2. Confirm — MANDATORY

Ask: "Delete this? The markdown file will be moved to the `deleted/` folder (recoverable), but the database record will be permanently removed and the page will go offline."

**Do not proceed without explicit confirmation.**

### 3. Execute deletion

#### 3a. Soft-delete the markdown file (if it has one)

Move the file to the `deleted/` subdirectory on the host:

**For a post:**
```bash
mkdir -p /home/carter/blog/blog/app/posts/deleted
mv /home/carter/blog/blog/app/posts/<filename>.md /home/carter/blog/blog/app/posts/deleted/
```

**For a review (only if it has a path):**
```bash
mkdir -p /home/carter/blog/blog/app/reviews/deleted
mv /home/carter/blog/blog/app/reviews/<filename>.md /home/carter/blog/blog/app/reviews/deleted/
```

#### 3b. Destroy the database record

**For a post:**
```bash
docker exec blog-web-1 bin/rails runner "Post.find(<id>).destroy!"
```

**For a review:**
```bash
docker exec blog-web-1 bin/rails runner "Review.find(<id>).destroy!"
```

#### 3c. Verify

```bash
docker exec blog-web-1 bin/rails runner "puts Post.exists?(<id>)"
# Should print "false"
```

Report: record destroyed, file moved to `deleted/<filename>.md`, page is now offline.

## Important notes

- **Deletion does NOT send any emails.** There is no `after_destroy` callback for notifications.
- The soft-delete only applies to the markdown file. The database record is permanently destroyed. Images in `app/assets/images/` are left in place (they may be shared across posts).
- If multiple DB records share the same file path (edge case from the controller: `Post.where(path: @post.path).size > 1`), do NOT move the file — only destroy the record. Check this before moving.
- The `deleted/` directories are **not** bind-mounted into the container, so soft-deleted files only exist on the host.
- To recover a deleted post, the user would need to move the file back and create a new DB record (effectively a new post with the old content).
