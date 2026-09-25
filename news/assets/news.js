(() => {
  const picker = document.querySelector("#edition-date[data-category]");
  if (!(picker instanceof HTMLSelectElement)) return;

  picker.addEventListener("change", () => {
    const issueDate = picker.value;
    const category = picker.dataset.category;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(issueDate) || !category) return;
    const destination = category === "front-page"
      ? `/${issueDate}/`
      : `/${issueDate}/${encodeURIComponent(category)}/`;
    window.location.assign(destination);
  });
})();
